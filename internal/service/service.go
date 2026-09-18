package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var UnitPath = "/etc/systemd/system/webfleet.service"
var BinaryPath = "/usr/local/bin/webfleet"

// DefaultDataDir is the canonical data directory the installed service owns
// and runs from. It must be independent of the CLI default (./data) because
// `service install` is run as root with no runtime config and the unit it
// writes embeds the path.
const DefaultDataDir = "/var/lib/webfleet"

// DefaultListen is the canonical loopback listen address embedded in the unit.
const DefaultListen = "127.0.0.1:7336"

// DefaultEnvFile is the root-protected environment file the unit references via
// EnvironmentFile= before the process drops to the service user. It can carry
// replication/cluster configuration (for example
// WEBFLEET_REPLICATION_INSECURE_PLAINTEXT).
const DefaultEnvFile = "/etc/webfleet/webfleet.env"

// listenMode records how a unit's recorded listener is meant to be applied.
// Explicit units record the canonical --host/--port pair in ExecStart, so the
// installed process genuinely binds that listener across restart/reboot.
// Bootstrap units record a legacy WEBFLEET_LISTEN environment / --listen flag,
// whose address the foreground binds; old units predating the marker default
// to bootstrap so they keep behaving exactly as before.
const (
	modeExplicit  = "explicit"
	modeBootstrap = "bootstrap"
)

// ServiceAccount is the dedicated unprivileged account the unit runs as. It is
// created idempotently by Install so a clean machine needs no hidden manual
// prerequisites.
const ServiceUser = "webfleet"
const ServiceGroup = "webfleet"

// unitMarker marks unit files written by `webfleet service`. Service operations
// refuse to act on a unit that does not carry it, so the CLI can never modify
// an unrelated system service that happens to share the unit name.
const unitMarker = "# Managed by webfleet. Do not edit manually."

// managedPrefix introduces the versioned integrity header followed by a SHA-256
// of everything below it, so any hand edit is detected on read.
const managedPrefix = "# webfleet-managed: "

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// Runner abstracts systemctl/journalctl so the CLI is testable without a real
// systemd manager. Run returns captured combined output, the exit code (0 on
// success, -1 when the command could not launch) and a launch error only.
type Runner interface {
	Run(name string, args ...string) (string, int, error)
	Stream(name string, args ...string) (int, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, int, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return string(out), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode(), nil
	}
	return string(out), -1, err
}

func (execRunner) Stream(name string, args ...string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, err
}

var defaultRunner Runner = execRunner{}

// setRunner replaces the systemctl runner (test seam; nil restores the default).
func setRunner(r Runner) { defaultRunner = r }

func systemctl(args ...string) (string, int, error) { return defaultRunner.Run("systemctl", args...) }

func bounded(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// systemctlSuccess runs a systemctl operation that must exit zero; launch
// failures and nonzero exits are both errors.
func systemctlSuccess(args ...string) error {
	out, code, err := systemctl(args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

// resetFailed clears systemd's accumulated failed/start-limit state for the
// managed unit. The CLI issues it immediately before its own deliberate
// start/restart activations (install, update, rollback, recovery and the
// explicit start/restart verbs), so the finite crash-loop policy in the unit
// body catches spontaneous Restart=on-failure crash loops while
// operator-controlled lifecycle transitions are never blocked by previously
// accumulated starts. systemd reports "Unit ... not loaded" when a stopped unit
// has no failed state to clear; that benign no-op (no accumulated limit) is
// not a reset failure, so it is tolerated here while genuine failures still
// surface to the caller.
func resetFailed() error {
	out, code, err := systemctl("reset-failed", "webfleet.service")
	if err != nil {
		return fmt.Errorf("cannot run systemctl reset-failed webfleet.service: %w", err)
	}
	if code == 0 {
		return nil
	}
	if strings.Contains(strings.ToLower(out), "not loaded") {
		return nil
	}
	return fmt.Errorf("systemctl reset-failed webfleet.service exited %d: %s", code, bounded(strings.TrimSpace(out)))
}

// unitStateWord runs a state verb (is-enabled/is-active) and returns the
// trimmed state word. A nonzero exit is a legitimate negative state answer
// (disabled, inactive, masked, ...); only a launch failure is a query error.
func unitStateWord(verb string) (string, error) {
	out, code, err := systemctl(verb, "webfleet.service")
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	_ = code
	return strings.TrimSpace(out), nil
}

// systemdQuote escapes a value for a systemd ExecStart/Environment/ReadWritePaths
// directive so paths containing spaces or systemd-special characters survive.
func systemdQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%%")
		case '"', '\\', '$', '`':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// validateNoControl rejects CR, LF, NUL and other control characters so no
// user-supplied value can inject directives into a systemd unit.
func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}

// fileSHA256 returns the hex SHA-256 of a file (used to detect a changed
// executable during reinstall).
func fileSHA256(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// unitMeta carries the metadata recorded in the managed-unit header.
type unitMeta struct {
	data       string
	listen     string
	listenMode string
	envfile    string
}

// readManagedUnit validates a managed unit's integrity header and parses its
// recorded metadata. Any hand edit to the metadata or the unit body is detected
// via the body checksum, so a foreign, malformed or modified unit is refused
// rather than treated as healthy or overwritten.
func readManagedUnit(content string) (unitMeta, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 3 || lines[0] != unitMarker {
		return unitMeta{}, errNotManaged
	}
	count := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, managedPrefix) {
			count++
		}
	}
	if count != 1 || !strings.HasPrefix(lines[1], managedPrefix) {
		return unitMeta{}, errMalformed
	}
	sm := regexp.MustCompile(`^# webfleet-managed: v1 sha256=([0-9a-f]{64})$`).FindStringSubmatch(lines[1])
	if sm == nil {
		return unitMeta{}, errMalformed
	}
	contentBody := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(contentBody))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	// Old units predating the listen-mode marker default to bootstrap: their
	// recorded listener is only a bootstrap value, matching the legacy
	// behaviour.
	meta := unitMeta{listenMode: modeBootstrap}
	dataSeen, listenSeen, modeSeen, envfileSeen := 0, 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# webfleet-data: "):
			dataSeen++
			if dataSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.data = strings.TrimSpace(strings.TrimPrefix(ln, "# webfleet-data: "))
		case strings.HasPrefix(ln, "# webfleet-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# webfleet-listen: "))
		case strings.HasPrefix(ln, "# webfleet-listen-mode: "):
			modeSeen++
			if modeSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listenMode = strings.TrimSpace(strings.TrimPrefix(ln, "# webfleet-listen-mode: "))
		case strings.HasPrefix(ln, "# webfleet-envfile: "):
			envfileSeen++
			if envfileSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.envfile = strings.TrimSpace(strings.TrimPrefix(ln, "# webfleet-envfile: "))
		}
	}
	if dataSeen != 1 || listenSeen != 1 || meta.data == "" || meta.listen == "" {
		return unitMeta{}, errMalformed
	}
	if meta.listenMode != modeExplicit && meta.listenMode != modeBootstrap {
		return unitMeta{}, errMalformed
	}
	for _, v := range []struct{ val, name string }{{meta.listen, "listen"}, {meta.data, "data-dir"}} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return unitMeta{}, errMalformed
		}
	}
	if meta.envfile != "" {
		if err := validateNoControl(meta.envfile, "environment file"); err != nil {
			return unitMeta{}, errMalformed
		}
		if strings.ContainsAny(meta.envfile, "%") {
			return unitMeta{}, errMalformed
		}
	}
	return meta, nil
}

// managedUnit reports whether the unit file carries the webfleet managed marker.
func managedUnit(path string) bool {
	b, e := os.ReadFile(path)
	if e != nil {
		return false
	}
	return strings.Contains(string(b), unitMarker)
}

// InstalledListener returns the verified listener recorded by the currently
// installed managed unit so a bare reinstall can preserve it. explicit reports
// whether the existing unit uses the authoritative --host/--port form; false
// means a legacy/bootstrap single-address unit. exists is false when no unit is
// installed. An existing foreign, malformed or modified unit is returned as an
// error so a bare reinstall fails closed rather than silently changing an
// unverified installation.
func InstalledListener() (listen string, explicit, exists bool, err error) {
	b, err := os.ReadFile(UnitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, false, nil
		}
		return "", false, false, err
	}
	meta, err := readManagedUnit(string(b))
	if err != nil {
		return "", false, true, err
	}
	return meta.listen, meta.listenMode == modeExplicit, true, nil
}

// requireManaged refuses to operate on a unit that is not installed or not
// a webfleet-managed unit, so the CLI never touches an unrelated system service.
func requireManaged(verb string) error {
	b, e := os.ReadFile(UnitPath)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("refusing to %s webfleet.service: unit is not installed (run `webfleet service install`)", verb)
	}
	if e != nil {
		return fmt.Errorf("refusing to %s webfleet.service: %w", verb, e)
	}
	if _, ve := readManagedUnit(string(b)); ve != nil {
		return fmt.Errorf("refusing to %s webfleet.service: %v", verb, ve)
	}
	return nil
}

func requireLinux() error {
	if runtime.GOOS != "linux" {
		return errors.New("service management is supported on Linux only")
	}
	return nil
}

var isRoot = func() bool { return os.Geteuid() == 0 }
var ensureAccount = func() error { return ensureServiceAccount() }

// serviceUID returns the numeric UID of the service account. It is a variable
// so tests can simulate the account without a real system user.
var serviceUID = func() (int, error) {
	uid, _, e := lookupServiceIDs()
	return uid, e
}

// systemDataRoots are filesystem and system-prefix directories the service
// installer must never adopt as a data directory. Passing one of these as
// `service install --data` is refused before any mutation.
var systemDataRoots = map[string]bool{
	"/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true,
	"/home": true, "/lib": true, "/lib64": true, "/opt": true, "/proc": true,
	"/root": true, "/run": true, "/sbin": true, "/srv": true, "/sys": true,
	"/tmp": true, "/usr": true, "/var": true,
}

// protectedDataHierarchies are filesystem prefixes whose descendants are never
// adopted as a service data directory. The unit sandbox makes /home, /root and
// /run/user inaccessible to the service (ProtectHome=true, PrivateTmp=true),
// and these hold system machine state that a privileged installer must not
// create directories inside. /var/lib and /srv are deliberately excluded so a
// deliberate custom location like /srv/webfleet remains usable. It is a
// variable so tests can narrow it around their own temporary paths.
var protectedDataHierarchies = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
	"/proc", "/root", "/run", "/sbin", "/sys", "/tmp", "/usr", "/home",
}

// validateReadWritePath validates a data directory for ReadWritePaths=: an
// absolute plain path free of systemd specifiers and characters that cannot be
// safely quoted in the unit.
func validateReadWritePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("data directory %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "data directory"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("data directory %q must not contain systemd specifiers (%% )", path)
	}
	if strings.ContainsAny(path, `"\`) {
		return fmt.Errorf("data directory %q cannot be safely quoted in ReadWritePaths", path)
	}
	if len(path) > 0 && strings.ContainsRune("-+!~", rune(path[0])) {
		return fmt.Errorf("data directory %q starts with a ReadWritePaths special prefix; use a plain absolute path", path)
	}
	return nil
}

// validateDataDirPath rejects data-directory paths that are dangerous system
// roots or descendants of a protected system hierarchy. It must run before any
// ownership or mode mutation. /var/lib and /srv custom locations are allowed;
// only the exact roots and protected descendants are refused.
func validateDataDirPath(path string) error {
	clean := filepath.Clean(path)
	if systemDataRoots[clean] {
		return fmt.Errorf("data directory %q is a system directory and cannot be adopted as a service data directory", path)
	}
	for _, p := range protectedDataHierarchies {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return fmt.Errorf("data directory %q is under the protected system hierarchy %q and cannot be adopted as a service data directory", path, p)
		}
	}
	return nil
}

// dataDirStatus classifies the outcome of the non-mutating data-path
// inspection so the installer can defer every filesystem mutation until after
// all preflight succeeds.
type dataDirStatus int

const (
	// dataDirAcceptFresh means the final leaf is missing but its parent already
	// exists and was safely opened; the leaf may be created during the mutation
	// phase, relative to the retained parent descriptor.
	dataDirAcceptFresh dataDirStatus = iota
	// dataDirAcceptExisting means the leaf already exists and is a safe,
	// service-owned directory.
	dataDirAcceptExisting
)

// dataLeafInfo carries the leaf stat fields the installer needs, kept
// cross-platform so the descriptor-relative primitives can be declared and
// stubbed on every build target.
type dataLeafInfo struct {
	isDir     bool
	isSymlink bool
	mode      os.FileMode
	uid       int
}

// dataDirPlan is the result of the non-mutating inspection. It retains the
// validated parent directory descriptor AND, for an existing leaf, the leaf
// directory descriptor opened during inspection, so the mutation phase is bound
// to the exact objects inspected, never re-looked-up by name.
type dataDirPlan struct {
	status   dataDirStatus
	parentFd int
	leafFd   int // retained leaf descriptor for existing leaves (-1 for fresh)
	leafName string
	path     string
}

// close releases the retained leaf and parent descriptors exactly once
// (idempotent).
func (p *dataDirPlan) close() {
	if p.leafFd >= 0 {
		closeFdSeam(p.leafFd)
		p.leafFd = -1
	}
	if p.parentFd >= 0 {
		closeFdSeam(p.parentFd)
		p.parentFd = -1
	}
}

// inspectDataDir and establishDataDir are implemented on Linux using a
// descriptor-relative, no-symlink walk of the parent chain (see datadir_linux.go)
// so the validated parent is the exact directory mutated; non-Linux stubs fail
// (Install is Linux-gated).

func requireRoot(verb string) error {
	if !isRoot() {
		return fmt.Errorf("%s requires root (sudo webfleet service %s)", verb, verb)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	tmp := dst + ".new"
	out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, dst)
}

// unitBody renders the systemd directives (no managed marker) for a legacy
// bootstrap unit: the recorded WEBFLEET_LISTEN environment is what the
// foreground binds. The explicit StartLimitIntervalSec/StartLimitBurst pair is
// a finite crash-loop boundary: a persistent startup failure is eventually
// rate-limited instead of restarting forever. The CLI clears the accumulated
// counter with reset-failed before its own deliberate activations, so
// legitimate install/update/rollback restarts are never blocked.
func unitBody(dataDir, listen, envfile string) string {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	if listen == "" {
		listen = DefaultListen
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Web Fleet website monitoring\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("StartLimitIntervalSec=60\n")
	b.WriteString("StartLimitBurst=5\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("Environment=WEBFLEET_DATA_DIR=" + systemdQuote(dataDir) + "\n")
	b.WriteString("Environment=WEBFLEET_LISTEN=" + systemdQuote(listen) + "\n")
	if envfile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(envfile) + "\n")
	}
	b.WriteString("ExecStart=" + BinaryPath + "\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=3\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ReadWritePaths=" + systemdQuote(dataDir) + "\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// unitBodyExplicit renders the systemd directives (no managed marker) for a
// new explicit unit: the canonical --host/--port pair is recorded in ExecStart
// so the installed process genuinely binds that listener across
// restart/reboot, and no WEBFLEET_LISTEN environment is set (the flags are the
// runtime authority; the foreground resolves CLI > env > default). As in the
// bootstrap body, the explicit finite start-limit pair retains a crash-loop
// boundary that the CLI's reset-failed-before-activation clears for deliberate
// lifecycle transitions.
func unitBodyExplicit(dataDir, host, port, envfile string) string {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Web Fleet website monitoring\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("StartLimitIntervalSec=60\n")
	b.WriteString("StartLimitBurst=5\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("Environment=WEBFLEET_DATA_DIR=" + systemdQuote(dataDir) + "\n")
	if envfile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(envfile) + "\n")
	}
	b.WriteString("ExecStart=" + BinaryPath)
	b.WriteString(" " + systemdQuote("--host") + " " + systemdQuote(strings.TrimSpace(host)))
	b.WriteString(" " + systemdQuote("--port") + " " + systemdQuote(strings.TrimSpace(port)))
	b.WriteString("\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=3\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ReadWritePaths=" + systemdQuote(dataDir) + "\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// buildUnit returns the full managed unit content for a legacy bootstrap
// install: the marker, the versioned integrity header (SHA-256 of the metadata
// + body), the recorded metadata (including the listen mode) and the systemd
// body.
func buildUnit(dataDir, listen, envfile string) string {
	meta := "# webfleet-data: " + dataDir + "\n# webfleet-listen: " + listen + "\n# webfleet-listen-mode: " + modeBootstrap + "\n"
	if envfile != "" {
		meta += "# webfleet-envfile: " + envfile + "\n"
	}
	content := meta + unitBody(dataDir, listen, envfile)
	sum := sha256.Sum256([]byte(content))
	header := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

// buildUnitExplicit returns the full managed unit content for a new explicit
// --host/--port install, recording the canonical joined listener and the
// explicit listen-mode marker.
func buildUnitExplicit(dataDir, host, port, envfile string) string {
	listen := net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port))
	meta := "# webfleet-data: " + dataDir + "\n# webfleet-listen: " + listen + "\n# webfleet-listen-mode: " + modeExplicit + "\n"
	if envfile != "" {
		meta += "# webfleet-envfile: " + envfile + "\n"
	}
	content := meta + unitBodyExplicit(dataDir, host, port, envfile)
	sum := sha256.Sum256([]byte(content))
	header := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

// Unit returns the full managed unit content for the given data dir and listen
// address (legacy bootstrap form).
func Unit(dataDir, listen, envfile string) string {
	return buildUnit(dataDir, listen, envfile)
}

// UnitExplicit returns the full managed unit content for the given data dir and
// canonical host/port pair (explicit form recording --host/--port in ExecStart).
func UnitExplicit(dataDir, host, port, envfile string) string {
	return buildUnitExplicit(dataDir, host, port, envfile)
}

// installOptions carries the values recorded in the managed unit. The legacy
// single-address listen form is preserved for compatibility (bootstrap mode);
// otherwise the canonical host/port pair is written to ExecStart (explicit
// mode) so the recorded listener is the runtime listener.
type installOptions struct {
	dataDir    string
	listen     string
	host       string
	port       string
	listenMode string
	envfile    string
}

// listener returns the canonical listen address recorded in the unit metadata:
// the legacy listen address when set, otherwise the trimmed host/port pair
// joined safely (so IPv6 hosts are bracketed).
func (o installOptions) listener() string {
	if o.listen != "" {
		return o.listen
	}
	return net.JoinHostPort(strings.TrimSpace(o.host), strings.TrimSpace(o.port))
}

// unit returns the full managed unit content for the install options.
func (o installOptions) unit() string {
	if o.listenMode == modeExplicit {
		return buildUnitExplicit(o.dataDir, strings.TrimSpace(o.host), strings.TrimSpace(o.port), o.envfile)
	}
	return buildUnit(o.dataDir, o.listener(), o.envfile)
}

// Install installs (or idempotently reinstalls) the webfleet systemd unit in
// the legacy bootstrap form: the recorded listen address is set as the
// WEBFLEET_LISTEN environment the foreground binds.
func Install(exe, dataDir, listen, envfile string) error {
	return install(exe, dataDir, installOptions{dataDir: dataDir, listen: listen, listenMode: modeBootstrap, envfile: envfile})
}

// InstallExplicit installs (or idempotently reinstalls) the webfleet systemd
// unit in the explicit form: the canonical host/port pair is recorded as
// --host/--port in ExecStart so the installed process genuinely binds that
// listener across restart/reboot.
func InstallExplicit(exe, dataDir, host, port, envfile string) error {
	return install(exe, dataDir, installOptions{dataDir: dataDir, host: host, port: port, listenMode: modeExplicit, envfile: envfile})
}

// install installs (or idempotently reinstalls) the webfleet systemd unit: it
// creates the service account and data directory, copies the current binary,
// writes the managed unit, daemon-reloads and restores the operational state.
//
// For an existing managed unit the exact prior enablement and active state are
// snapshotted, classified and re-applied on the forward path, so a reinstall
// preserves disabled/stopped (and every supported combination) exactly instead
// of forcing enabled+active. A fresh install establishes Web Fleet's normal
// initial enabled/running state.
//
// Every non-mutating check (argument validation, unit integrity, state
// classification, executable inspection, and data-path inspection classifying
// the directory as an acceptable fresh leaf or existing service-owned leaf)
// runs as preflight BEFORE any account or data-directory creation, so an
// install that must fail closed never leaves a machine mutation behind, and a
// genuine no-op additionally requires the recorded data directory to already
// exist as a safe service-owned leaf (a missing leaf is repaired instead). A
// partial failure restores the prior unit, enablement, active state and binary,
// and the returned error combines the original failure with EVERY rollback
// failure (including neutralization stop/disable) rather than claiming
// "installation rolled back" blindly.
func install(exe, dataDir string, opts installOptions) (retErr error) {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("service install requires root")
	}
	for _, v := range []struct{ val, name string }{{dataDir, "data dir"}, {opts.listener(), "listen"}} {
		if e := validateNoControl(v.val, v.name); e != nil {
			return e
		}
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	opts.dataDir = dataDir
	if opts.listenMode == modeExplicit {
		if strings.TrimSpace(opts.host) == "" && strings.TrimSpace(opts.port) == "" {
			host, port, err := net.SplitHostPort(DefaultListen)
			if err != nil {
				return fmt.Errorf("default listener %q is malformed: %w", DefaultListen, err)
			}
			opts.host, opts.port = host, port
		}
	} else if opts.listen == "" {
		opts.listen = DefaultListen
	}
	if e := validateReadWritePath(dataDir); e != nil {
		return e
	}
	if e := validateDataDirPath(dataDir); e != nil {
		return e
	}
	if _, e := exec.LookPath("systemctl"); e != nil {
		return errors.New("systemctl not found; is systemd installed?")
	}
	unit := opts.unit()
	priorUnit, hadUnit := []byte(nil), false
	if b, e := os.ReadFile(UnitPath); e == nil {
		hadUnit = true
		priorUnit = b
		if _, ve := readManagedUnit(string(b)); ve != nil {
			return fmt.Errorf("refusing to reinstall webfleet.service: %v", ve)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	// Non-mutating preflight: snapshot and classify the exact prior enablement
	// and active states BEFORE any account/data/binary/unit mutation. Query
	// failures are propagated and every state that cannot be recreated exactly
	// by the shared restore mapping is refused up front, so install never
	// mutates a state it cannot restore.
	priorEnabled, priorActive := "", ""
	if hadUnit {
		var e error
		if priorEnabled, e = unitStateWord("is-enabled"); e != nil {
			return fmt.Errorf("refusing to reinstall webfleet.service: %w", e)
		}
		if !restorableEnabledWord(priorEnabled) {
			return fmt.Errorf("refusing to reinstall webfleet.service: prior enablement state %q cannot be restored exactly; disable or unmask it first", priorEnabled)
		}
		if priorActive, e = unitStateWord("is-active"); e != nil {
			return fmt.Errorf("refusing to reinstall webfleet.service: %w", e)
		}
		if !restorableActiveWord(priorActive) {
			return fmt.Errorf("refusing to reinstall webfleet.service: prior active state %q cannot be restored exactly; stop or restart it first", priorActive)
		}
		if !restorablePriorState(priorEnabled, priorActive) {
			return fmt.Errorf("refusing to reinstall webfleet.service: prior state %s+%s cannot be restored exactly; unmask it first", priorEnabled, priorActive)
		}
	}
	incomingDigest, err := fileSHA256(exe)
	if err != nil {
		return fmt.Errorf("read incoming executable: %w", err)
	}
	priorBinaryDigest, hadBinary := "", false
	if d, e := fileSHA256(BinaryPath); e == nil {
		hadBinary = true
		priorBinaryDigest = d
	}
	binaryChanged := !hadBinary || incomingDigest != priorBinaryDigest
	// Non-mutating data-path inspection: classify the requested directory
	// (acceptable fresh leaf with a safe existing parent, or acceptable existing
	// service-owned leaf) or refuse it. This runs before the genuine-no-op
	// return so a reinstall never claims "already correct" while a recorded
	// runtime prerequisite (the data directory) is missing or unsafe, and it
	// runs before any account/data mutation so an unacceptable existing
	// directory cannot trigger account creation first.
	dataPlan, dErr := inspectDataDir(dataDir)
	if dErr != nil {
		return fmt.Errorf("refusing to install webfleet.service: %w", dErr)
	}
	defer dataPlan.close()
	// Genuine no-op: the installed unit and executable already match the request
	// AND the recorded data directory already exists as a safe service-owned
	// leaf, so the service is already running the requested version in its prior
	// state; nothing is rewritten, reloaded, enabled or started.
	if hadUnit && string(priorUnit) == unit && !binaryChanged && dataPlan.status == dataDirAcceptExisting {
		return nil
	}
	// Preflight is complete: only now may install mutate the machine (account,
	// data directory, then binary/unit/systemd state).
	if e := ensureAccount(); e != nil {
		return e
	}
	if e := establishDataDir(&dataPlan); e != nil {
		return e
	}
	// Repair-only: the unit and binary already match the request, so the only
	// reason the no-op check did not return early was a missing data leaf, which
	// has just been recreated. No systemd state change is needed.
	if hadUnit && string(priorUnit) == unit && !binaryChanged {
		return nil
	}
	// Preserve the prior binary so activation failure can roll back cleanly.
	if hadBinary {
		if e := copyFile(BinaryPath, BinaryPath+".preinstall", 0o755); e != nil {
			return e
		}
	}
	installOK := false
	restore := func() string {
		var errs []string
		// 1) Neutralize any attempted activation before restoring the binary so a
		// previously running service is never restarted with the failing binary.
		// These neutralization failures are part of the rollback result, never
		// discarded.
		if e := systemctlSuccess("stop", "webfleet.service"); e != nil {
			errs = append(errs, fmt.Sprintf("stop failed service: %v", e))
		}
		if e := systemctlSuccess("disable", "webfleet.service"); e != nil {
			errs = append(errs, fmt.Sprintf("disable failed service: %v", e))
		}
		// 2) Restore the executable before the unit and before activation.
		if hadBinary {
			if e := copyFile(BinaryPath+".preinstall", BinaryPath, 0o755); e != nil {
				errs = append(errs, fmt.Sprintf("restore binary: %v", e))
			}
		} else {
			_ = os.Remove(BinaryPath)
		}
		_ = os.Remove(BinaryPath + ".preinstall")
		// 3) Restore the unit.
		if hadUnit {
			if e := os.WriteFile(UnitPath, priorUnit, 0o644); e != nil {
				errs = append(errs, fmt.Sprintf("restore unit: %v", e))
			}
		} else {
			_ = os.Remove(UnitPath)
		}
		if e := systemctlSuccess("daemon-reload"); e != nil {
			errs = append(errs, fmt.Sprintf("reload systemd: %v", e))
		}
		// 4) Restore the exact prior enablement and active states via the same
		// mapping used by the successful reinstall path.
		if hadUnit {
			for _, args := range enableRestoreSteps(priorEnabled, "webfleet.service") {
				if e := systemctlSuccess(args...); e != nil {
					errs = append(errs, fmt.Sprintf("restore enablement %q: %v", priorEnabled, e))
					break
				}
			}
			// The restore may reactivate the service, so clear any start-limit
			// state accumulated by the failed activation first; a reset failure
			// is part of the combined rollback result, never discarded.
			if priorActive == "active" {
				if e := resetFailed(); e != nil {
					errs = append(errs, fmt.Sprintf("reset failed state: %v", e))
				}
			}
			if e := systemctlSuccess(activeRestoreArgs(priorActive, "webfleet.service")...); e != nil {
				errs = append(errs, fmt.Sprintf("restore active state %q: %v", priorActive, e))
			}
		}
		if len(errs) == 0 {
			return ""
		}
		return "; rollback incomplete: " + strings.Join(errs, "; ")
	}
	defer func() {
		if !installOK && retErr != nil {
			if rb := restore(); rb != "" {
				retErr = fmt.Errorf("%v%s", retErr, rb)
			}
		}
	}()
	if e := copyFile(exe, BinaryPath, 0o755); e != nil {
		return e
	}
	if e := os.WriteFile(UnitPath, []byte(unit), 0o644); e != nil {
		return e
	}
	steps := [][]string{{"daemon-reload"}}
	if !hadUnit {
		// Fresh install: establish Web Fleet's normal initial enabled/running state.
		steps = append(steps, []string{"enable", "webfleet.service"}, []string{"start", "webfleet.service"})
	} else {
		// Reinstall: preserve the exact prior enablement and active state.
		steps = append(steps, enableRestoreSteps(priorEnabled, "webfleet.service")...)
		steps = append(steps, activeRestoreArgs(priorActive, "webfleet.service"))
	}
	// A deliberate start/restart clears any accumulated start-limit state first
	// so the finite crash-loop policy never blocks an operator-controlled
	// activation; a reset failure is an install step failure and participates
	// in the transactional rollback below.
	if last := steps[len(steps)-1]; last[0] == "start" || last[0] == "restart" {
		steps = append(steps[:len(steps)-1], []string{"reset-failed", "webfleet.service"}, last)
	}
	for _, a := range steps {
		if out, code, err := systemctl(a...); err != nil || code != 0 {
			retErr = fmt.Errorf("systemctl %s: %s: %w (installation rolled back)", strings.Join(a, " "), bounded(strings.TrimSpace(out)), errorIfNil(err, code, a))
			return retErr
		}
	}
	installOK = true
	_ = os.Remove(BinaryPath + ".preinstall")
	return nil
}

// restorableEnabledWord reports whether a prior is-enabled word can be
// recreated exactly by the shared enablement mapping. Persistent enablement
// (enabled), runtime-only enablement (enabled-runtime) and their absence
// (disabled) are restorable. Masked/static/linked/generated/transient and other
// unit-file states are refused before mutation because enable/disable cannot
// reproduce them.
func restorableEnabledWord(word string) bool {
	switch word {
	case "enabled", "enabled-runtime", "disabled":
		return true
	}
	return false
}

// restorableActiveWord reports whether a prior is-active word can be recreated
// exactly by the shared activation mapping. Running and stopped are restorable;
// transient, failed, reloading, activating and unknown states are not.
func restorableActiveWord(word string) bool {
	switch word {
	case "active", "inactive":
		return true
	}
	return false
}

// restorablePriorState reports whether the enablement/active pair can be
// reproduced exactly. Only the states accepted above are combined here; this
// guard exists so any future widening of the accept sets must also prove the
// pair is restorable.
func restorablePriorState(enabledWord, activeWord string) bool {
	return restorableEnabledWord(enabledWord) && restorableActiveWord(activeWord)
}

// enableRestoreSteps returns the systemctl calls that reproduce a prior
// is-enabled word exactly. Enablement is normalized first: the enablement link
// created by the attempted install is removed with disable, then the intended
// persistent or runtime link is recreated, so a runtime-only prior never leaves
// a persistent enablement behind.
func enableRestoreSteps(word, unit string) [][]string {
	switch word {
	case "enabled":
		return [][]string{{"disable", unit}, {"enable", unit}}
	case "enabled-runtime":
		return [][]string{{"disable", unit}, {"enable", "--runtime", unit}}
	default: // disabled
		return [][]string{{"disable", unit}}
	}
}

// activeRestoreArgs returns the systemctl call that reproduces a prior is-active
// word exactly.
func activeRestoreArgs(word, unit string) []string {
	if word == "active" {
		return []string{"restart", unit}
	}
	return []string{"stop", unit}
}

func errorIfNil(err error, code int, args []string) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("exited %d", code)
}

// ensureServiceAccount creates the webfleet group and user idempotently so a
// clean machine needs no manually created prerequisites. The service account is
// a system account with no login shell and no home directory.
func ensureServiceAccount() error {
	if out, e := exec.Command("groupadd", "--system", ServiceGroup).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("groupadd: %s", strings.TrimSpace(string(out)))
		}
	}
	if out, e := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", ServiceGroup, ServiceUser).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("useradd: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// lookupServiceIDs resolves the numeric uid/gid of the dedicated service
// account, used for descriptor-relative ownership assignment of the data leaf.
func lookupServiceIDs() (int, int, error) {
	g, e := user.LookupGroup(ServiceGroup)
	if e != nil {
		return 0, 0, fmt.Errorf("service group not found: %w", e)
	}
	gid, _ := strconv.Atoi(g.Gid)
	u, e := user.Lookup(ServiceUser)
	if e != nil {
		return 0, 0, fmt.Errorf("service user not found: %w", e)
	}
	uid, _ := strconv.Atoi(u.Uid)
	return uid, gid, nil
}

// Start starts the service.
func Start() error {
	return lifecycle("start")
}

// Stop stops the service.
func Stop() error {
	return lifecycle("stop")
}

// Restart restarts the service.
func Restart() error {
	return lifecycle("restart")
}

// Enable enables the service at boot.
func Enable() error {
	return lifecycle("enable")
}

// Disable disables the service at boot (without stopping it).
func Disable() error {
	return lifecycle("disable")
}

func lifecycle(verb string) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireRoot(verb); e != nil {
		return e
	}
	if e := requireManaged(verb); e != nil {
		return e
	}
	// A deliberate start/restart clears any start-limit state accumulated since
	// the last operator-controlled activation; a reset failure fails the verb
	// rather than silently attempting a blocked activation.
	if verb == "start" || verb == "restart" {
		if e := resetFailed(); e != nil {
			return e
		}
	}
	if err := systemctlSuccess(verb, "webfleet.service"); err != nil {
		return err
	}
	return nil
}

// Uninstall stops and disables the service, removes the unit and reloads
// systemd. The data directory and installed binary are deliberately preserved.
// Uninstall is idempotent: when no unit is installed it is a successful no-op
// with no systemctl mutation; a foreign unit at the path is refused.
func Uninstall() error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireRoot("uninstall"); e != nil {
		return e
	}
	if _, e := os.Stat(UnitPath); errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e := requireManaged("uninstall"); e != nil {
		return e
	}
	// Surface a failed stop/disable rather than pretending uninstall succeeded.
	if e := systemctlSuccess("disable", "--now", "webfleet.service"); e != nil {
		return fmt.Errorf("uninstall: %w", e)
	}
	if e := os.Remove(UnitPath); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return systemctlSuccess("daemon-reload")
}

// effectiveListen returns the listener the installed process genuinely binds.
// Explicit units record the canonical --host/--port pair in ExecStart, which is
// the runtime listener. Legacy bootstrap units record the WEBFLEET_LISTEN
// address the unit sets as the runtime environment, which is what the
// foreground binds (Web Fleet has no config file to consult, so the recorded
// bootstrap address is the durable source).
func effectiveListen(meta unitMeta) string {
	return meta.listen
}

// InstalledDataDir returns the data directory recorded by the managed service unit.
// The boolean is false when the service is not installed. A present but invalid
// unit is an error so destructive CLI operations never fall back to another path.
func InstalledDataDir() (string, bool, error) {
	body, err := os.ReadFile(UnitPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cannot use installed service configuration: %w", err)
	}
	meta, err := readManagedUnit(string(body))
	if err != nil {
		return "", false, fmt.Errorf("cannot use installed service configuration: %w", err)
	}
	dataDir := meta.data
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return dataDir, true, nil
}

// Status reports the resolved service state, pid, data/listen configuration and
// a live health check. It is read-only and does not require root.
func Status(out io.Writer) error {
	if e := requireLinux(); e != nil {
		return e
	}
	body, e := os.ReadFile(UnitPath)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("webfleet.service is not installed (run `webfleet service install`)")
	}
	if e != nil {
		return fmt.Errorf("cannot read %s: %w", UnitPath, e)
	}
	meta, ve := readManagedUnit(string(body))
	if ve != nil {
		return fmt.Errorf("webfleet.service unit at %s is not valid: %v", UnitPath, ve)
	}
	enabled, _ := unitStateWord("is-enabled")
	active, _ := unitStateWord("is-active")
	pid, _, _ := systemctl("show", "-p", "MainPID", "--value", "webfleet.service")
	dataDir := meta.data
	listen := effectiveListen(meta)
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	if listen == "" {
		listen = DefaultListen
	}
	fmt.Fprintf(out, "unit:    webfleet.service\n")
	fmt.Fprintf(out, "file:    %s\n", UnitPath)
	fmt.Fprintf(out, "enabled: %s\n", strings.TrimSpace(enabled))
	fmt.Fprintf(out, "active:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "user:    %s\n", ServiceUser)
	fmt.Fprintf(out, "data:    %s\n", dataDir)
	fmt.Fprintf(out, "listen:  %s\n", listen)
	if strings.TrimSpace(active) != "active" {
		fmt.Fprintln(out, "health:  not running")
		return fmt.Errorf("webfleet.service is %q; expected active", strings.TrimSpace(active))
	}
	if err := healthCheckFunc("http://" + listen + "/healthz"); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

var healthCheckFunc = func(url string) error { return healthCheckReal(url) }

func healthCheckReal(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

// Logs streams the service journal. follow=false prints the current journal;
// follow=true tails live output.
func Logs(follow bool, out io.Writer) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireManaged("view logs for"); e != nil {
		return e
	}
	args := []string{"--unit", "webfleet.service"}
	if follow {
		args = append(args, "-f")
		code, err := defaultRunner.Stream("journalctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("journalctl exited with status %d", code)
		}
		return nil
	}
	o, code, err := defaultRunner.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("cannot run journalctl: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("journalctl exited %d: %s", code, bounded(strings.TrimSpace(o)))
	}
	fmt.Fprint(out, o)
	return nil
}

func Verify(path, want string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	got := hex.EncodeToString(h[:])
	if !strings.EqualFold(got, strings.TrimSpace(want)) {
		return fmt.Errorf("checksum mismatch: got %s", got)
	}
	return nil
}

func Update(artifact, want string) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("update requires root")
	}
	if e := requireManaged("update"); e != nil {
		return e
	}
	if e := Verify(artifact, want); e != nil {
		return e
	}
	// Transactional prior-state capture: read the current active state and
	// persist the rollback marker BEFORE touching the binary. A failure to
	// determine or record the state aborts the update so rollback can never
	// later guess.
	priorActive, err := unitStateWord("is-active")
	if err != nil {
		return fmt.Errorf("update: cannot determine current service state: %w", err)
	}
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("update: unexpected service state %q; refusing to update", priorActive)
	}
	wasActive := priorActive == "active"
	if _, e := os.Stat(BinaryPath); e == nil {
		if e := copyFile(BinaryPath, BinaryPath+".rollback", 0o755); e != nil {
			return e
		}
		if e := os.WriteFile(BinaryPath+".prior-active", []byte(priorActive), 0o600); e != nil {
			_ = os.Remove(BinaryPath + ".rollback")
			return fmt.Errorf("update: cannot record rollback state: %w", e)
		}
	}
	if e := copyFile(artifact, BinaryPath, 0o755); e != nil {
		return e
	}
	if !wasActive {
		// Preserve the stopped state: install the new binary, do not start it.
		return nil
	}
	// Verify real activation/health after the restart: a zero exit from
	// `restart` does not prove the process stayed alive. Both the initial-restart
	// failure and the later health failure share one recovery path, so a
	// recovery failure is always surfaced alongside the original update error.
	// The deliberate restart clears any accumulated start-limit state first; a
	// reset failure after the binary swap enters the verified recovery path.
	if e := resetFailed(); e != nil {
		updateErr := fmt.Errorf("restart after update: %v", e)
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	if out, code, err := systemctl("restart", "webfleet.service"); err != nil || code != 0 {
		updateErr := fmt.Errorf("restart after update: %s: %w", bounded(strings.TrimSpace(out)), errorIfNil(err, code, nil))
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	if e := verifyActiveAndHealthy(); e != nil {
		updateErr := fmt.Errorf("update: new binary failed to become healthy: %w", e)
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	// Successful active update: retain the rollback binary and the prior-active
	// marker so a later manual `service rollback` can still restore the previous
	// version and its operational state. The metadata is consumed only by a
	// subsequent successful rollback.
	return nil
}

var healthWindow = 30 * time.Second

// updateFailureWithRecovery returns the update error, augmenting it with a
// recovery error when the attempt to restore the previous version also failed.
func updateFailureWithRecovery(updateErr, recoveryErr error) error {
	if recoveryErr != nil {
		return fmt.Errorf("%v; recovery also failed: %v", updateErr, recoveryErr)
	}
	return updateErr
}

// verifyActiveAndHealthy polls a bounded window for the service to be active
// and its healthz endpoint to return 200.
func verifyActiveAndHealthy() error {
	listen := DefaultListen
	if b, e := os.ReadFile(UnitPath); e == nil {
		if meta, ve := readManagedUnit(string(b)); ve == nil && meta.listen != "" {
			listen = effectiveListen(meta)
		}
	}
	deadline := time.Now().Add(healthWindow)
	for time.Now().Before(deadline) {
		active, _ := unitStateWord("is-active")
		if strings.TrimSpace(active) == "active" {
			if err := healthCheckFunc("http://" + listen + "/healthz"); err == nil {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not become active and healthy within %s", healthWindow)
}

// restoreAfterFailedUpdate verifiably restores the previous version and its
// operational state after a failed update. It returns an error if any step of
// the recovery (stop, binary restore, restart, health) fails, so a failed
// update never silently claims a rollback happened.
// readPriorStateAtRecovery is a test-only seam: production reads the
// .prior-active marker file, but a test may override it to inject a missing or
// corrupt marker precisely at recovery time (after state capture and binary
// mutation), proving recovery fails closed rather than guessing.
var readPriorStateAtRecovery = func() (string, error) {
	b, err := os.ReadFile(BinaryPath + ".prior-active")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func restoreAfterFailedUpdate() error {
	// Fail closed: the prior-state marker was written transactionally before the
	// binary was replaced, so recovery must not guess at the active state.
	priorActive, err := readPriorStateAtRecovery()
	if err != nil {
		return fmt.Errorf("recovery: no prior-state marker: %w", err)
	}
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("recovery: invalid prior-state marker %q", priorActive)
	}
	if e := systemctlSuccess("stop", "webfleet.service"); e != nil {
		return fmt.Errorf("recovery: stop failed service: %w", e)
	}
	if e := copyFile(BinaryPath+".rollback", BinaryPath, 0o755); e != nil {
		return fmt.Errorf("recovery: restore old binary: %w", e)
	}
	if priorActive == "active" {
		if e := resetFailed(); e != nil {
			return fmt.Errorf("recovery: reset failed state: %w", e)
		}
		if e := systemctlSuccess("restart", "webfleet.service"); e != nil {
			return fmt.Errorf("recovery: restart old service: %w", e)
		}
		if e := verifyActiveAndHealthy(); e != nil {
			return fmt.Errorf("recovery: restored service not healthy: %w", e)
		}
	}
	// Verified recovery complete: consume both temporary rollback artifacts so no
	// stale rollback binary remains for the now-current (restored) version.
	_ = os.Remove(BinaryPath + ".prior-active")
	_ = os.Remove(BinaryPath + ".rollback")
	return nil
}

func Rollback() error {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("rollback requires root")
	}
	if e := requireManaged("rollback"); e != nil {
		return e
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); e != nil {
		return errors.New("no rollback binary available")
	}
	// Fail closed: the prior-active marker must exist and be valid. A missing
	// marker is a degraded/legacy condition, not a signal to default to active.
	b, err := os.ReadFile(BinaryPath + ".prior-active")
	if err != nil {
		return fmt.Errorf("rollback: no prior-state marker; refusing to guess the service state")
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("rollback: invalid prior-state marker %q", priorActive)
	}
	wasActive := priorActive == "active"
	// For an active prior state, clear any accumulated start-limit BEFORE any
	// binary mutation. A reset failure must leave the current binary, the
	// rollback binary, the prior-state marker and any existing .failed file
	// byte-for-byte unchanged so the operator can retry rollback; a stopped
	// prior needs no reset or restart.
	if wasActive {
		if e := resetFailed(); e != nil {
			return e
		}
	}
	cur := BinaryPath + ".failed"
	_ = os.Remove(cur)
	if e := os.Rename(BinaryPath, cur); e != nil {
		return e
	}
	if e := os.Rename(BinaryPath+".rollback", BinaryPath); e != nil {
		_ = os.Rename(cur, BinaryPath)
		return e
	}
	if !wasActive {
		// Stopped state preserved: consume rollback metadata only after success.
		_ = os.Remove(BinaryPath + ".prior-active")
		_ = os.Remove(BinaryPath + ".rollback")
		return nil
	}
	if e := systemctlSuccess("restart", "webfleet.service"); e != nil {
		return e
	}
	if e := verifyActiveAndHealthy(); e != nil {
		return e
	}
	_ = os.Remove(BinaryPath + ".prior-active")
	_ = os.Remove(BinaryPath + ".rollback")
	return nil
}
func Executable() string { p, _ := os.Executable(); p, _ = filepath.Abs(p); return p }

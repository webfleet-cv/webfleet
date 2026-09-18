//go:build linux

package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeRunner records systemctl/journalctl invocations and returns scripted
// outputs/exit codes so the lifecycle can be tested without a real manager.
// strict makes any unconfigured invocation fail with a nonzero exit so an
// unexpected lifecycle call can never be hidden by a permissive success default.
type fakeRunner struct {
	script map[string]fakeResult // key "verb args..." -> result
	log    []string
	calls  map[string]int // per-key call count for sequence scripting
	seq    map[string][]fakeResult
	strict bool
}
type fakeResult struct {
	out  string
	code int
	err  error
}

func (f *fakeRunner) Run(name string, args ...string) (string, int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	n := f.calls[key]
	f.calls[key] = n + 1
	if seq, ok := f.seq[key]; ok && n < len(seq) {
		r := seq[n]
		return r.out, r.code, r.err
	}
	if r, ok := f.script[key]; ok {
		return r.out, r.code, r.err
	}
	if f.strict {
		return "", 1, fmt.Errorf("unexpected command: %s", key)
	}
	return "", 0, nil
}
func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if r, ok := f.script[key]; ok {
		return r.code, r.err
	}
	if f.strict {
		return 1, fmt.Errorf("unexpected command: %s", key)
	}
	return 0, nil
}

// setupService points the unit/binary paths at temp files, simulates root and
// the service account, and installs a strict fake runner. It returns the fake
// runner and a cleanup. The descriptor-relative data-dir seams default to a
// simulated successful fresh-leaf establishment; tests needing real filesystem
// behavior override them (see useRealDataDirSeams).
func setupService(t *testing.T) *fakeRunner {
	t.Helper()
	dir := t.TempDir()
	oldUnit, oldBin := UnitPath, BinaryPath
	oldRoot, oldAccount := isRoot, ensureAccount
	oldUID := serviceUID
	oldOpenParent, oldConsistent := openDataParentSeam, dataParentConsistentSeam
	oldStatLeaf, oldParentSafe := statDataLeafSeam, parentSafeSeam
	oldMkdirAt := mkdirAtLeafSeam
	oldOpenAt, oldChmod, oldChown := openAtLeafSeam, fchmodLeafSeam, fchownLeafSeam
	oldFstat, oldUnlink, oldClose := fstatLeafSeam, unlinkAtSeam, closeFdSeam
	oldRunner := defaultRunner
	oldHealth := healthWindow
	oldPriorRead := readPriorStateAtRecovery
	UnitPath = filepath.Join(dir, "webfleet.service")
	BinaryPath = filepath.Join(dir, "webfleet")
	os.WriteFile(BinaryPath, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	isRoot = func() bool { return true }
	ensureAccount = func() error { return nil }
	serviceUID = func() (int, error) { return 4242, nil }
	openDataParentSeam = func(string) (int, error) { return 1, nil }
	dataParentConsistentSeam = func(int, string) bool { return true }
	parentSafeSeam = func(int) error { return nil }
	statDataLeafSeam = func(int, string) (dataLeafInfo, error) { return dataLeafInfo{}, os.ErrNotExist }
	mkdirAtLeafSeam = func(int, string) error { return nil }
	openAtLeafSeam = func(int, string) (int, error) { return 2, nil }
	fchmodLeafSeam = func(int) error { return nil }
	fchownLeafSeam = func(int) error { return nil }
	fstatLeafSeam = func(int) (dataLeafInfo, error) {
		return dataLeafInfo{isDir: true, mode: 0o700, uid: 4242}, nil
	}
	unlinkAtSeam = func(int, string) error { return nil }
	closeFdSeam = func(int) error { return nil }
	r := &fakeRunner{script: map[string]fakeResult{}, seq: map[string][]fakeResult{}, strict: true}
	// Deliberate lifecycle activations reset-failed first; script the default
	// success so existing tests observe the new order unless they override it.
	r.script["systemctl reset-failed webfleet.service"] = fakeResult{}
	defaultRunner = r
	t.Cleanup(func() {
		UnitPath, BinaryPath = oldUnit, oldBin
		isRoot, ensureAccount = oldRoot, oldAccount
		serviceUID = oldUID
		openDataParentSeam, dataParentConsistentSeam = oldOpenParent, oldConsistent
		statDataLeafSeam, parentSafeSeam = oldStatLeaf, oldParentSafe
		mkdirAtLeafSeam = oldMkdirAt
		openAtLeafSeam, fchmodLeafSeam, fchownLeafSeam = oldOpenAt, oldChmod, oldChown
		fstatLeafSeam, unlinkAtSeam, closeFdSeam = oldFstat, oldUnlink, oldClose
		healthWindow = oldHealth
		healthCheckFunc = func(url string) error { return healthCheckReal(url) }
		readPriorStateAtRecovery = oldPriorRead
		defaultRunner = oldRunner
	})
	return r
}

// prepareUpdate sets up the fake state (is-active), the prior-state marker, and
// a healthy health-check stub so update/rollback proceed on their normal path.
func prepareUpdate(r *fakeRunner, active string, healthOK bool) {
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: active, code: 0}
	old := healthCheckFunc
	healthCheckFunc = func(url string) error {
		if !healthOK {
			return fmt.Errorf("health failed")
		}
		return nil
	}
	_ = old
	_ = os.WriteFile(BinaryPath+".prior-active", []byte(active), 0o600)
}

func installManagedUnit(t *testing.T) {
	t.Helper()
	if e := os.WriteFile(UnitPath, []byte(Unit("/var/lib/webfleet", "127.0.0.1:8090", "")), 0o644); e != nil {
		t.Fatal(e)
	}
}

func TestUnitHardeningAndManagedMarker(t *testing.T) {
	setupService(t)
	u := Unit("/var/lib/webfleet", "127.0.0.1:8090", "")
	for _, x := range []string{"# Managed by webfleet. Do not edit manually.", "NoNewPrivileges=true", "ProtectSystem=strict", "ReadWritePaths=\"/var/lib/webfleet\"", "User=" + ServiceUser, "Group=" + ServiceGroup, "WantedBy=multi-user.target", "StartLimitIntervalSec=60", "StartLimitBurst=5"} {
		if !strings.Contains(u, x) {
			t.Fatal("missing " + x)
		}
	}
	if strings.Contains(u, "StartLimitIntervalSec=0") {
		t.Fatal("unit must retain a finite crash-loop limit, not disable it")
	}
	if !strings.Contains(Unit("/var/lib/web fleet", "127.0.0.1:8090", ""), "WEBFLEET_DATA_DIR=\"/var/lib/web fleet\"") {
		t.Fatal("data path with spaces is not quoted")
	}
	if e := os.WriteFile(UnitPath, []byte(u), 0o644); e != nil {
		t.Fatal(e)
	}
	if !managedUnit(UnitPath) {
		t.Fatal("managed marker not detected from the unit file")
	}
}

func TestValidateNoControlAndQuote(t *testing.T) {
	if e := validateNoControl("127.0.0.1:8090", "listen"); e != nil {
		t.Fatal(e)
	}
	if e := validateNoControl("127.0.0.1:8090\nfoo", "listen"); e == nil {
		t.Fatal("newline accepted")
	}
	if got := systemdQuote(`/a b/"x"$y`); got != `"/a b/\"x\"\$y"` {
		t.Fatalf("quote = %q", got)
	}
}

func TestLifecycleVerbsRequireManagedUnit(t *testing.T) {
	r := setupService(t)
	// Without an installed unit, verbs refuse (no systemctl call).
	for _, v := range []string{"start", "stop", "restart", "enable", "disable"} {
		if err := lifecycle(v); err == nil {
			t.Fatalf("%s succeeded without an installed unit", v)
		}
		if len(r.log) != 0 {
			t.Fatalf("%s touched systemctl without a managed unit", v)
		}
	}
	// With a managed unit, verbs dispatch to systemctl.
	installManagedUnit(t)
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if err := lifecycle("start"); err != nil {
		t.Fatal(err)
	}
	if !contains(r.log, "systemctl start webfleet.service") {
		t.Fatal("start did not call systemctl")
	}
	// A failed verb surfaces the exit code.
	r.script["systemctl stop webfleet.service"] = fakeResult{out: "Job failed", code: 1}
	if err := lifecycle("stop"); err == nil {
		t.Fatal("failed stop returned nil")
	}
}

func TestLifecycleResetFailedPrecedesStartRestart(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl start webfleet.service"] = fakeResult{}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	for _, v := range []string{"start", "restart"} {
		r.log = nil
		if e := lifecycle(v); e != nil {
			t.Fatalf("%s: %v", v, e)
		}
		if !ordered(r.log, []string{"systemctl reset-failed webfleet.service", "systemctl " + v + " webfleet.service"}) {
			t.Fatalf("%s must reset-failed before activating: %v", v, r.log)
		}
	}
	// A reset failure fails the verb and must not proceed to activation.
	r.script["systemctl reset-failed webfleet.service"] = fakeResult{out: "reset failed", code: 1}
	r.log = nil
	if e := lifecycle("start"); e == nil {
		t.Fatal("start succeeded despite reset-failed failure")
	}
	if contains(r.log, "systemctl start webfleet.service") {
		t.Fatalf("start proceeded after reset-failed failure: %v", r.log)
	}
}

func TestLifecycleStopDoesNotReset(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	if e := lifecycle("stop"); e != nil {
		t.Fatal(e)
	}
	if contains(r.log, "systemctl reset-failed webfleet.service") {
		t.Fatalf("stop must not reset-failed: %v", r.log)
	}
}

func TestLifecycleStartToleratesBenignResetNotLoaded(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl reset-failed webfleet.service"] = fakeResult{out: "Failed to reset failed state of unit webfleet.service: Unit webfleet.service not loaded.", code: 1}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := lifecycle("start"); e != nil {
		t.Fatalf("start must tolerate the benign 'not loaded' reset no-op: %v", e)
	}
	if !ordered(r.log, []string{"systemctl reset-failed webfleet.service", "systemctl start webfleet.service"}) {
		t.Fatalf("start must still reset-failed before activating: %v", r.log)
	}
}

func TestLifecycleRefusesForeignUnit(t *testing.T) {
	setupService(t)
	// A unit at the path WITHOUT the managed marker must be refused.
	if e := os.WriteFile(UnitPath, []byte("[Unit]\nDescription=admin unit\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"start", "stop", "restart", "enable", "disable", "uninstall"} {
		if err := lifecycle(v); err == nil {
			t.Fatalf("%s modified a foreign unit", v)
		}
	}
}

func TestInstallRequiresRootAndLinux(t *testing.T) {
	oldRoot := isRoot
	isRoot = func() bool { return false }
	defer func() { isRoot = oldRoot }()
	if e := Install("", t.TempDir(), "127.0.0.1:0", ""); e == nil {
		t.Fatal("install succeeded without root")
	}
}

func TestReinstallRestoresPriorStateOnFailure(t *testing.T) {
	r := setupService(t)
	// First install succeeds (fresh): write unit, daemon-reload, enable, start.
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	priorUnit, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(priorUnit), "Managed by webfleet") {
		t.Fatal("installed unit lacks the managed marker")
	}
	// Second install: prior enabled+active, changed unit (9090). The shared
	// restore mapping runs disable -> enable -> restart; the enable fails, so
	// rollback must restore the prior unit and re-apply the prior state.
	setState(r, "enabled", "active")
	r.seq["systemctl daemon-reload"] = []fakeResult{{}, {}, {}}
	r.seq["systemctl enable webfleet.service"] = []fakeResult{{}, {out: "failed to enable", code: 3}, {}}
	r.seq["systemctl disable webfleet.service"] = []fakeResult{{}, {}, {}}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", ""); e == nil {
		t.Fatal("failed reinstall returned nil")
	}
	got, _ := os.ReadFile(UnitPath)
	if string(got) != string(priorUnit) {
		t.Fatalf("reinstall failure did not restore the prior unit:\n--- got\n%s\n--- want\n%s", got, priorUnit)
	}
}

func TestStatusReportsStates(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value webfleet.service"] = fakeResult{out: "1234", code: 0}
	// Health check against the loopback listen from the unit.
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer h.Close()
	listen := strings.TrimPrefix(h.URL, "http://")
	os.WriteFile(UnitPath, []byte(Unit("/var/lib/webfleet", listen, "")), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"unit:    webfleet.service", "enabled: enabled", "active:  active", "pid:     1234", "data:    /var/lib/webfleet", "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q:\n%s", want, buf.String())
		}
	}
	// Not installed -> clear diagnostic.
	r2 := setupService(t)
	_ = r2
	os.Remove(UnitPath)
	if e := Status(io.Discard); e == nil {
		t.Fatal("status succeeded without an installed unit")
	}
}

func TestLogsConstruction(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["journalctl --unit webfleet.service"] = fakeResult{out: "boot log lines\n", code: 0}
	if e := Logs(false, io.Discard); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "journalctl --unit webfleet.service") {
		t.Fatal("logs did not run journalctl --unit")
	}
	r.log = nil
	r.script["journalctl --unit webfleet.service -f"] = fakeResult{code: 0}
	if e := Logs(true, io.Discard); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "journalctl --unit webfleet.service -f") {
		t.Fatal("follow did not add -f")
	}
}

func TestUninstallPreservesDataAndIsIdempotent(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl disable --now webfleet.service"] = fakeResult{}
	r.script["systemctl daemon-reload"] = fakeResult{}
	if e := Uninstall(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
		t.Fatal("unit file not removed")
	}
	// Repeated uninstall is a genuine idempotent no-op: unit already absent, no
	// systemctl mutation, no error.
	r.log = nil
	if e := Uninstall(); e != nil {
		t.Fatalf("uninstall of an already-absent unit should be a successful no-op: %v", e)
	}
	if len(r.log) != 0 {
		t.Fatalf("idempotent uninstall issued systemctl calls: %v", r.log)
	}
}

func TestQuotingSurvivesSpacesInDataPath(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	data := "/var/lib/web fleet data"
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := Install(exe, data, "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), `WEBFLEET_DATA_DIR="`+data+`"`) {
		t.Fatalf("spaced data path not quoted in unit:\n%s", b)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// ordered reports whether every element of want appears in log in the given
// relative order (not necessarily contiguously).
func ordered(log, want []string) bool {
	i := 0
	for _, l := range log {
		if i < len(want) && l == want[i] {
			i++
		}
	}
	return i == len(want)
}

func setState(r *fakeRunner, enabled, active string) {
	r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: enabled, code: 0}
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: active, code: 0}
}

func writeForeignUnit(t *testing.T) {
	t.Helper()
	os.WriteFile(UnitPath, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/thing\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
}

func TestUpdateAndRollbackRefuseForeignUnit(t *testing.T) {
	r := setupService(t)
	writeForeignUnit(t)
	before, _ := os.ReadFile(BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update mutated a foreign unit")
	}
	if e := Rollback(); e == nil {
		t.Fatal("rollback mutated a foreign unit")
	}
	after, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(before, after) {
		t.Fatal("update/rollback mutated the binary of a foreign unit")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart webfleet.service") {
			t.Fatalf("foreign unit triggered a restart: %s", call)
		}
	}
}

func TestReinstallChangedBinaryRestarts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	// A different executable than the installed one -> the shared restore
	// mapping re-applies the prior enabled+active state (disable, enable, restart).
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# different binary\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable webfleet.service"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart webfleet.service") {
		t.Fatal("changed binary did not trigger a restart")
	}
}

func TestInstallResetFailedPrecedesActivation(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# different binary\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable webfleet.service"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	if !ordered(r.log, []string{"systemctl reset-failed webfleet.service", "systemctl restart webfleet.service"}) {
		t.Fatalf("reinstall restart must be preceded by reset-failed: %v", r.log)
	}
}

func TestInstallResetFailedFailureRollsBack(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	priorUnit := mustRead(t, UnitPath)
	priorBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable webfleet.service"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	// The forward activation reset fails; the rollback reset succeeds.
	r.seq["systemctl reset-failed webfleet.service"] = []fakeResult{{out: "reset failed", code: 1}, {}}
	if err := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", ""); err == nil {
		t.Fatal("install succeeded despite reset-failed failure")
	} else if !strings.Contains(err.Error(), "reset-failed") {
		t.Fatalf("install error must surface the reset failure: %v", err)
	}
	if got := mustRead(t, UnitPath); !bytes.Equal(got, priorUnit) {
		t.Fatal("prior unit not restored after reset-failed failure")
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, priorBin) {
		t.Fatal("prior binary not restored after reset-failed failure")
	}
}

func TestReinstallSameBinaryIsNoOp(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	// Byte-identical executable + identical unit + enabled + active -> no-op.
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl daemon-reload") {
			t.Fatal("identical reinstall performed a daemon-reload")
		}
	}
}

// TestReinstallFailureRollbackRestoresExactState proves that a failed changed
// reinstall restores the exact prior enablement and active state for every
// supported combination, via the shared restore mapping.
func TestReinstallFailureRollbackRestoresExactState(t *testing.T) {
	cases := []struct {
		name            string
		enabled, active string
	}{
		{"enabled-active", "enabled", "active"},
		{"enabled-inactive", "enabled", "inactive"},
		{"disabled-active", "disabled", "active"},
		{"disabled-inactive", "disabled", "inactive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := setupService(t)
			installManagedUnit(t)
			priorBin := mustRead(t, BinaryPath)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "wf2")
			os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
			// Changed unit (different listen) -> reinstall path; a forward
			// activation step fails (restart for active priors, stop for inactive
			// priors), then rollback must restore everything.
			r.script["systemctl daemon-reload"] = fakeResult{}
			r.script["systemctl disable webfleet.service"] = fakeResult{}
			r.script["systemctl enable webfleet.service"] = fakeResult{}
			if tc.active == "active" {
				r.seq["systemctl restart webfleet.service"] = []fakeResult{{out: "activation failed", code: 1}, {}}
				r.script["systemctl stop webfleet.service"] = fakeResult{}
			} else {
				r.seq["systemctl stop webfleet.service"] = []fakeResult{{out: "activation failed", code: 1}, {}, {}}
				r.script["systemctl restart webfleet.service"] = fakeResult{}
			}
			if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", ""); e == nil {
				t.Fatal("failed reinstall returned nil")
			}
			// The prior unit must be restored.
			b, _ := os.ReadFile(UnitPath)
			if !strings.Contains(string(b), "127.0.0.1:8090") {
				t.Fatal("prior unit not restored after failed reinstall")
			}
			// The prior binary must be restored.
			if got := mustRead(t, BinaryPath); !bytes.Equal(got, priorBin) {
				t.Fatal("prior binary not restored after failed reinstall")
			}
			// The exact prior state must be re-applied by rollback, negative
			// states included.
			want := tc.enabled == "enabled"
			for _, call := range r.log {
				switch {
				case call == "systemctl enable webfleet.service" && !want:
					t.Fatal("rollback enabled a previously disabled service")
				case call == "systemctl enable --runtime webfleet.service" && !want:
					t.Fatal("rollback runtime-enabled a previously disabled service")
				}
			}
			// For a disabled prior, rollback must re-issue a disable after the
			// forward neutralization (>= 2 disable calls total).
			if !want {
				disables := 0
				for _, call := range r.log {
					if call == "systemctl disable webfleet.service" {
						disables++
					}
				}
				if disables < 2 {
					t.Fatalf("negative enabled state not re-applied during rollback (disable calls=%d)", disables)
				}
			}
			// For an inactive prior, rollback must issue a stop.
			if tc.active == "inactive" {
				stops := 0
				for _, call := range r.log {
					if call == "systemctl stop webfleet.service" {
						stops++
					}
				}
				if stops < 1 {
					t.Fatal("negative active state not re-applied during rollback (no stop)")
				}
			}
		})
	}
}

func TestUninstallSurfacesStopDisableFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl disable --now webfleet.service"] = fakeResult{out: "cannot stop", code: 1}
	if e := Uninstall(); e == nil {
		t.Fatal("uninstall ignored a failed disable --now")
	}
	if _, e := os.Stat(UnitPath); os.IsNotExist(e) {
		t.Fatal("uninstall removed the unit despite the failed stop/disable")
	}
}

func TestMalformedManagedUnitClassified(t *testing.T) {
	r := setupService(t)
	// Marker present but a required directive missing -> classified invalid.
	os.WriteFile(UnitPath, []byte("# Managed by webfleet. Do not edit manually.\n[Unit]\n[Service]\n[Install]\n"), 0o644)
	if e := lifecycle("start"); e == nil {
		t.Fatal("malformed managed unit accepted for start")
	}
	if e := Status(io.Discard); e == nil {
		t.Fatal("malformed managed unit accepted for status")
	}
	_ = r
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// allowTempDataDirs narrows the protected-hierarchy check so tests can build
// real data leaves under t.TempDir() (/tmp on Linux) without weakening the
// production contract; the refused system paths remain covered by dedicated
// tests.
func allowTempDataDirs(t *testing.T) {
	t.Helper()
	old := protectedDataHierarchies
	var filtered []string
	for _, p := range old {
		if p != "/tmp" && p != filepath.Clean(os.TempDir()) {
			filtered = append(filtered, p)
		}
	}
	protectedDataHierarchies = filtered
	t.Cleanup(func() { protectedDataHierarchies = old })
}

func fakeSHA(path string) string {
	h, _ := fileSHA256(path)
	return h
}

func TestUpdatePreservesActiveState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	// Active service -> update restarts it.
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart webfleet.service") {
		t.Fatal("active update did not restart")
	}
	// Stopped service -> update installs the binary and leaves it stopped.
	r.log = nil
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart webfleet.service") || strings.Contains(call, "start webfleet.service") {
			t.Fatalf("stopped update started the service: %s", call)
		}
	}
}

func TestUpdateFailedActivationRestoresOldBinaryAndActive(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart webfleet.service"] = fakeResult{out: "activation failed", code: 1}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("failed activation update returned nil")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("failed activation did not restore the old binary")
	}
	// The restore path restarted the old service.
	if !contains(r.log, "systemctl restart webfleet.service") {
		t.Fatal("restored active service was not restarted")
	}
}

func TestRollbackRestoresStoppedStateWithoutStarting(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	// Prior stopped service: update keeps it stopped (no start).
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	// Rollback must restore the old binary without starting the service.
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart webfleet.service") || strings.Contains(call, "start webfleet.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

func TestRollbackRestoresRunningState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	// Prior active service: update restarts (active), rollback restarts too.
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart webfleet.service") {
		t.Fatal("rollback of an active service did not restart it")
	}
	// After a successful rollback the metadata is consumed.
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("rollback metadata not consumed after successful rollback")
	}
	// Enable/disable state is never touched by update or rollback.
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") {
			t.Fatalf("update/rollback changed enablement: %s", call)
		}
	}
}

func TestUpdateResetFailedPrecedesRestart(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if !ordered(r.log, []string{"systemctl reset-failed webfleet.service", "systemctl restart webfleet.service"}) {
		t.Fatalf("update restart must be preceded by reset-failed: %v", r.log)
	}
}

func TestUpdateResetFailedFailureEntersRecovery(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	oldBin := mustRead(t, BinaryPath)
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	// The post-swap reset fails; the recovery reset succeeds.
	r.seq["systemctl reset-failed webfleet.service"] = []fakeResult{{out: "reset failed", code: 1}, {}}
	err := Update(exe, fakeSHA(exe))
	if err == nil {
		t.Fatal("update succeeded despite reset-failed failure")
	}
	if !strings.Contains(err.Error(), "restart after update") || !strings.Contains(err.Error(), "reset-failed") {
		t.Fatalf("update error must surface the reset failure: %v", err)
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, oldBin) {
		t.Fatal("recovery did not restore the old binary after reset-failed failure")
	}
}

func TestRollbackResetFailureLeavesStateIntactAndRetryable(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	currentBin := []byte("#!/bin/sh\n# current v2\nexit 0\n")
	rollbackBin := []byte("#!/bin/sh\n# rollback v1\nexit 0\n")
	os.WriteFile(BinaryPath, currentBin, 0o755)
	os.WriteFile(BinaryPath+".rollback", rollbackBin, 0o755)
	os.WriteFile(BinaryPath+".prior-active", []byte("active"), 0o600)
	// A pre-existing .failed sentinel proves reset failure does not replace it.
	os.WriteFile(BinaryPath+".failed", []byte("stale"), 0o600)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	// A reset failure must abort rollback BEFORE any binary mutation.
	r.script["systemctl reset-failed webfleet.service"] = fakeResult{out: "reset failed", code: 1}
	if e := Rollback(); e == nil {
		t.Fatal("rollback succeeded despite reset-failed failure")
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, currentBin) {
		t.Fatal("current binary changed after reset failure")
	}
	if got := mustRead(t, BinaryPath+".rollback"); !bytes.Equal(got, rollbackBin) {
		t.Fatal("rollback binary changed after reset failure")
	}
	if got := mustRead(t, BinaryPath+".prior-active"); !bytes.Equal(got, []byte("active")) {
		t.Fatal("prior-state marker changed after reset failure")
	}
	if got := mustRead(t, BinaryPath+".failed"); !bytes.Equal(got, []byte("stale")) {
		t.Fatal(".failed replacement created or overwritten after reset failure")
	}
	if contains(r.log, "systemctl restart webfleet.service") {
		t.Fatalf("restart attempted after reset failure: %v", r.log)
	}
	// A retry with a successful reset can proceed to completion.
	r.script["systemctl reset-failed webfleet.service"] = fakeResult{}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatalf("retry rollback after reset failure failed: %v", e)
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, rollbackBin) {
		t.Fatal("retry rollback did not install the rollback binary")
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("rollback metadata not consumed after successful retry")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal("prior-state marker not consumed after successful retry")
	}
}

func TestRollbackOrderingResetBeforeBinarySwap(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	rollbackBin := []byte("#!/bin/sh\n# rollback v1\nexit 0\n")
	os.WriteFile(BinaryPath, []byte("#!/bin/sh\n# current v2\nexit 0\n"), 0o755)
	os.WriteFile(BinaryPath+".rollback", rollbackBin, 0o755)
	os.WriteFile(BinaryPath+".prior-active", []byte("active"), 0o600)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	// Active rollback order: reset-failed precedes the restart, which follows
	// the binary swap; metadata is consumed only after health verification.
	if len(r.log) < 2 || r.log[0] != "systemctl reset-failed webfleet.service" || r.log[1] != "systemctl restart webfleet.service" {
		t.Fatalf("active rollback must reset-failed then restart: %v", r.log)
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, rollbackBin) {
		t.Fatal("rollback binary not installed after successful rollback")
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal(".rollback not consumed after successful rollback")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal(".prior-active not consumed after successful rollback")
	}
}

func TestRollbackStoppedStateNeverResets(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	rollbackBin := []byte("#!/bin/sh\n# rollback v1\nexit 0\n")
	os.WriteFile(BinaryPath, []byte("#!/bin/sh\n# current v2\nexit 0\n"), 0o755)
	os.WriteFile(BinaryPath+".rollback", rollbackBin, 0o755)
	os.WriteFile(BinaryPath+".prior-active", []byte("inactive"), 0o600)
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	if contains(r.log, "systemctl reset-failed webfleet.service") {
		t.Fatalf("stopped rollback must not reset-failed: %v", r.log)
	}
	if contains(r.log, "systemctl restart webfleet.service") {
		t.Fatalf("stopped rollback must not restart: %v", r.log)
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, rollbackBin) {
		t.Fatal("stopped rollback did not restore the rollback binary")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal("prior-state marker not consumed after stopped rollback")
	}
}

func TestUpdateRecoveryResetFailedPrecedesRestart(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	// Forward restart fails, sending update into recovery; the recovery restart
	// must be preceded by its own reset-failed.
	r.seq["systemctl restart webfleet.service"] = []fakeResult{{out: "activation failed", code: 1}, {}}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("failed-activation update returned nil")
	}
	// Last restart is the recovery restart and must be preceded by reset-failed.
	idx := -1
	for i, call := range r.log {
		if call == "systemctl restart webfleet.service" {
			idx = i
		}
	}
	if idx < 0 || !contains(r.log[:idx], "systemctl reset-failed webfleet.service") {
		t.Fatalf("recovery restart must be preceded by reset-failed: %v", r.log)
	}
}

func TestUpdateVerifiesHealthNotJustRestartExit(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	// restart exits 0 but the service never becomes active/healthy -> update
	// must fail and restore the old binary.
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false) // health never OK
	healthWindow = 1 * time.Second
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update succeeded although the new binary never became healthy")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("unhealthy update did not restore the old binary")
	}
}

func TestUpdateActiveStateQueryFailureAborts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	// Failure to query the current active state -> abort before binary mutation.
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: "", code: 1, err: fmt.Errorf("systemctl is-active failed")}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update proceeded when the active state could not be determined")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("state-query failure still mutated the binary")
	}
}

func TestUpdatePriorStateMarkerWriteFailureAborts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "inactive")
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: "inactive", code: 0}
	// Make the marker write fail by creating a directory at that path.
	os.MkdirAll(BinaryPath+".prior-active", 0o700)
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update proceeded when the rollback marker could not be written")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("marker-write failure still mutated the binary")
	}
}

func TestRollbackFailClosedWithoutMarker(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	// A rollback binary exists but no prior-state marker -> rollback must
	// refuse rather than defaulting to active.
	os.WriteFile(BinaryPath+".rollback", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.Remove(BinaryPath + ".prior-active")
	if e := Rollback(); e == nil {
		t.Fatal("rollback defaulted to active without a prior-state marker")
	}
	_ = r
}

// TestEndToEndActiveUpdateThenRollback proves a successful update of an active
// service retains rollback metadata and a later manual Rollback restores the
// old binary and the active state - with NO test-side metadata fabrication.
func TestEndToEndActiveUpdateThenRollback(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	// Metadata must survive a successful active update.
	if _, e := os.Stat(BinaryPath + ".rollback"); e != nil {
		t.Fatal("rollback binary missing after successful update")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after successful update")
	}
	now, _ := os.ReadFile(BinaryPath)
	if bytes.Equal(now, oldBin) {
		t.Fatal("update did not replace the binary")
	}
	// Manual rollback restores the old binary and the active state.
	r.log = nil
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	if !contains(r.log, "systemctl restart webfleet.service") {
		t.Fatal("rollback of an active service did not restart it")
	}
}

// TestEndToEndStoppedUpdateThenRollback proves a successful update of a stopped
// service retains metadata and a later Rollback restores the old binary while
// leaving the service stopped.
func TestEndToEndStoppedUpdateThenRollback(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after stopped update")
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart webfleet.service") || strings.Contains(call, "start webfleet.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

// TestFailedUpdateRecoverySurfacesFailures proves recovery is verified and a
// failed restoration step is surfaced rather than silently claimed.
func TestFailedUpdateRecoverySurfacesFailures(t *testing.T) {
	// Recovery restart failure after an unhealthy new version is surfaced.
	{
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		prepareUpdate(r, "active", false) // health fails -> recovery path
		healthWindow = 1 * time.Second
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
		r.script["systemctl restart webfleet.service"] = fakeResult{}
		r.script["systemctl stop webfleet.service"] = fakeResult{}
		// Recovery restart (the 2nd restart call) fails.
		r.seq["systemctl restart webfleet.service"] = []fakeResult{{}, {out: "restore failed", code: 1}}
		uerr := Update(exe, fakeSHA(exe))
		if uerr == nil {
			t.Fatal("update succeeded despite a failed recovery restart")
		}
		if !strings.Contains(uerr.Error(), "recovery") {
			t.Fatalf("recovery restart failure not surfaced: %v", uerr)
		}
	}
	// Recovery stop failure is surfaced.
	{
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		prepareUpdate(r, "active", false)
		healthWindow = 1 * time.Second
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
		r.script["systemctl restart webfleet.service"] = fakeResult{}
		r.script["systemctl stop webfleet.service"] = fakeResult{out: "cannot stop", code: 1}
		uerr := Update(exe, fakeSHA(exe))
		if uerr == nil {
			t.Fatal("update succeeded despite a failed recovery stop")
		}
		if !strings.Contains(uerr.Error(), "recovery") {
			t.Fatalf("recovery stop failure not surfaced: %v", uerr)
		}
	}
}

// TestInitialRestartFailureSurfacesRecoveryFailure proves the initial-restart
// failure branch also surfaces a recovery failure (not just the health branch).
func TestInitialRestartFailureSurfacesRecoveryFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	// Initial restart of the new binary fails (code 1), then recovery's own
	// restart also fails.
	r.seq["systemctl restart webfleet.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{out: "recovery restart failed", code: 1},
	}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite initial restart failure")
	}
	if !strings.Contains(uerr.Error(), "restart after update") {
		t.Fatalf("original restart failure missing: %v", uerr)
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery failure not surfaced: %v", uerr)
	}
}

// TestInitialRestartFailureRecoverySucceedsCleansMetadata proves when the
// initial restart fails but recovery succeeds, the old binary is restored,
// health is verified, and both rollback artifacts are consumed.
func TestInitialRestartFailureRecoverySucceedsCleansMetadata(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart webfleet.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1}, // initial
		{}, // recovery restart succeeds
	}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update should report the initial restart failure")
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("recovery did not restore the old binary")
	}
	// Verified recovery consumed both artifacts.
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("stale rollback binary left after verified recovery")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal("stale prior-active marker left after verified recovery")
	}
}

// TestRecoveryFailsClosedWithoutMarker proves recovery does not guess to active
// when the prior-state marker is missing/invalid.
func TestRecoveryFailsClosedWithoutMarker(t *testing.T) {
	// The seam removes/corrupts the marker AFTER Update() has captured and
	// persisted it but BEFORE recovery reads it, so this genuinely exercises the
	// "marker missing at recovery time" fail-closed contract.
	run := func(desc string, mutate func()) {
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		prepareUpdate(r, "active", false)
		healthWindow = 1 * time.Second
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
		r.script["systemctl restart webfleet.service"] = fakeResult{}
		// Record the log position at the moment the marker is found missing, so
		// we can assert NO recovery activation (stop/restart) is issued AFTER the
		// fail-closed decision - independent of the update's own legitimate restart.
		markerRead := 0
		readPriorStateAtRecovery = func() (string, error) {
			markerRead = len(r.log)
			mutate()
			b, err := os.ReadFile(BinaryPath + ".prior-active")
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		}
		uerr := Update(exe, fakeSHA(exe))
		if uerr == nil {
			t.Fatalf("[%s] update succeeded despite a missing recovery marker", desc)
		}
		// A genuine fail-closed guard: recovery must refuse to guess and report
		// that the prior-state marker is missing/invalid - not merely surface
		// some unrelated "recovery" error.
		if !strings.Contains(uerr.Error(), "prior-state marker") {
			t.Fatalf("[%s] recovery did not fail closed on the marker (got: %v)", desc, uerr)
		}
		// Fail closed means recovery must NOT proceed into a guessed-active
		// restart: no stop/restart may be issued after the marker failure.
		for _, call := range r.log[markerRead:] {
			if strings.HasPrefix(call, "systemctl stop ") || strings.HasPrefix(call, "systemctl restart ") {
				t.Fatalf("[%s] recovery proceeded to activate after the marker failure: %s", desc, call)
			}
		}
	}
	run("missing", func() { os.Remove(BinaryPath + ".prior-active") })
	run("invalid", func() { os.WriteFile(BinaryPath+".prior-active", []byte("bogus"), 0o600) })
}

// TestReinstallPreservesExactStateMatrix proves a successful changed reinstall
// preserves the exact prior enablement and active state for every supported
// combination instead of forcing enabled+active. Under the strict harness any
// unscripted (i.e. unexpected) systemctl call would already have failed the
// install, so the assertion below documents the expected restore mapping.
func TestReinstallPreservesExactStateMatrix(t *testing.T) {
	cases := []struct {
		name            string
		enabled, active string
		wantSteps       []string
	}{
		{"enabled-active", "enabled", "active",
			[]string{"systemctl disable webfleet.service", "systemctl enable webfleet.service", "systemctl restart webfleet.service"}},
		{"enabled-inactive", "enabled", "inactive",
			[]string{"systemctl disable webfleet.service", "systemctl enable webfleet.service", "systemctl stop webfleet.service"}},
		{"disabled-active", "disabled", "active",
			[]string{"systemctl disable webfleet.service", "systemctl restart webfleet.service"}},
		{"disabled-inactive", "disabled", "inactive",
			[]string{"systemctl disable webfleet.service", "systemctl stop webfleet.service"}},
		{"enabled-runtime-active", "enabled-runtime", "active",
			[]string{"systemctl disable webfleet.service", "systemctl enable --runtime webfleet.service", "systemctl restart webfleet.service"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := setupService(t)
			installManagedUnit(t)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "wf2")
			os.WriteFile(exe, []byte("#!/bin/sh\n# different binary\nexit 0\n"), 0o755)
			r.script["systemctl daemon-reload"] = fakeResult{}
			r.script["systemctl disable webfleet.service"] = fakeResult{}
			r.script["systemctl enable webfleet.service"] = fakeResult{}
			r.script["systemctl enable --runtime webfleet.service"] = fakeResult{}
			r.script["systemctl restart webfleet.service"] = fakeResult{}
			r.script["systemctl stop webfleet.service"] = fakeResult{}
			if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", ""); e != nil {
				t.Fatal(e)
			}
			for _, want := range tc.wantSteps {
				if !contains(r.log, want) {
					t.Fatalf("reinstall did not preserve prior state; missing %q in %v", want, r.log)
				}
			}
			// The service must never be started unconditionally by a reinstall.
			for _, call := range r.log {
				if strings.HasPrefix(call, "systemctl start ") {
					t.Fatalf("reinstall started the service unconditionally: %s", call)
				}
			}
		})
	}
}

// TestReinstallRejectsUnsupportedPriorStates proves install refuses unsupported
// systemd-special enablement/active words BEFORE any mutation, so it can never
// overwrite a state it cannot recreate exactly.
func TestReinstallRejectsUnsupportedPriorStates(t *testing.T) {
	unsupported := map[string][]string{
		"is-enabled": {"masked", "static", "linked", "generated", "transient", "not-found", "alias", "indirect", "unknown", ""},
		"is-active":  {"failed", "reloading", "activating", "deactivating", "dead", "unknown", ""},
	}
	for verb, words := range unsupported {
		for _, word := range words {
			t.Run(verb+"="+word, func(t *testing.T) {
				r := setupService(t)
				installManagedUnit(t)
				unitBefore, _ := os.ReadFile(UnitPath)
				binBefore := mustRead(t, BinaryPath)
				if verb == "is-enabled" {
					r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: word, code: 3}
					r.script["systemctl is-active webfleet.service"] = fakeResult{out: "inactive", code: 0}
				} else {
					r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: "disabled", code: 0}
					r.script["systemctl is-active webfleet.service"] = fakeResult{out: word, code: 3}
				}
				exe := filepath.Join(t.TempDir(), "wf2")
				os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
				if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", ""); e == nil {
					t.Fatalf("install accepted unsupported prior state %s=%q", verb, word)
				}
				if got, _ := os.ReadFile(UnitPath); !bytes.Equal(got, unitBefore) {
					t.Fatalf("unsupported state %s=%q still rewrote the unit", verb, word)
				}
				if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
					t.Fatalf("unsupported state %s=%q still rewrote the binary", verb, word)
				}
				for _, call := range r.log {
					if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl restart ") || strings.HasPrefix(call, "systemctl start ") {
						t.Fatalf("unsupported state %s=%q still activated the service: %s", verb, word, call)
					}
				}
			})
		}
	}
}

// TestInstallRefusesStateQueryFailure proves a query failure (as opposed to a
// legitimate negative state) aborts install before mutation.
func TestInstallRefusesStateQueryFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	unitBefore, _ := os.ReadFile(UnitPath)
	binBefore := mustRead(t, BinaryPath)
	r.script["systemctl is-enabled webfleet.service"] = fakeResult{err: fmt.Errorf("cannot reach systemd")}
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", ""); e == nil {
		t.Fatal("install proceeded when the prior enablement state could not be queried")
	}
	if got, _ := os.ReadFile(UnitPath); !bytes.Equal(got, unitBefore) {
		t.Fatal("state-query failure still rewrote the unit")
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
		t.Fatal("state-query failure still mutated the binary")
	}
}

// TestInstallSurfacesRollbackFailure proves the returned install error combines
// the original forward failure with a rollback failure instead of claiming
// "installation rolled back" when the rollback itself failed.
func TestInstallSurfacesRollbackFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "wf2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
	// Forward: daemon-reload, disable, enable -> the forward enable fails.
	// Rollback: neutralization (stop, disable), restore, daemon-reload, then the
	// restore enable also fails -> combined error.
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.seq["systemctl disable webfleet.service"] = []fakeResult{{}, {}, {}}
	r.seq["systemctl enable webfleet.service"] = []fakeResult{
		{out: "forward enable failed", code: 1},
		{out: "restore enable failed", code: 1},
	}
	err := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", "")
	if err == nil {
		t.Fatal("install with a failing forward activation returned nil")
	}
	if !strings.Contains(err.Error(), "forward enable failed") {
		t.Fatalf("forward install failure missing: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("rollback failure not combined into the error: %v", err)
	}
	if !strings.Contains(err.Error(), "restore enable failed") {
		t.Fatalf("rollback failure detail missing: %v", err)
	}
}

// TestInstallRefusesSystemRootDataDir proves dangerous system roots are refused
// before any mutation.
func TestInstallRefusesSystemRootDataDir(t *testing.T) {
	for _, dir := range []string{"/", "/etc", "/usr", "/var", "/bin"} {
		t.Run(dir, func(t *testing.T) {
			r := setupService(t)
			binBefore := mustRead(t, BinaryPath)
			exe := filepath.Join(t.TempDir(), "wf")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if e := Install(exe, dir, "127.0.0.1:8090", ""); e == nil {
				t.Fatalf("install accepted system root data dir %q", dir)
			}
			if len(r.log) != 0 {
				t.Fatalf("install %q touched systemctl before refusing", dir)
			}
			if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
				t.Fatalf("install %q wrote a unit before refusing", dir)
			}
			if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
				t.Fatalf("install %q mutated the binary before refusing", dir)
			}
		})
	}
}

// TestInstallRefusesRelativeDataDir proves install requires an absolute data
// path.
func TestInstallRefusesRelativeDataDir(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, "relative/data", "127.0.0.1:8090", ""); e == nil {
		t.Fatal("install accepted a relative data directory")
	}
	if len(r.log) != 0 {
		t.Fatal("relative data dir install touched systemctl")
	}
}

// TestInstallRefusesExistingForeignOwnedDir proves an existing directory not
// owned by the service account is refused rather than silently adopted, before
// any metadata mutation.
func TestInstallRefusesExistingForeignOwnedDir(t *testing.T) {
	allowTempDataDirs(t)
	r := setupService(t)
	dir := filepath.Join(t.TempDir(), "existing")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	testUID := os.Getuid()
	svcUID := testUID + 1
	if svcUID == 0 {
		svcUID = 9999
	}
	serviceUID = func() (int, error) { return svcUID, nil }
	useRealDataDirSeams(t)
	binBefore := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, dir, "127.0.0.1:8090", ""); e == nil {
		t.Fatal("install adopted a foreign-owned existing directory")
	}
	if len(r.log) != 0 {
		t.Fatal("foreign-owned dir install touched systemctl")
	}
	if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
		t.Fatal("foreign-owned dir install wrote a unit before refusing")
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
		t.Fatal("foreign-owned dir install mutated the binary")
	}
}

// TestInstallReusesServiceOwnedExistingDir proves an existing directory already
// owned by the service account is validated and reused rather than re-adopted.
func TestInstallReusesServiceOwnedExistingDir(t *testing.T) {
	allowTempDataDirs(t)
	r := setupService(t)
	dir := filepath.Join(t.TempDir(), "owned")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	serviceUID = func() (int, error) { return os.Getuid(), nil }
	useRealDataDirSeams(t)
	trustParentForTest(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := Install(exe, dir, "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), dir) {
		t.Fatal("installed unit does not reference the reused data dir")
	}
}

// TestTamperedManagedUnitRejected proves a hand edit to a managed unit (without
// updating the integrity checksum) is refused for both lifecycle actions and
// status.
func TestTamperedManagedUnitRejected(t *testing.T) {
	setupService(t)
	u := Unit("/var/lib/webfleet", "127.0.0.1:8090", "")
	tampered := strings.Replace(u, "127.0.0.1:8090", "127.0.0.1:9090", 1)
	os.WriteFile(UnitPath, []byte(tampered), 0o644)
	if e := lifecycle("start"); e == nil {
		t.Fatal("tampered managed unit accepted for start")
	}
	if e := Status(io.Discard); e == nil {
		t.Fatal("tampered managed unit accepted for status")
	}
}

// TestManagedUnitHeaderMalformedRejected proves malformed integrity headers are
// refused rather than treated as healthy.
func TestManagedUnitHeaderMalformedRejected(t *testing.T) {
	setupService(t)
	cases := map[string]string{
		"missing-version-header": unitMarker + "\n[Unit]\nDescription=Web Fleet website monitoring\n",
		"duplicated-header":      unitMarker + "\n" + managedPrefix + "v1 sha256=" + strings.Repeat("0", 64) + "\n" + managedPrefix + "v1 sha256=" + strings.Repeat("0", 64) + "\n[Unit]\n",
		"bad-checksum-length":    unitMarker + "\n" + managedPrefix + "v1 sha256=tooshort\n[Unit]\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			os.WriteFile(UnitPath, []byte(body), 0o644)
			if e := lifecycle("start"); e == nil {
				t.Fatalf("malformed managed unit (%s) accepted for start", name)
			}
			if e := Status(io.Discard); e == nil {
				t.Fatalf("malformed managed unit (%s) accepted for status", name)
			}
		})
	}
}

// TestStrictHarnessRejectsUnexpectedCalls documents that the fake harness is
// fail-closed: an unconfigured systemctl invocation must fail, so a test can
// never silently paper over a new lifecycle call.
func TestStrictHarnessRejectsUnexpectedCalls(t *testing.T) {
	r := setupService(t)
	_, code, err := r.Run("systemctl", "bogus", "webfleet.service")
	if err == nil || code == 0 {
		t.Fatal("strict harness accepted an unexpected systemctl call")
	}
}

type mutationCounts struct{ account, mkdir, chmod, chown int }

func countMutations() *mutationCounts {
	c := &mutationCounts{}
	ensureAccount = func() error { c.account++; return nil }
	mkdirAtLeafSeam = func(int, string) error { c.mkdir++; return nil }
	fchmodLeafSeam = func(int) error { c.chmod++; return nil }
	fchownLeafSeam = func(int) error { c.chown++; return nil }
	return c
}

// useRealDataDirSeams switches the descriptor-relative data-dir seams to their
// real implementations so tests can exercise real leaf creation and inspection
// under t.TempDir(). The ownership step is stubbed to a no-op (the service
// account does not exist on the test host), and the parent-trust check uses the
// real fstat so fresh-leaf tests must call trustParentForTest (t.TempDir() is
// not root-owned).
func useRealDataDirSeams(t *testing.T) {
	t.Helper()
	openDataParentSeam = openDataParentReal
	dataParentConsistentSeam = dataParentConsistentReal
	parentSafeSeam = parentSafeReal
	statDataLeafSeam = statDataLeafReal
	mkdirAtLeafSeam = mkdirAtLeafReal
	openAtLeafSeam = openAtLeafReal
	fchmodLeafSeam = fchmodLeafReal
	fchownLeafSeam = func(int) error { return nil }
	fstatLeafSeam = fstatLeafReal
	unlinkAtSeam = unlinkAtLeafReal
	closeFdSeam = closeFdReal
}

// trustParentForTest makes the retained parent appear as a trusted root-owned,
// non-writable directory so fresh-leaf tests can create leaves under
// t.TempDir() (which is owned by the test user, not root).
func trustParentForTest(t *testing.T) {
	t.Helper()
	parentSafeSeam = func(int) error { return nil }
}

// parentSafeFromInfo mirrors the production safe-parent contract for test seams:
// the parent must be a directory, owned by root (uid 0), and not group- or
// world-writable.
func parentSafeFromInfo(info dataLeafInfo) func(int) error {
	return func(int) error {
		if !info.isDir {
			return errors.New("parent is not a directory")
		}
		if info.uid != 0 {
			return fmt.Errorf("parent owned by UID %d; requires root-owned", info.uid)
		}
		if info.mode&0o022 != 0 {
			return fmt.Errorf("parent is group- or world-writable")
		}
		return nil
	}
}

func assertNoMutation(t *testing.T, c *mutationCounts, what string) {
	t.Helper()
	if c.account != 0 || c.mkdir != 0 || c.chmod != 0 || c.chown != 0 {
		t.Fatalf("%s: install mutated the machine before refusing (account=%d mkdir=%d chmod=%d chown=%d)", what, c.account, c.mkdir, c.chmod, c.chown)
	}
}

// TestInstallPreflightBeforeAnyMutation proves every preflight-only refusal
// (foreign/tampered unit, unsupported or unqueryable systemd state) happens
// before any account/data-directory mutation, using real mutation counters
// rather than systemctl-call assertions alone.
func TestInstallPreflightBeforeAnyMutation(t *testing.T) {
	exe := func() string {
		p := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		return p
	}
	t.Run("foreign-unit", func(t *testing.T) {
		r := setupService(t)
		writeForeignUnit(t)
		c := countMutations()
		if e := Install(exe(), "/srv/new-webfleet", "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install proceeded with a foreign unit")
		}
		assertNoMutation(t, c, "foreign unit")
		_ = r
	})
	t.Run("tampered-unit", func(t *testing.T) {
		r := setupService(t)
		u := Unit("/var/lib/webfleet", "127.0.0.1:8090", "")
		os.WriteFile(UnitPath, []byte(strings.Replace(u, "127.0.0.1:8090", "127.0.0.1:9090", 1)), 0o644)
		c := countMutations()
		if e := Install(exe(), "/srv/new-webfleet", "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install proceeded with a tampered unit")
		}
		assertNoMutation(t, c, "tampered unit")
		_ = r
	})
	t.Run("unsupported-is-enabled", func(t *testing.T) {
		r := setupService(t)
		installManagedUnit(t)
		r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: "masked", code: 1}
		r.script["systemctl is-active webfleet.service"] = fakeResult{out: "inactive", code: 0}
		c := countMutations()
		if e := Install(exe(), "/srv/new-webfleet", "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install proceeded with an unsupported enablement state")
		}
		assertNoMutation(t, c, "unsupported is-enabled")
	})
	t.Run("unsupported-is-active", func(t *testing.T) {
		r := setupService(t)
		installManagedUnit(t)
		r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: "disabled", code: 0}
		r.script["systemctl is-active webfleet.service"] = fakeResult{out: "failed", code: 3}
		c := countMutations()
		if e := Install(exe(), "/srv/new-webfleet", "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install proceeded with an unsupported active state")
		}
		assertNoMutation(t, c, "unsupported is-active")
	})
	t.Run("state-query-failure", func(t *testing.T) {
		r := setupService(t)
		installManagedUnit(t)
		r.script["systemctl is-enabled webfleet.service"] = fakeResult{err: fmt.Errorf("cannot reach systemd")}
		c := countMutations()
		if e := Install(exe(), "/srv/new-webfleet", "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install proceeded when the prior enablement state could not be queried")
		}
		assertNoMutation(t, c, "state-query failure")
	})
}

// TestPrepareDataDirLeafOnlyContract proves the data directory is a
// final-leaf-only creation primitive: an existing parent + missing leaf is
// created as a single leaf, a missing parent is refused with nothing created,
// and the service account ownership applies only to the leaf.
func TestPrepareDataDirLeafOnlyContract(t *testing.T) {
	t.Run("existing-parent-creates-leaf-only", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		parent := t.TempDir()
		leaf := filepath.Join(parent, "webfleet")
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl enable webfleet.service"] = fakeResult{}
		r.script["systemctl start webfleet.service"] = fakeResult{}
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(leaf); e != nil {
			t.Fatalf("final leaf was not created: %v", e)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 1 {
			t.Fatalf("parent gained unexpected entries: %v", entries)
		}
	})
	t.Run("missing-parent-refused", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		root := t.TempDir()
		leaf := filepath.Join(root, "new-parent", "webfleet")
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install created a data leaf under a missing parent")
		}
		if _, e := os.Stat(filepath.Join(root, "new-parent")); !os.IsNotExist(e) {
			t.Fatalf("missing parent was created: %v", e)
		}
		if _, e := os.Stat(leaf); !os.IsNotExist(e) {
			t.Fatalf("leaf was created under a missing parent: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("missing-parent install touched systemctl")
		}
	})
}

// TestInstallRefusesProtectedHierarchyDescendants proves descendants of the
// protected system hierarchies (/etc, /usr, /tmp, /run, /bin, /home, /root,
// ...) are refused before any mutation.
func TestInstallRefusesProtectedHierarchyDescendants(t *testing.T) {
	for _, dir := range []string{
		"/etc/webfleet", "/usr/local/webfleet", "/tmp/webfleet", "/run/webfleet",
		"/bin/webfleet", "/home/alice/webfleet", "/root/webfleet", "/sbin/webfleet",
	} {
		t.Run(dir, func(t *testing.T) {
			r := setupService(t)
			binBefore := mustRead(t, BinaryPath)
			exe := filepath.Join(t.TempDir(), "wf")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if e := Install(exe, dir, "127.0.0.1:8090", ""); e == nil {
				t.Fatalf("install accepted protected hierarchy descendant %q", dir)
			}
			if len(r.log) != 0 {
				t.Fatalf("%q touched systemctl before refusing", dir)
			}
			if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
				t.Fatalf("%q mutated the binary before refusing", dir)
			}
			if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
				t.Fatalf("%q wrote a unit before refusing", dir)
			}
		})
	}
}

// TestValidateDataDirPathAllowsCanonical proves the canonical and deliberate
// custom data namespaces (/var/lib/<project>, /srv/<project>) are allowed.
func TestValidateDataDirPathAllowsCanonical(t *testing.T) {
	for _, dir := range []string{"/var/lib/webfleet", "/var/lib/something", "/srv/webfleet", "/srv/monitoring/data"} {
		if e := validateDataDirPath(dir); e != nil {
			t.Fatalf("canonical data dir %q refused: %v", dir, e)
		}
	}
}

// TestDataDirEstablishmentFailuresCleanUp proves a failure to fully establish
// the data leaf (mode, ownership, or post-creation inspection) fails the
// install BEFORE any binary/unit/systemd mutation, removes the partial leaf via
// the retained parent descriptor, and reports the cleanup result.
func TestDataDirEstablishmentFailuresCleanUp(t *testing.T) {
	run := func(name string, breakIt func()) {
		t.Run(name, func(t *testing.T) {
			allowTempDataDirs(t)
			r := setupService(t)
			useRealDataDirSeams(t)
			trustParentForTest(t)
			leaf := filepath.Join(t.TempDir(), "webfleet")
			binBefore := mustRead(t, BinaryPath)
			breakIt()
			exe := filepath.Join(t.TempDir(), "wf")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
				t.Fatal("install succeeded despite a data-leaf establishment failure")
			}
			if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
				t.Fatal("unit written despite the data-leaf failure")
			}
			if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
				t.Fatal("binary mutated despite the data-leaf failure")
			}
			if hasMutatingSystemctl(r.log) {
				t.Fatalf("systemctl mutated despite the data-leaf failure: %v", r.log)
			}
			if _, e := os.Stat(leaf); !os.IsNotExist(e) {
				t.Fatal("partial leaf was not cleaned up after the establishment failure")
			}
		})
	}
	run("chmod-failure", func() { fchmodLeafSeam = func(int) error { return errors.New("chmod denied") } })
	run("chown-failure", func() { fchownLeafSeam = func(int) error { return errors.New("chown denied") } })
	run("inspection-failure", func() {
		fstatLeafSeam = func(int) (dataLeafInfo, error) { return dataLeafInfo{}, errors.New("inspect denied") }
	})
	run("bind-failure", func() {
		openAtLeafSeam = func(int, string) (int, error) { return -1, errors.New("bind denied") }
	})

	// A failure to establish mode 0700 must be surfaced as such.
	t.Run("chmod-error-message", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		leaf := filepath.Join(t.TempDir(), "webfleet")
		fchmodLeafSeam = func(int) error { return errors.New("chmod denied") }
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install succeeded despite a chmod failure")
		} else if !strings.Contains(e.Error(), "mode 0700") {
			t.Fatalf("chmod failure not surfaced: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("chmod-failure install touched systemctl")
		}
	})

	// A cleanup failure after a failed establishment must be reported, not
	// silently claimed as rolled back.
	t.Run("cleanup-failure-reported", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		leaf := filepath.Join(t.TempDir(), "webfleet")
		fchmodLeafSeam = func(int) error { return errors.New("chmod denied") }
		unlinkAtSeam = func(int, string) error { return errors.New("unlink denied") }
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install succeeded despite a cleanup failure")
		} else if !strings.Contains(e.Error(), "partial leaf cleanup incomplete") {
			t.Fatalf("cleanup failure not surfaced: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("cleanup-failure install touched systemctl")
		}
	})
}

// TestInstallSurfacesRollbackNeutralizationFailures proves the initial rollback
// stop/disable (the neutralization boundary) failures are collected into the
// combined error rather than discarded.
func TestInstallSurfacesRollbackNeutralizationFailures(t *testing.T) {
	t.Run("rollback-stop-failure", func(t *testing.T) {
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl stop webfleet.service"] = fakeResult{out: "cannot stop", code: 1}
		r.script["systemctl restart webfleet.service"] = fakeResult{}
		r.seq["systemctl disable webfleet.service"] = []fakeResult{{}, {}, {}}
		r.seq["systemctl enable webfleet.service"] = []fakeResult{{out: "forward enable failed", code: 1}, {}}
		err := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", "")
		if err == nil {
			t.Fatal("install returned nil")
		}
		if !strings.Contains(err.Error(), "rollback incomplete") {
			t.Fatalf("rollback failure marker missing: %v", err)
		}
		if !strings.Contains(err.Error(), "stop failed service") {
			t.Fatalf("rollback stop failure not surfaced: %v", err)
		}
	})
	t.Run("rollback-disable-failure", func(t *testing.T) {
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl stop webfleet.service"] = fakeResult{}
		r.script["systemctl restart webfleet.service"] = fakeResult{}
		r.seq["systemctl disable webfleet.service"] = []fakeResult{{}, {out: "cannot disable", code: 1}, {out: "cannot disable", code: 1}}
		r.seq["systemctl enable webfleet.service"] = []fakeResult{{out: "forward enable failed", code: 1}}
		err := Install(exe, "/var/lib/webfleet", "127.0.0.1:9090", "")
		if err == nil {
			t.Fatal("install returned nil")
		}
		if !strings.Contains(err.Error(), "rollback incomplete") {
			t.Fatalf("rollback failure marker missing: %v", err)
		}
		if !strings.Contains(err.Error(), "disable failed service") {
			t.Fatalf("rollback disable failure not surfaced: %v", err)
		}
	})
	t.Run("fresh-install-rollback-disable-failure", func(t *testing.T) {
		r := setupService(t)
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl enable webfleet.service"] = fakeResult{}
		r.script["systemctl start webfleet.service"] = fakeResult{out: "activation failed", code: 1}
		r.script["systemctl stop webfleet.service"] = fakeResult{}
		r.script["systemctl disable webfleet.service"] = fakeResult{out: "cannot disable", code: 1}
		err := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", "")
		if err == nil {
			t.Fatal("install returned nil")
		}
		if !strings.Contains(err.Error(), "rollback incomplete") {
			t.Fatalf("rollback failure marker missing: %v", err)
		}
		if !strings.Contains(err.Error(), "disable failed service") {
			t.Fatalf("fresh-install rollback disable failure not surfaced: %v", err)
		}
	})
}

// hasMutatingSystemctl reports whether a call log contains any lifecycle-mutating
// systemctl invocation (read-only state queries are excluded).
func hasMutatingSystemctl(log []string) bool {
	for _, call := range log {
		for _, prefix := range []string{
			"systemctl enable ", "systemctl disable ", "systemctl start ",
			"systemctl restart ", "systemctl stop ", "systemctl daemon-reload",
		} {
			if strings.HasPrefix(call, prefix) {
				return true
			}
		}
	}
	return false
}

// TestInstallRefusesExistingUnacceptableDirBeforeMutation proves an existing
// unacceptable (foreign-owned) data directory is refused with ZERO account/data
// mutation and zero binary/unit/systemctl mutation: the account is never created
// merely to discover the directory is unsuitable.
func TestInstallRefusesExistingUnacceptableDirBeforeMutation(t *testing.T) {
	allowTempDataDirs(t)
	r := setupService(t)
	dir := filepath.Join(t.TempDir(), "existing")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	testUID := os.Getuid()
	svcUID := testUID + 1
	if svcUID == 0 {
		svcUID = 9999
	}
	serviceUID = func() (int, error) { return svcUID, nil }
	useRealDataDirSeams(t)
	c := countMutations()
	binBefore := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, dir, "127.0.0.1:8090", ""); e == nil {
		t.Fatal("install adopted a foreign-owned existing directory")
	}
	assertNoMutation(t, c, "existing unacceptable data dir")
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
		t.Fatal("binary mutated before refusing")
	}
	if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
		t.Fatal("unit written before refusing")
	}
	if len(r.log) != 0 {
		t.Fatal("systemctl touched before refusing")
	}
}

// TestReinstallDataDirContractWithNoOp proves the genuine no-op requires the
// recorded data directory to already exist as a safe service-owned leaf: a
// missing leaf is repaired (not silently skipped), and an unsafe/foreign leaf is
// refused with no unrelated mutation.
func TestReinstallDataDirContractWithNoOp(t *testing.T) {
	t.Run("genuine-noop-with-valid-data-dir", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		dataDir := filepath.Join(t.TempDir(), "webfleet")
		if e := os.Mkdir(dataDir, 0o700); e != nil {
			t.Fatal(e)
		}
		os.WriteFile(UnitPath, []byte(Unit(dataDir, "127.0.0.1:8090", "")), 0o644)
		setState(r, "enabled", "active")
		serviceUID = func() (int, error) { return os.Getuid(), nil }
		useRealDataDirSeams(t)
		trustParentForTest(t)
		c := countMutations()
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
		if e := Install(exe, dataDir, "127.0.0.1:8090", ""); e != nil {
			t.Fatal(e)
		}
		if hasMutatingSystemctl(r.log) {
			t.Fatalf("genuine no-op issued mutating systemctl calls: %v", r.log)
		}
		assertNoMutation(t, c, "genuine no-op")
	})
	t.Run("missing-data-leaf-repaired-not-noop", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		dataDir := filepath.Join(t.TempDir(), "webfleet")
		os.WriteFile(UnitPath, []byte(Unit(dataDir, "127.0.0.1:8090", "")), 0o644)
		setState(r, "enabled", "active")
		useRealDataDirSeams(t)
		trustParentForTest(t)
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
		if e := Install(exe, dataDir, "127.0.0.1:8090", ""); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(dataDir); e != nil {
			t.Fatalf("missing data leaf was not repaired: %v", e)
		}
		if hasMutatingSystemctl(r.log) {
			t.Fatalf("repair-only install issued mutating systemctl calls: %v", r.log)
		}
	})
	t.Run("unsafe-existing-data-dir-refused", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		dataDir := filepath.Join(t.TempDir(), "webfleet")
		if e := os.Mkdir(dataDir, 0o700); e != nil {
			t.Fatal(e)
		}
		os.WriteFile(UnitPath, []byte(Unit(dataDir, "127.0.0.1:8090", "")), 0o644)
		setState(r, "enabled", "active")
		testUID := os.Getuid()
		svcUID := testUID + 1
		if svcUID == 0 {
			svcUID = 9999
		}
		serviceUID = func() (int, error) { return svcUID, nil }
		useRealDataDirSeams(t)
		c := countMutations()
		binBefore := mustRead(t, BinaryPath)
		unitBefore, _ := os.ReadFile(UnitPath)
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
		if e := Install(exe, dataDir, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install accepted an unsafe existing data dir")
		}
		assertNoMutation(t, c, "unsafe existing data dir")
		if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
			t.Fatal("binary mutated before refusing")
		}
		if got, _ := os.ReadFile(UnitPath); !bytes.Equal(got, unitBefore) {
			t.Fatal("unit mutated before refusing")
		}
		if hasMutatingSystemctl(r.log) {
			t.Fatal("systemctl mutated before refusing")
		}
	})
}

// TestDataDirAncestorSymlinkEscape proves an allowed-looking lexical path cannot
// resolve through symlinked ancestors into an unrelated location: legitimate
// parents are accepted, symlinked parents/intermediates are refused (never
// silently redirected), and no leaf is ever created at the resolved target.
func TestDataDirAncestorSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	exe := func() string {
		p := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		return p
	}

	t.Run("legitimate-parent-accepted", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		realParent := filepath.Join(base, "real")
		if e := os.Mkdir(realParent, 0o700); e != nil {
			t.Fatal(e)
		}
		leaf := filepath.Join(realParent, "webfleet")
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl enable webfleet.service"] = fakeResult{}
		r.script["systemctl start webfleet.service"] = fakeResult{}
		if e := Install(exe(), leaf, "127.0.0.1:8090", ""); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(leaf); e != nil {
			t.Fatalf("legitimate leaf not created: %v", e)
		}
	})
	t.Run("immediate-symlink-parent-refused", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		target := t.TempDir()
		link := filepath.Join(base, "link")
		if e := os.Symlink(target, link); e != nil {
			t.Fatal(e)
		}
		leaf := filepath.Join(link, "webfleet")
		if e := Install(exe(), leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install accepted a data leaf through a symlinked parent")
		}
		if _, e := os.Stat(filepath.Join(target, "webfleet")); !os.IsNotExist(e) {
			t.Fatalf("leaf created at the symlink target: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("symlink-escape install touched systemctl")
		}
	})
	t.Run("intermediate-symlink-refused", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		target := t.TempDir()
		link := filepath.Join(base, "link2")
		if e := os.Symlink(target, link); e != nil {
			t.Fatal(e)
		}
		child := filepath.Join(target, "child")
		if e := os.Mkdir(child, 0o700); e != nil {
			t.Fatal(e)
		}
		leaf := filepath.Join(link, "child", "webfleet")
		if e := Install(exe(), leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install accepted a leaf through an intermediate symlink")
		}
		if _, e := os.Stat(filepath.Join(child, "webfleet")); !os.IsNotExist(e) {
			t.Fatalf("leaf created at the resolved symlink target: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("symlink-escape install touched systemctl")
		}
	})
	// A symlinked ancestor into another otherwise-allowed hierarchy is refused
	// outright rather than silently redirected, even though the target is not
	// protected: the privileged installer never follows symlinked service-data
	// ancestry.
	t.Run("symlink-into-allowed-hierarchy-refused", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		target := t.TempDir()
		link := filepath.Join(base, "link3")
		if e := os.Symlink(target, link); e != nil {
			t.Fatal(e)
		}
		leaf := filepath.Join(link, "webfleet")
		if e := Install(exe(), leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install followed a symlinked ancestor into another hierarchy")
		}
		if _, e := os.Stat(filepath.Join(target, "webfleet")); !os.IsNotExist(e) {
			t.Fatalf("leaf created at the symlink target: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("symlink-escape install touched systemctl")
		}
	})
	// An ancestor replaced after inspection but before creation is detected via
	// the retained parent descriptor and refused; the substituted (now symlinked)
	// location never receives a leaf.
	t.Run("ancestor-swap-after-inspection-refused", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		original := t.TempDir()
		substitute := t.TempDir()
		leaf := filepath.Join(original, "webfleet")
		// Between inspection (parent descriptor opened) and establishment, an
		// attacker replaces the parent with a symlink to the substitute.
		ensureAccount = func() error {
			if e := os.Rename(original, original+"-moved"); e != nil {
				return e
			}
			return os.Symlink(substitute, original)
		}
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install proceeded after the parent was swapped for a symlink")
		}
		if _, e := os.Stat(filepath.Join(substitute, "webfleet")); !os.IsNotExist(e) {
			t.Fatalf("leaf created at the substituted target: %v", e)
		}
		if _, e := os.Stat(filepath.Join(original+"-moved", "webfleet")); !os.IsNotExist(e) {
			t.Fatalf("leaf created at the renamed original: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("ancestor-swap install touched systemctl")
		}
	})
}

// fdTracker records which data-dir descriptors were opened and how many times
// each was closed, so descriptor-lifecycle tests can prove exactly-once close
// (no leaks on inspection errors/no-op returns, no double-close).
type fdTracker struct {
	opened []int
	closed map[int]int
}

func trackFds(t *testing.T) *fdTracker {
	t.Helper()
	tr := &fdTracker{closed: map[int]int{}}
	oldOpenParent := openDataParentSeam
	oldOpenAt := openAtLeafSeam
	oldClose := closeFdSeam
	openDataParentSeam = func(p string) (int, error) {
		fd, err := oldOpenParent(p)
		if err == nil {
			tr.opened = append(tr.opened, fd)
		}
		return fd, err
	}
	openAtLeafSeam = func(fd int, name string) (int, error) {
		nfd, err := oldOpenAt(fd, name)
		if err == nil {
			tr.opened = append(tr.opened, nfd)
		}
		return nfd, err
	}
	closeFdSeam = func(fd int) error {
		tr.closed[fd]++
		return oldClose(fd)
	}
	t.Cleanup(func() {
		openDataParentSeam = oldOpenParent
		openAtLeafSeam = oldOpenAt
		closeFdSeam = oldClose
	})
	return tr
}

func (tr *fdTracker) assert(t *testing.T) {
	t.Helper()
	if len(tr.opened) == 0 {
		t.Fatal("no data-dir descriptors were opened; tracking ineffective")
	}
	for _, fd := range tr.opened {
		if tr.closed[fd] != 1 {
			t.Fatalf("opened fd %d was closed %d times (want exactly once)", fd, tr.closed[fd])
		}
	}
	for fd, n := range tr.closed {
		if n > 1 {
			t.Fatalf("fd %d was closed %d times (double close)", fd, n)
		}
	}
}

// TestDataDirDescriptorsClosedExactlyOnce proves parent and leaf descriptors are
// closed exactly once across success, no-op, refusal and failure paths.
func TestDataDirDescriptorsClosedExactlyOnce(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		leaf := filepath.Join(t.TempDir(), "webfleet")
		tr := trackFds(t)
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl enable webfleet.service"] = fakeResult{}
		r.script["systemctl start webfleet.service"] = fakeResult{}
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e != nil {
			t.Fatal(e)
		}
		tr.assert(t)
	})
	t.Run("noop", func(t *testing.T) {
		allowTempDataDirs(t)
		r := setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		dataDir := filepath.Join(t.TempDir(), "webfleet")
		if e := os.Mkdir(dataDir, 0o700); e != nil {
			t.Fatal(e)
		}
		os.WriteFile(UnitPath, []byte(Unit(dataDir, "127.0.0.1:8090", "")), 0o644)
		setState(r, "enabled", "active")
		serviceUID = func() (int, error) { return os.Getuid(), nil }
		tr := trackFds(t)
		exe := filepath.Join(t.TempDir(), "wf2")
		os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
		if e := Install(exe, dataDir, "127.0.0.1:8090", ""); e != nil {
			t.Fatal(e)
		}
		tr.assert(t)
	})
	t.Run("refusal", func(t *testing.T) {
		allowTempDataDirs(t)
		setupService(t)
		useRealDataDirSeams(t)
		dataDir := filepath.Join(t.TempDir(), "webfleet")
		if e := os.Mkdir(dataDir, 0o700); e != nil {
			t.Fatal(e)
		}
		svcUID := os.Getuid() + 1
		serviceUID = func() (int, error) { return svcUID, nil }
		tr := trackFds(t)
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, dataDir, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install adopted a foreign-owned leaf")
		}
		tr.assert(t)
	})
	t.Run("failure", func(t *testing.T) {
		allowTempDataDirs(t)
		setupService(t)
		useRealDataDirSeams(t)
		trustParentForTest(t)
		leaf := filepath.Join(t.TempDir(), "webfleet")
		fchmodLeafSeam = func(int) error { return errors.New("chmod denied") }
		tr := trackFds(t)
		exe := filepath.Join(t.TempDir(), "wf")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
			t.Fatal("install succeeded despite a chmod failure")
		}
		tr.assert(t)
	})
}

// TestDataDirExistingLeafReplacementNotMutated proves an existing leaf inspected
// and retained by descriptor is the ONLY possible mutation target: renaming the
// leaf and replacing it with another ordinary directory between inspection and
// establishment leaves the replacement untouched (O_NOFOLLOW alone is
// insufficient against ordinary-directory replacement; descriptor binding is
// the fix).
func TestDataDirExistingLeafReplacementNotMutated(t *testing.T) {
	allowTempDataDirs(t)
	r := setupService(t)
	useRealDataDirSeams(t)
	trustParentForTest(t)
	parent := t.TempDir()
	leaf := filepath.Join(parent, "webfleet")
	if e := os.Mkdir(leaf, 0o755); e != nil {
		t.Fatal(e)
	}
	serviceUID = func() (int, error) { return os.Getuid(), nil }
	// Between inspection (leaf descriptor retained) and establishment, the leaf
	// is renamed away and replaced with another ordinary directory.
	ensureAccount = func() error {
		if e := os.Rename(leaf, leaf+"-orig"); e != nil {
			return e
		}
		return os.Mkdir(leaf, 0o755)
	}
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := Install(exe, leaf, "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	// The replacement is NOT chmodded: its mode stays 0755.
	fi, _ := os.Stat(leaf)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("replacement leaf was mutated (mode %o)", fi.Mode().Perm())
	}
	// The retained original (renamed) descriptor WAS the mutation target: 0700.
	oi, _ := os.Stat(leaf + "-orig")
	if oi.Mode().Perm() != 0o700 {
		t.Fatalf("retained original leaf not normalized to 0700 (mode %o)", oi.Mode().Perm())
	}
}

// TestDataDirFreshLeafBindRace proves a replacement of the freshly created leaf
// between mkdirat and openat is detected (the bound entry is not the expected
// fresh directory) and the replacement is never chmod'd or chown'd.
func TestDataDirFreshLeafBindRace(t *testing.T) {
	allowTempDataDirs(t)
	r := setupService(t)
	useRealDataDirSeams(t)
	trustParentForTest(t)
	parent := t.TempDir()
	leaf := filepath.Join(parent, "webfleet")
	// Between mkdirat and openat the created leaf is renamed away and replaced
	// with another ordinary directory of a different mode.
	mkdirAtLeafSeam = func(fd int, name string) error {
		if e := unix.Mkdirat(fd, name, 0o700); e != nil {
			return e
		}
		if e := os.Rename(filepath.Join(parent, name), filepath.Join(parent, name+"-orig")); e != nil {
			return e
		}
		return os.Mkdir(filepath.Join(parent, name), 0o755)
	}
	unlinkAtSeam = func(int, string) error { return nil } // keep the replacement observable
	binBefore := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
		t.Fatal("install bound a replaced fresh leaf")
	}
	// The replacement was never chmod'd to 0700.
	fi, _ := os.Stat(leaf)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("replacement leaf was mutated (mode %o)", fi.Mode().Perm())
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
		t.Fatal("binary mutated despite the bind-race refusal")
	}
	if hasMutatingSystemctl(r.log) {
		t.Fatalf("systemctl mutated despite the bind-race refusal: %v", r.log)
	}
}

// TestDataDirFreshRequiresTrustedParent proves a fresh data leaf is only created
// under a root-owned, non-group/world-writable parent; an untrusted parent is
// refused before any account/data/binary/unit/systemd mutation.
func TestDataDirFreshRequiresTrustedParent(t *testing.T) {
	cases := []struct {
		name string
		info dataLeafInfo
		ok   bool
	}{
		{"root-0755", dataLeafInfo{isDir: true, mode: 0o755, uid: 0}, true},
		{"root-0700", dataLeafInfo{isDir: true, mode: 0o700, uid: 0}, true},
		{"non-root-owned", dataLeafInfo{isDir: true, mode: 0o755, uid: 1000}, false},
		{"group-writable", dataLeafInfo{isDir: true, mode: 0o775, uid: 0}, false},
		{"world-writable", dataLeafInfo{isDir: true, mode: 0o777, uid: 0}, false},
		{"not-a-directory", dataLeafInfo{isDir: false, mode: 0o755, uid: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowTempDataDirs(t)
			r := setupService(t)
			useRealDataDirSeams(t)
			parentSafeSeam = parentSafeFromInfo(tc.info)
			leaf := filepath.Join(t.TempDir(), "webfleet")
			binBefore := mustRead(t, BinaryPath)
			exe := filepath.Join(t.TempDir(), "wf")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if tc.ok {
				r.script["systemctl daemon-reload"] = fakeResult{}
				r.script["systemctl enable webfleet.service"] = fakeResult{}
				r.script["systemctl start webfleet.service"] = fakeResult{}
				if e := Install(exe, leaf, "127.0.0.1:8090", ""); e != nil {
					t.Fatalf("trusted parent rejected: %v", e)
				}
				if _, e := os.Stat(leaf); e != nil {
					t.Fatalf("fresh leaf not created under trusted parent: %v", e)
				}
			} else {
				c := countMutations()
				if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
					t.Fatal("install created a leaf under an untrusted parent")
				}
				assertNoMutation(t, c, tc.name)
				if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
					t.Fatal("unit written under an untrusted parent")
				}
				if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
					t.Fatal("binary mutated under an untrusted parent")
				}
				if hasMutatingSystemctl(r.log) {
					t.Fatal("systemctl mutated under an untrusted parent")
				}
			}
		})
	}
}

// TestDataDirParentPathnameSymlinkSwapRefused proves the parent-consistency
// check re-walks the current pathname with O_NOFOLLOW instead of following
// newly introduced symlinks: renaming the parent between inspection and
// establishment and replacing its pathname with a symlink pointing back to the
// renamed original is refused before any leaf/binary/unit/systemd mutation. An
// EvalSymlinks-based check would follow the symlink, observe the same dev+ino
// as the retained descriptor, and wrongly pass; the no-symlink re-walk refuses.
func TestDataDirParentPathnameSymlinkSwapRefused(t *testing.T) {
	allowTempDataDirs(t)
	r := setupService(t)
	useRealDataDirSeams(t)
	trustParentForTest(t)
	parent := t.TempDir()
	leaf := filepath.Join(parent, "webfleet")
	// Between inspection (parent descriptor retained) and establishment the
	// parent is renamed away and its pathname replaced with a symlink pointing
	// back to the renamed original.
	ensureAccount = func() error {
		if e := os.Rename(parent, parent+"-original"); e != nil {
			return e
		}
		return os.Symlink(parent+"-original", parent)
	}
	t.Cleanup(func() { os.RemoveAll(parent + "-original"); os.Remove(parent) })
	binBefore := mustRead(t, BinaryPath)
	tr := trackFds(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, leaf, "127.0.0.1:8090", ""); e == nil {
		t.Fatal("install proceeded after the parent pathname became a symlink")
	} else if !strings.Contains(e.Error(), "parent") {
		t.Fatalf("refusal did not identify the parent pathname: %v", e)
	}
	// No leaf was created anywhere (the refusal happens before any leaf mutation).
	if _, e := os.Stat(filepath.Join(parent+"-original", "webfleet")); !os.IsNotExist(e) {
		t.Fatal("leaf created through the symlinked parent pathname")
	}
	if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
		t.Fatal("binary mutated despite the parent-pathname refusal")
	}
	if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
		t.Fatal("unit written despite the parent-pathname refusal")
	}
	if hasMutatingSystemctl(r.log) {
		t.Fatalf("systemctl mutated despite the parent-pathname refusal: %v", r.log)
	}
	tr.assert(t)
}

// oldStyleUnit renders a managed unit exactly as the pre-listen-mode format
// wrote it (no listen-mode marker), so the read path can prove old units
// default to bootstrap.
func oldStyleUnit(dataDir, listen string) string {
	meta := "# webfleet-data: " + dataDir + "\n# webfleet-listen: " + listen + "\n"
	content := meta + unitBody(dataDir, listen, "")
	sum := sha256.Sum256([]byte(content))
	header := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

func TestUnitListenModeMarkers(t *testing.T) {
	explicit := UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7336", "")
	if !strings.Contains(explicit, "# webfleet-listen-mode: explicit") {
		t.Fatalf("host/port unit missing explicit mode marker:\n%s", explicit)
	}
	if _, err := readManagedUnit(explicit); err != nil {
		t.Fatalf("explicit unit should validate: %v", err)
	}
	legacy := Unit("/var/lib/webfleet", "127.0.0.1:8090", "")
	if !strings.Contains(legacy, "# webfleet-listen-mode: bootstrap") {
		t.Fatalf("legacy unit missing bootstrap mode marker:\n%s", legacy)
	}
	if _, err := readManagedUnit(legacy); err != nil {
		t.Fatalf("legacy unit should validate: %v", err)
	}
	// A hostile mode value is rejected.
	bad := strings.Replace(legacy, "# webfleet-listen-mode: bootstrap", "# webfleet-listen-mode: attacker", 1)
	if _, err := readManagedUnit(bad); err == nil {
		t.Fatal("invalid listen-mode accepted")
	}
}

func TestOldUnitWithoutMarkerDefaultsToBootstrap(t *testing.T) {
	old := oldStyleUnit("/var/lib/webfleet", "127.0.0.1:8090")
	meta, err := readManagedUnit(old)
	if err != nil {
		t.Fatalf("old-style unit should validate: %v", err)
	}
	if meta.listenMode != modeBootstrap {
		t.Fatalf("old unit listen-mode = %q, want bootstrap", meta.listenMode)
	}
}

func TestUnitExplicitRecordsHostPortInExecStart(t *testing.T) {
	u := UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7336", "")
	if !strings.Contains(u, `"--host" "127.0.0.1" "--port" "7336"`) {
		t.Fatalf("explicit unit must record --host/--port in ExecStart:\n%s", u)
	}
	if strings.Contains(u, "WEBFLEET_LISTEN") {
		t.Fatalf("explicit unit must not set WEBFLEET_LISTEN env:\n%s", u)
	}
	if !strings.Contains(u, "WEBFLEET_DATA_DIR") {
		t.Fatalf("explicit unit must retain WEBFLEET_DATA_DIR env:\n%s", u)
	}
	if !strings.Contains(u, "# webfleet-listen: 127.0.0.1:7336") {
		t.Fatalf("explicit unit must record the canonical joined listener:\n%s", u)
	}
	if !strings.Contains(u, "StartLimitIntervalSec=60") || !strings.Contains(u, "StartLimitBurst=5") {
		t.Fatalf("explicit unit must retain a finite crash-loop limit:\n%s", u)
	}
	if strings.Contains(u, "StartLimitIntervalSec=0") {
		t.Fatalf("explicit unit must not disable the start limiter:\n%s", u)
	}
	// IPv6 hosts are bracketed in the metadata and ExecStart.
	u6 := UnitExplicit("/var/lib/webfleet", "::1", "7336", "")
	if !strings.Contains(u6, "# webfleet-listen: [::1]:7336") {
		t.Fatalf("explicit IPv6 unit must bracket the host:\n%s", u6)
	}
	if !strings.Contains(u6, `"--host" "::1"`) {
		t.Fatalf("explicit IPv6 unit must record --host ::1:\n%s", u6)
	}
}

func TestInstallExplicitWritesExplicitUnit(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := InstallExplicit(exe, "/var/lib/webfleet", "127.0.0.1", "7336", ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), "# webfleet-listen-mode: explicit") {
		t.Fatalf("installed unit must be explicit mode:\n%s", b)
	}
	if !strings.Contains(string(b), `"--host" "127.0.0.1" "--port" "7336"`) {
		t.Fatalf("installed unit must record --host/--port:\n%s", b)
	}
	// Reinstall with a different port must update the unit and restart.
	setState(r, "enabled", "active")
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable webfleet.service"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	if e := InstallExplicit(exe, "/var/lib/webfleet", "127.0.0.1", "7402", ""); e != nil {
		t.Fatal(e)
	}
	b2, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b2), `"--port" "7402"`) {
		t.Fatalf("reinstalled unit must record 7402:\n%s", b2)
	}
	if !strings.Contains(string(b2), "# webfleet-listen-mode: explicit") {
		t.Fatalf("reinstalled unit must remain explicit mode:\n%s", b2)
	}
	if !contains(r.log, "systemctl restart webfleet.service") {
		t.Fatalf("changed listener must restart the service; calls: %v", r.log)
	}
}

func TestInstallBootstrapWritesBootstrapUnit(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/webfleet", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), "# webfleet-listen-mode: bootstrap") {
		t.Fatalf("legacy install must be bootstrap mode:\n%s", b)
	}
	if !strings.Contains(string(b), `WEBFLEET_LISTEN="127.0.0.1:8090"`) {
		t.Fatalf("legacy install must record the WEBFLEET_LISTEN env:\n%s", b)
	}
	if strings.Contains(string(b), "--host") {
		t.Fatalf("legacy install must not record --host/--port:\n%s", b)
	}
}

// TestReinstallExplicitPreservesExactPriorState proves the explicit install
// path shares the same transactional state-preservation and rollback contract
// as the legacy path: a changed reinstall restores the exact prior unit on a
// forward failure.
func TestReinstallExplicitPreservesExactPriorState(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wf")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	if e := InstallExplicit(exe, "/var/lib/webfleet", "127.0.0.1", "7336", ""); e != nil {
		t.Fatal(e)
	}
	priorUnit, _ := os.ReadFile(UnitPath)
	setState(r, "enabled", "active")
	r.seq["systemctl daemon-reload"] = []fakeResult{{}, {}, {}}
	r.seq["systemctl enable webfleet.service"] = []fakeResult{{}, {out: "failed to enable", code: 3}, {}}
	r.seq["systemctl disable webfleet.service"] = []fakeResult{{}, {}, {}}
	r.script["systemctl restart webfleet.service"] = fakeResult{}
	r.script["systemctl stop webfleet.service"] = fakeResult{}
	if e := InstallExplicit(exe, "/var/lib/webfleet", "127.0.0.1", "7402", ""); e == nil {
		t.Fatal("failed explicit reinstall returned nil")
	}
	got, _ := os.ReadFile(UnitPath)
	if string(got) != string(priorUnit) {
		t.Fatalf("failed explicit reinstall did not restore the prior unit:\n--- got\n%s\n--- want\n%s", got, priorUnit)
	}
}

func TestStatusUsesExplicitUnitListener(t *testing.T) {
	r := setupService(t)
	r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value webfleet.service"] = fakeResult{out: "1234", code: 0}
	// Health check against the explicit unit's recorded listener.
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer h.Close()
	host, port := splitHostPort(t, strings.TrimPrefix(h.URL, "http://"))
	os.WriteFile(UnitPath, []byte(UnitExplicit("/var/lib/webfleet", host, port, "")), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"listen:  " + host + ":" + port, "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q:\n%s", want, buf.String())
		}
	}
}

func TestStatusUsesBootstrapUnitListener(t *testing.T) {
	r := setupService(t)
	r.script["systemctl is-enabled webfleet.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active webfleet.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value webfleet.service"] = fakeResult{out: "1234", code: 0}
	// Health check against the legacy unit's recorded WEBFLEET_LISTEN address.
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer h.Close()
	listen := strings.TrimPrefix(h.URL, "http://")
	os.WriteFile(UnitPath, []byte(Unit("/var/lib/webfleet", listen, "")), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"listen:  " + listen, "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q:\n%s", want, buf.String())
		}
	}
}

func splitHostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		t.Fatal(e)
	}
	return h, p
}

func TestBareReinstallLifecyclePreservesNonDefaultPort(t *testing.T) {
	r := setupService(t)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable webfleet.service"] = fakeResult{}
	r.script["systemctl start webfleet.service"] = fakeResult{}
	exe := BinaryPath
	// Fresh explicit install on a non-default port.
	if e := InstallExplicit(exe, "/var/lib/webfleet", "127.0.0.1", "7406", ""); e != nil {
		t.Fatal(e)
	}
	body, _ := os.ReadFile(UnitPath)
	meta, err := readManagedUnit(string(body))
	if err != nil {
		t.Fatalf("installed unit should validate: %v", err)
	}
	if meta.listen != "127.0.0.1:7406" || meta.listenMode != modeExplicit {
		t.Fatalf("recorded listener = %q mode=%q, want 127.0.0.1:7406 explicit", meta.listen, meta.listenMode)
	}
	if got := effectiveListen(meta); got != "127.0.0.1:7406" {
		t.Fatalf("status/health effective listener = %q, want 127.0.0.1:7406", got)
	}
	// InstalledListener reports the recorded listener a bare reinstall preserves.
	ln, explicit, exists, err := InstalledListener()
	if err != nil || !exists || !explicit || ln != "127.0.0.1:7406" {
		t.Fatalf("InstalledListener = %q explicit=%v exists=%v err=%v", ln, explicit, exists, err)
	}
	// A bare reinstall that preserves the recorded listener produces a
	// byte-identical unit (the genuine no-op path), so status and health remain
	// on the non-default port.
	setState(r, "enabled", "active")
	r.calls = nil
	if e := InstallExplicit(exe, "/var/lib/webfleet", "127.0.0.1", "7406", ""); e != nil {
		t.Fatalf("preserving reinstall: %v", e)
	}
	after, _ := os.ReadFile(UnitPath)
	if string(after) != string(body) {
		t.Fatal("preserving bare reinstall changed the unit")
	}
	meta2, _ := readManagedUnit(string(after))
	if got := effectiveListen(meta2); got != "127.0.0.1:7406" {
		t.Fatalf("post-reinstall effective listener = %q, want 127.0.0.1:7406", got)
	}
}

func TestUnitEnvFileRenderedAndParsed(t *testing.T) {
	u := UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7336", "/etc/webfleet/webfleet.env")
	if !strings.Contains(u, "EnvironmentFile="+systemdQuote("/etc/webfleet/webfleet.env")) {
		t.Fatalf("unit missing EnvironmentFile directive:\n%s", u)
	}
	if !strings.Contains(u, "# webfleet-envfile: /etc/webfleet/webfleet.env") {
		t.Fatalf("unit missing envfile metadata:\n%s", u)
	}
	meta, err := readManagedUnit(u)
	if err != nil {
		t.Fatal(err)
	}
	if meta.envfile != "/etc/webfleet/webfleet.env" {
		t.Fatalf("parsed envfile=%q, want /etc/webfleet/webfleet.env", meta.envfile)
	}
	// No envfile: no EnvironmentFile directive, unit still valid.
	plain := UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7336", "")
	if strings.Contains(plain, "EnvironmentFile=") {
		t.Fatal("unit without envfile unexpectedly has EnvironmentFile")
	}
	if _, err := readManagedUnit(plain); err != nil {
		t.Fatal(err)
	}
}

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webfleet-cv/webfleet/internal/service"
)

// withStub dispatch replaces the lifecycle seam so runService can be exercised
// end-to-end without root or systemd, recording the parsed command.
func withStub(t *testing.T, stub func(serviceCommand) (string, error)) func(serviceCommand) (string, error) {
	t.Helper()
	old := execServiceCommand
	execServiceCommand = stub
	t.Cleanup(func() { execServiceCommand = old })
	return old
}

// redirectUnitPath points the service unit path at a temp file so reinstall
// preservation can be exercised without touching /etc/systemd.
func redirectUnitPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := service.UnitPath
	service.UnitPath = filepath.Join(dir, "webfleet.service")
	t.Cleanup(func() { service.UnitPath = old })
	return service.UnitPath
}

func parsedInstall(t *testing.T, args ...string) (serviceCommand, int) {
	t.Helper()
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) { got = c; return "ok", nil })
	var out, errOut bytes.Buffer
	code := runServiceIO(&out, &errOut, args)
	return got, code
}

// unsetListenerEnv removes every listener-related variable so tests observe the
// CLI/default precedence rather than a developer's shell.
func unsetListenerEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"WEBFLEET_HOST", "WEBFLEET_PORT", "WEBFLEET_LISTEN"} {
		os.Unsetenv(k)
	}
}

func TestRunServiceInstallParsesFlags(t *testing.T) {
	unsetListenerEnv(t)
	cases := []struct {
		name       string
		args       []string
		wantData   string
		wantHost   string
		wantPort   string
		wantListen string
	}{
		{"defaults", []string{"install"}, service.DefaultDataDir, "127.0.0.1", "7336", ""},
		{"data", []string{"install", "--data", "/srv/webfleet"}, "/srv/webfleet", "127.0.0.1", "7336", ""},
		{"data-with-spaces", []string{"install", "--data", "/srv/web fleet"}, "/srv/web fleet", "127.0.0.1", "7336", ""},
		{"data-equals", []string{"install", "--data=/srv/webfleet"}, "/srv/webfleet", "127.0.0.1", "7336", ""},
		{"host-port", []string{"install", "--host", "0.0.0.0", "--port", "9000"}, service.DefaultDataDir, "0.0.0.0", "9000", ""},
		{"host-only", []string{"install", "--host", "0.0.0.0"}, service.DefaultDataDir, "0.0.0.0", "7336", ""},
		{"port-only", []string{"install", "--port", "9000"}, service.DefaultDataDir, "127.0.0.1", "9000", ""},
		{"listen", []string{"install", "--listen", "127.0.0.1:9000"}, service.DefaultDataDir, "", "", "127.0.0.1:9000"},
		{"both-data-listen", []string{"install", "--data", "/srv/webfleet", "--listen", "127.0.0.1:9000"}, "/srv/webfleet", "", "", "127.0.0.1:9000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got serviceCommand
			withStub(t, func(c serviceCommand) (string, error) {
				got = c
				return "ok", nil
			})
			var out, errOut bytes.Buffer
			if code := runServiceIO(&out, &errOut, tc.args); code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, errOut.String())
			}
			if got.verb != "install" || got.data != tc.wantData || got.host != tc.wantHost || got.port != tc.wantPort || got.listen != tc.wantListen {
				t.Fatalf("parsed = %+v, want data=%q host=%q port=%q listen=%q", got, tc.wantData, tc.wantHost, tc.wantPort, tc.wantListen)
			}
		})
	}
}

func TestRunServiceInstallUsageErrors(t *testing.T) {
	unsetListenerEnv(t)
	cases := []struct {
		name string
		args []string
	}{
		{"missing-data-value", []string{"install", "--data"}},
		{"missing-listen-value", []string{"install", "--listen"}},
		{"missing-host-value", []string{"install", "--host"}},
		{"missing-port-value", []string{"install", "--port"}},
		{"unknown-flag", []string{"install", "--bogus", "x"}},
		{"unexpected-positional", []string{"install", "/srv/webfleet"}},
		{"listen-plus-host", []string{"install", "--listen", "127.0.0.1:9000", "--host", "0.0.0.0"}},
		{"listen-plus-port", []string{"install", "--listen", "127.0.0.1:9000", "--port", "9000"}},
		{"invalid-port", []string{"install", "--port", "abc"}},
		{"zero-port", []string{"install", "--port", "0"}},
		{"negative-port", []string{"install", "--port", "-5"}},
		{"oversized-port", []string{"install", "--port", "65536"}},
		{"empty-port", []string{"install", "--port", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withStub(t, func(serviceCommand) (string, error) { return "ok", nil })
			var out, errOut bytes.Buffer
			if code := runServiceIO(&out, &errOut, tc.args); code != 2 {
				t.Fatalf("exit %d, want 2; stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if errOut.Len() == 0 {
				t.Fatal("usage error printed no diagnostic")
			}
		})
	}
}

func TestRunServiceInstallEnvOverrides(t *testing.T) {
	unsetListenerEnv(t)
	t.Setenv("WEBFLEET_HOST", "0.0.0.0")
	t.Setenv("WEBFLEET_PORT", "9000")
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) { got = c; return "ok", nil })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"install"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	if got.host != "0.0.0.0" || got.port != "9000" || got.listen != "" {
		t.Fatalf("env override parsed = %+v, want host=0.0.0.0 port=9000", got)
	}
}

func TestRunServiceInstallCLIOverridesEnv(t *testing.T) {
	unsetListenerEnv(t)
	t.Setenv("WEBFLEET_HOST", "0.0.0.0")
	t.Setenv("WEBFLEET_PORT", "9000")
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) { got = c; return "ok", nil })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"install", "--host", "127.0.0.1", "--port", "7402"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	if got.host != "127.0.0.1" || got.port != "7402" {
		t.Fatalf("cli must override env: %+v", got)
	}
}

func TestRunServiceInstallHonorsLegacyListenEnv(t *testing.T) {
	unsetListenerEnv(t)
	t.Setenv("WEBFLEET_LISTEN", "127.0.0.1:9000")
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) { got = c; return "ok", nil })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"install"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	if got.listen != "127.0.0.1:9000" || got.host != "" || got.port != "" {
		t.Fatalf("legacy env install parsed = %+v, want listen=127.0.0.1:9000", got)
	}
}

func TestRunServiceInstallHostPortOverridesLegacyEnv(t *testing.T) {
	unsetListenerEnv(t)
	t.Setenv("WEBFLEET_LISTEN", "127.0.0.1:8080")
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) { got = c; return "ok", nil })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"install", "--host", "0.0.0.0", "--port", "9000"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	if got.host != "0.0.0.0" || got.port != "9000" || got.listen != "" {
		t.Fatalf("explicit --host/--port must override WEBFLEET_LISTEN: %+v", got)
	}
}

func TestRunServiceInstallEnvConflictFails(t *testing.T) {
	unsetListenerEnv(t)
	t.Setenv("WEBFLEET_LISTEN", "127.0.0.1:8080")
	t.Setenv("WEBFLEET_HOST", "0.0.0.0")
	withStub(t, func(serviceCommand) (string, error) { return "ok", nil })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"install"}); code != 2 {
		t.Fatalf("WEBFLEET_LISTEN + WEBFLEET_HOST conflict exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "WEBFLEET_LISTEN") {
		t.Fatalf("conflict diagnostic missing: %q", errOut.String())
	}
	os.Unsetenv("WEBFLEET_HOST")
	t.Setenv("WEBFLEET_PORT", "9000")
	out.Reset()
	errOut.Reset()
	if code := runServiceIO(&out, &errOut, []string{"install"}); code != 2 {
		t.Fatalf("WEBFLEET_LISTEN + WEBFLEET_PORT conflict exit %d, want 2", code)
	}
}

func TestRunServiceInstallMalformedEnvFails(t *testing.T) {
	unsetListenerEnv(t)
	t.Setenv("WEBFLEET_HOST", "127.0.0.1")
	t.Setenv("WEBFLEET_PORT", "abc")
	withStub(t, func(serviceCommand) (string, error) { return "ok", nil })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"install"}); code != 2 {
		t.Fatalf("malformed WEBFLEET_PORT exit %d, want 2; stderr=%q", code, errOut.String())
	}
}

func TestRunServiceNonInstallIgnoresMalformedListenerEnv(t *testing.T) {
	// Malformed listener env in the invoking shell must not break any non-install
	// service verb: only install resolves/validates the listener environment.
	t.Setenv("WEBFLEET_HOST", "not a host")
	t.Setenv("WEBFLEET_PORT", "not-a-port")
	t.Setenv("WEBFLEET_LISTEN", "not-a-listener")
	for _, verb := range []string{"start", "stop", "restart", "status", "enable", "disable", "logs", "update", "rollback", "uninstall"} {
		t.Run(verb, func(t *testing.T) {
			args := []string{verb}
			if verb == "update" {
				args = []string{"update", "/tmp/art", "abc"}
			}
			var got serviceCommand
			withStub(t, func(c serviceCommand) (string, error) { got = c; return "ok", nil })
			var out, errOut bytes.Buffer
			if code := runServiceIO(&out, &errOut, args); code != 0 {
				t.Fatalf("%s exit %d, want 0; stderr=%q", verb, code, errOut.String())
			}
			if got.verb != verb {
				t.Fatalf("verb = %q, want %q", got.verb, verb)
			}
		})
	}
}

func TestRunServiceLogs(t *testing.T) {
	unsetListenerEnv(t)
	for _, follow := range []bool{false, true} {
		args := []string{"logs"}
		if follow {
			args = append(args, "--follow")
		}
		var got serviceCommand
		withStub(t, func(c serviceCommand) (string, error) {
			got = c
			return "journal", nil
		})
		var out, errOut bytes.Buffer
		if code := runServiceIO(&out, &errOut, args); code != 0 {
			t.Fatalf("exit %d, stderr: %s", code, errOut.String())
		}
		if got.verb != "logs" || got.follow != follow {
			t.Fatalf("logs parsed = %+v, want follow=%v", got, follow)
		}
		if !strings.Contains(out.String(), "journal") {
			t.Fatalf("logs output not written to stdout: %q", out.String())
		}
	}
	// logs rejects extra positionals.
	withStub(t, func(c serviceCommand) (string, error) {
		return "", nil
	})
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"logs", "--follow", "extra"}); code != 2 {
		t.Fatalf("logs with positional exit %d, want 2", code)
	}
}

func TestRunServiceUpdate(t *testing.T) {
	unsetListenerEnv(t)
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) {
		got = c
		return serviceSuccessMessage(c), nil
	})
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"update", "/tmp/art", "abc123"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	if got.verb != "update" || got.artifact != "/tmp/art" || got.sha != "abc123" {
		t.Fatalf("update parsed = %+v", got)
	}
	if !strings.Contains(out.String(), "webfleet.service updated.") {
		t.Fatalf("update success message missing: %q", out.String())
	}

	for _, bad := range [][]string{
		{"update", "/tmp/art"},
		{"update", "/tmp/art", "abc", "extra"},
		{"update", "--data", "/tmp/art", "abc"},
	} {
		withStub(t, func(serviceCommand) (string, error) { return "", nil })
		var b1, b2 bytes.Buffer
		if code := runServiceIO(&b1, &b2, bad); code != 2 {
			t.Fatalf("update %v exit %d, want 2", bad, code)
		}
	}
}

// TestServiceSuccessMessagesAreStateNeutral proves the real success-message
// semantics do not contradict the state-preserving lifecycle: install/update/
// rollback must not claim the service is active or was restarted, and uninstall
// must not hard-code a data directory that may differ from the managed one.
func TestServiceSuccessMessagesAreStateNeutral(t *testing.T) {
	verbs := []string{"install", "update", "rollback", "uninstall"}
	for _, verb := range verbs {
		msg := strings.ToLower(serviceSuccessMessage(serviceCommand{verb: verb}))
		if msg == "" {
			t.Fatalf("%s has no success message", verb)
		}
		for _, banned := range []string{"active", "restarted", "/var/lib/webfleet"} {
			if strings.Contains(msg, banned) {
				t.Fatalf("success message for %s overstates state: %q contains %q", verb, msg, banned)
			}
		}
	}
	// The verbs whose effect IS a state change may state it.
	for _, verb := range []string{"start", "stop", "restart", "enable", "disable"} {
		if serviceSuccessMessage(serviceCommand{verb: verb}) == "" {
			t.Fatalf("%s has no success message", verb)
		}
	}
}

func TestRunServiceNoArgsDefaultsToStatus(t *testing.T) {
	unsetListenerEnv(t)
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) {
		got = c
		return "status-body", nil
	})
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, nil); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	if got.verb != "status" {
		t.Fatalf("default verb = %q, want status", got.verb)
	}
}

func TestRunServiceSimpleVerbs(t *testing.T) {
	unsetListenerEnv(t)
	for _, verb := range []string{"start", "stop", "restart", "enable", "disable", "rollback", "uninstall"} {
		var got serviceCommand
		withStub(t, func(c serviceCommand) (string, error) {
			got = c
			return "ok", nil
		})
		var out, errOut bytes.Buffer
		if code := runServiceIO(&out, &errOut, []string{verb}); code != 0 {
			t.Fatalf("%s exit %d, stderr: %s", verb, code, errOut.String())
		}
		if got.verb != verb {
			t.Fatalf("verb = %q, want %q", got.verb, verb)
		}
		// Positionals and flags are refused.
		withStub(t, func(serviceCommand) (string, error) { return "", nil })
		var b1, b2 bytes.Buffer
		if code := runServiceIO(&b1, &b2, []string{verb, "extra"}); code != 2 {
			t.Fatalf("%s with positional exit %d, want 2", verb, code)
		}
	}
}

func TestRunServiceOperationalFailure(t *testing.T) {
	unsetListenerEnv(t)
	withStub(t, func(serviceCommand) (string, error) { return "", errors.New("boom") })
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"start"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "boom") {
		t.Fatalf("operational failure not surfaced: %q", errOut.String())
	}
}

func TestRunServiceUnknownCommand(t *testing.T) {
	unsetListenerEnv(t)
	var out, errOut bytes.Buffer
	if code := runServiceIO(&out, &errOut, []string{"frobnicate"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "frobnicate") {
		t.Fatalf("unknown command diagnostic missing: %q", errOut.String())
	}
}

func TestParseServiceInstallAcceptsDataDirAlias(t *testing.T) {
	cmd, err := parseServiceCommand([]string{"install", "--data-dir", "/srv/webfleet", "--listen", "127.0.0.1:7336"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.data != "/srv/webfleet" {
		t.Fatalf("data = %q, want /srv/webfleet", cmd.data)
	}
	if _, err := parseServiceCommand([]string{"install", "--data", "/one", "--data-dir", "/two", "--listen", "127.0.0.1:7336"}); err == nil {
		t.Fatal("combining --data and --data-dir should fail")
	}
}

func TestRunServiceOutputWriters(t *testing.T) {
	unsetListenerEnv(t)
	// runService (the os.Stdout/os.Stderr wrapper) still compiles and routes to
	// the injected writers through runServiceIO; verify the wiring here.
	var got serviceCommand
	withStub(t, func(c serviceCommand) (string, error) {
		got = c
		return "success-line", nil
	})
	var out, errOut bytes.Buffer
	code := runServiceIO(&out, &errOut, []string{"install", "--listen", "127.0.0.1:9001"})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got.listen != "127.0.0.1:9001" {
		t.Fatalf("listen = %q", got.listen)
	}
	if !strings.Contains(out.String(), "success-line") {
		t.Fatalf("stdout missing success message: %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}
	_ = io.Discard
}

func TestRunServiceBareReinstallPreservesExplicitListener(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	// Existing explicit unit on a custom port.
	if err := os.WriteFile(path, []byte(service.UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7406", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, code := parsedInstall(t, "install")
	if code != 0 {
		t.Fatalf("bare reinstall exit %d", code)
	}
	if got.host != "127.0.0.1" || got.port != "7406" || got.listen != "" {
		t.Fatalf("bare reinstall over explicit unit must preserve host/port, got %+v", got)
	}
}

func TestRunServiceBareReinstallPreservesBootstrapListener(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	if err := os.WriteFile(path, []byte(service.Unit("/var/lib/webfleet", "127.0.0.1:8090", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, code := parsedInstall(t, "install")
	if code != 0 {
		t.Fatalf("bare reinstall exit %d", code)
	}
	if got.listen != "127.0.0.1:8090" || got.host != "" || got.port != "" {
		t.Fatalf("bare reinstall over bootstrap unit must preserve the single listener, got %+v", got)
	}
}

func TestRunServiceBareFreshInstallIsExplicitDefault(t *testing.T) {
	unsetListenerEnv(t)
	redirectUnitPath(t) // no unit file written -> fresh install
	got, code := parsedInstall(t, "install")
	if code != 0 {
		t.Fatalf("bare install exit %d", code)
	}
	if got.host != "127.0.0.1" || got.port != "7336" || got.listen != "" {
		t.Fatalf("fresh bare install must be explicit 127.0.0.1:7336, got %+v", got)
	}
}

func TestRunServiceExplicitOverrideChangesExistingListener(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	if err := os.WriteFile(path, []byte(service.UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7406", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	// Explicit --port must be authoritative over the existing explicit unit.
	got, code := parsedInstall(t, "install", "--port", "9000")
	if code != 0 {
		t.Fatalf("override reinstall exit %d", code)
	}
	if got.host != "127.0.0.1" || got.port != "9000" || got.listen != "" {
		t.Fatalf("--port override must win over existing listener, got %+v", got)
	}
}

func TestRunServiceExplicitOverrideChangesBootstrapListener(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	if err := os.WriteFile(path, []byte(service.Unit("/var/lib/webfleet", "127.0.0.1:8090", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, code := parsedInstall(t, "install", "--host", "0.0.0.0", "--port", "9000")
	if code != 0 {
		t.Fatalf("override reinstall exit %d", code)
	}
	if got.host != "0.0.0.0" || got.port != "9000" || got.listen != "" {
		t.Fatalf("--host/--port override must win over existing bootstrap listener, got %+v", got)
	}
}

func TestRunServiceLegacyListenChangesExistingToBootstrap(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	if err := os.WriteFile(path, []byte(service.UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7406", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	// Explicit legacy --listen must be authoritative and switch to bootstrap.
	got, code := parsedInstall(t, "install", "--listen", "127.0.0.1:8090")
	if code != 0 {
		t.Fatalf("legacy override reinstall exit %d", code)
	}
	if got.listen != "127.0.0.1:8090" || got.host != "" || got.port != "" {
		t.Fatalf("--listen override must win and be bootstrap, got %+v", got)
	}
}

func TestRunServiceBareReinstallMalformedUnitFailsClosed(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	// A foreign/unmanaged unit must fail closed on bare reinstall rather than
	// silently defaulting to 7336.
	if err := os.WriteFile(path, []byte("[Unit]\nDescription=something else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, code := parsedInstall(t, "install")
	if code == 0 {
		t.Fatal("bare reinstall over a foreign unit must fail closed")
	}
}

func TestRunServiceBareReinstallModifiedUnitFailsClosed(t *testing.T) {
	unsetListenerEnv(t)
	path := redirectUnitPath(t)
	unit := service.UnitExplicit("/var/lib/webfleet", "127.0.0.1", "7406", "")
	if err := os.WriteFile(path, []byte(strings.Replace(unit, "Restart=on-failure", "Restart=always", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, code := parsedInstall(t, "install")
	if code == 0 {
		t.Fatal("bare reinstall over a modified unit must fail closed")
	}
}

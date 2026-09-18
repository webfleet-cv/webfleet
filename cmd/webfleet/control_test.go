package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/webfleet-cv/webfleet/internal/auth"
	"github.com/webfleet-cv/webfleet/internal/service"
	"github.com/webfleet-cv/webfleet/internal/store"
)

// useInstalledResetDir points the managed unit at dir so runReset resolves the
// installed service's data directory instead of a CLI override or the default.
func useInstalledResetDir(t *testing.T, dir string) {
	t.Helper()
	oldUnit := service.UnitPath
	unit := filepath.Join(t.TempDir(), "webfleet.service")
	if err := os.WriteFile(unit, []byte(service.Unit(dir, "127.0.0.1:7336")), 0600); err != nil {
		t.Fatal(err)
	}
	service.UnitPath = unit
	t.Cleanup(func() { service.UnitPath = oldUnit })
	t.Setenv("WEBFLEET_DATA_DIR", "")
}

func TestRunResetAuthUsesInstalledServiceData(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.New(db).CreateAdmin("admin", "admin@example.com", "correct horse battery"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	useInstalledResetDir(t, dir)

	if code := runReset([]string{"--auth", "--confirm", "WEBFLEET AUTH"}); code != 0 {
		t.Fatalf("reset --auth exit = %d, want 0", code)
	}

	db, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var users int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("users after auth reset = %d, want 0", users)
	}
	backups, err := filepath.Glob(filepath.Join(dir, "reset-auth-*.db"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("auth backups = %v, err = %v; want one", backups, err)
	}
}

func TestRunSetupUsesInstalledServiceData(t *testing.T) {
	dir := t.TempDir()
	useInstalledResetDir(t, dir)
	pwFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(pwFile, []byte("correct horse battery"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := runSetup([]string{"--username", "admin", "--email", "admin@example.com", "--password-file", pwFile}); code != 0 {
		t.Fatalf("setup exit = %d, want 0", code)
	}
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var users int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Fatalf("installed data dir users = %d, want 1", users)
	}
}

func TestRunResetAllUsesInstalledServiceData(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	useInstalledResetDir(t, dir)

	if code := runReset([]string{"--all", "--confirm", "WEBFLEET ALL"}); code != 0 {
		t.Fatalf("reset --all exit = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "marker")); !os.IsNotExist(err) {
		t.Fatalf("recreated data directory retained old marker: %v", err)
	}
	backups, err := filepath.Glob(dir + ".reset-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("full backups = %v, err = %v; want one", backups, err)
	}
	if got, err := os.ReadFile(filepath.Join(backups[0], "marker")); err != nil || string(got) != "state" {
		t.Fatalf("backup marker = %q, err = %v", got, err)
	}
}

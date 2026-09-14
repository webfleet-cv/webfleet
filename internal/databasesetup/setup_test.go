package databasesetup

import (
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/store"
	"testing"
)

func TestPersistedPostgresReturnsToAdminCreation(t *testing.T) {
	dir := t.TempDir()
	st, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if e = config.SaveDatabaseChoice(dir, config.DatabaseChoice{Provider: "postgres", URL: "postgres://configured"}); e != nil {
		t.Fatal(e)
	}
	x, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if x.Selectable || x.Provider != "postgres" {
		t.Fatalf("%+v", x)
	}
}

func TestPostgresRestartStateSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	st, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if e = config.SaveDatabaseChoice(dir, config.DatabaseChoice{Provider: "postgres", URL: "postgres://configured"}); e != nil {
		t.Fatal(e)
	}
	// Before restart the process still runs SQLite, so the admin form must not
	// appear and the restart-required state must be reported.
	before, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if !before.RestartRequired || before.Selectable {
		t.Fatalf("pre-restart state = %+v, want restart_required and not selectable", before)
	}
	// After restart the process runs PostgreSQL: the admin form may appear but
	// the provider remains locked.
	st.DB.Dialect = "postgres"
	after, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if after.RestartRequired || after.Selectable || after.Provider != "postgres" {
		t.Fatalf("post-restart state = %+v, want admin creation on locked postgres", after)
	}
}

func TestSQLiteDefaultIsSelectableAndEnvironmentPostgresIsNot(t *testing.T) {
	dir := t.TempDir()
	st, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	// No choice file: SQLite default, running SQLite, chooser available.
	def, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if !def.Selectable || def.Provider != "sqlite" || def.RestartRequired {
		t.Fatalf("sqlite default state = %+v", def)
	}
	// Provisioned via environment: the process runs PostgreSQL even though no
	// choice file exists, so the browser chooser must not offer SQLite.
	st.DB.Dialect = "postgres"
	env, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if env.Selectable || env.RestartRequired {
		t.Fatalf("env-postgres state = %+v, want locked and no restart notice", env)
	}
}

// TestPendingPostgresChoiceHidesAdminEvenWhenAdminExists guards the first-run
// contract that a database transition pending a restart must be reported even
// when an administrator already exists in the currently running database, so
// the UI never offers login/administrator actions against the old database.
func TestPendingPostgresChoiceHidesAdminEvenWhenAdminExists(t *testing.T) {
	dir := t.TempDir()
	st, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if _, e := st.DB.Exec(`INSERT INTO users(username,email,password_hash,role,created_at) VALUES('admin','admin@example.com','x','admin','2026-01-01T00:00:00Z')`); e != nil {
		t.Fatal(e)
	}
	if e = config.SaveDatabaseChoice(dir, config.DatabaseChoice{Provider: "postgres", URL: "postgres://configured"}); e != nil {
		t.Fatal(e)
	}
	// Running SQLite with an admin present AND a pending PostgreSQL choice:
	// restart-required must be reported, and the database must not be selectable.
	x, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if !x.RestartRequired {
		t.Fatalf("pending postgres choice with existing admin = %+v, want restart_required", x)
	}
	if x.Selectable {
		t.Fatalf("pending postgres choice with existing admin = %+v, want not selectable", x)
	}
	// After restarting onto PostgreSQL the same admin-free transition rule
	// clears: running on the chosen provider, no restart notice.
	st.DB.Dialect = "postgres"
	y, e := StateFor(st, dir)
	if e != nil {
		t.Fatal(e)
	}
	if y.RestartRequired || y.Selectable {
		t.Fatalf("post-restart state = %+v, want no restart notice", y)
	}
}

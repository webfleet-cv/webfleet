package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/webfleet-cv/webfleet/internal/sqlite"
)

func TestFreshOpenRestartAndPragmas(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := OpenContext(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	var version, foreignKeys, busyTimeout int
	var journalMode string
	if err := s.DB.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion || foreignKeys != 1 || busyTimeout != 5000 || strings.ToLower(journalMode) != "wal" {
		t.Fatalf("version=%d foreign_keys=%d busy_timeout=%d journal_mode=%q", version, foreignKeys, busyTimeout, journalMode)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO app_events(kind,message,created_at) VALUES('restart-probe','persisted',?)`, Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = OpenContext(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM app_events WHERE kind='restart-probe'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("restart probe count=%d", count)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM _webfleet_schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != schemaVersion {
		t.Fatalf("migration history rows=%d want=%d", count, schemaVersion)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 0700 is a Unix ownership mode; Windows has no Unix permission bits.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("data directory permissions=%o want=700", info.Mode().Perm())
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	d := t.TempDir()
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SchemaVersion()
	if err != nil || v != schemaVersion {
		t.Fatalf("version=%d err=%v", v, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err = s.SchemaVersion()
	if err != nil || v != schemaVersion {
		t.Fatalf("second version=%d err=%v", v, err)
	}
}

func TestRefusesFutureSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webfleet.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 999`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir)
	if err == nil || !strings.Contains(err.Error(), "999") {
		t.Fatalf("unexpected future-schema error: %v", err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	ctx := context.Background()
	s, err := OpenContext(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	broken := migration{version: schemaVersion + 1, name: "broken migration", stmts: []string{
		`CREATE TABLE should_not_exist(id INTEGER);`,
		`THIS IS NOT SQL`,
	}}
	if err := s.apply(ctx, broken); err == nil {
		t.Fatal("broken migration succeeded")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='should_not_exist'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed migration left table behind: count=%d", count)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM _webfleet_schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != schemaVersion {
		t.Fatalf("failed migration changed history: count=%d", count)
	}
}

func TestMigrationHistoryMismatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE _webfleet_schema_migrations SET name='tampered' WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir)
	if err == nil || !strings.Contains(err.Error(), "unexpected name") {
		t.Fatalf("tampered migration history accepted: %v", err)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = st.DB.Exec(`INSERT INTO app_events(kind,message,created_at) VALUES('probe','yes',?)`, Now()); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if e = st.Backup(backup); e != nil {
		t.Fatal(e)
	}
	st.Close()
	if e = Restore(dir, backup); e != nil {
		t.Fatal(e)
	}
	st, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	var n int
	if e = st.DB.QueryRow(`SELECT count(*) FROM app_events WHERE kind='probe'`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("probe=%d err=%v", n, e)
	}
}

func TestPostgresMigrationSQL(t *testing.T) {
	q := postgresSQL(`CREATE TABLE x(id INTEGER PRIMARY KEY, token BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`)
	for _, want := range []string{"SERIAL PRIMARY KEY", "BYTEA", "CURRENT_TIMESTAMP::text"} {
		if !strings.Contains(q, want) {
			t.Fatalf("missing %s in %s", want, q)
		}
	}
}

func TestClaimDueExcludesOtherOwnersUntilExpiry(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, ok, e := st.ClaimDue(ctx, "check", 1, "worker-a", now, now.Add(time.Minute)); e != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, e)
	}
	// A second worker cannot claim the same unit while the lease is unexpired.
	if _, ok, e := st.ClaimDue(ctx, "check", 1, "worker-b", now, now.Add(time.Minute)); e != nil || ok {
		t.Fatalf("second worker claimed: ok=%v err=%v", ok, e)
	}
	// A different unit is independent.
	if _, ok, e := st.ClaimDue(ctx, "check", 2, "worker-b", now, now.Add(time.Minute)); e != nil || !ok {
		t.Fatalf("independent unit: ok=%v err=%v", ok, e)
	}
	// A unit is not claimable again before its next_due_at.
	if _, ok, _ := st.ClaimDue(ctx, "check", 2, "worker-a", now, now.Add(time.Minute)); ok {
		t.Fatal("unit claimed again before due")
	}
}

func TestClaimExpiryAllowsRecovery(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	gen, ok, _ := st.ClaimDue(ctx, "check", 1, "worker-a", now, now.Add(30*time.Millisecond))
	if !ok {
		t.Fatal("initial claim failed")
	}
	time.Sleep(60 * time.Millisecond)
	// A crashed worker's lease expires; another worker can claim (generation bumps).
	gen2, ok, e := st.ClaimDue(ctx, "check", 1, "worker-b", now.Add(100*time.Millisecond), now.Add(time.Minute))
	if e != nil || !ok {
		t.Fatalf("takeover after expiry: ok=%v err=%v", ok, e)
	}
	if gen2 <= gen {
		t.Fatalf("fencing generation did not advance: %d -> %d", gen, gen2)
	}
	// The stale owner's completion is a no-op and cannot corrupt next_due_at.
	if e := st.CompleteClaim(ctx, "check", 1, "worker-a", gen, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	rows, e := sqlite.Query(st.DB, `SELECT owner,generation FROM scheduler_claims WHERE claim_kind='check' AND site_id=1`)
	if e != nil || len(rows) != 1 || rows[0]["owner"].Text != "worker-b" {
		t.Fatalf("stale owner corrupted the claim: %v %v", rows, e)
	}
}

func TestClaimCompletionAdvancesNextDue(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	gen, ok, _ := st.ClaimDue(ctx, "check", 1, "worker-a", now, now.Add(time.Minute))
	if !ok {
		t.Fatal("claim failed")
	}
	nextDue := now.Add(30 * time.Second)
	if e := st.CompleteClaim(ctx, "check", 1, "worker-a", gen, nextDue); e != nil {
		t.Fatal(e)
	}
	rows, e := sqlite.Query(st.DB, `SELECT next_due_at,owner FROM scheduler_claims WHERE claim_kind='check' AND site_id=1`)
	if e != nil || len(rows) != 1 || rows[0]["owner"].Text != "" {
		t.Fatalf("completion did not release claim: %v %v", rows, e)
	}
	// Not due until next_due_at passes.
	if _, ok, _ := st.ClaimDue(ctx, "check", 1, "worker-b", now.Add(10*time.Second), now.Add(time.Minute)); ok {
		t.Fatal("claimed before next_due_at")
	}
	if _, ok, _ := st.ClaimDue(ctx, "check", 1, "worker-b", nextDue.Add(time.Second), nextDue.Add(time.Minute)); !ok {
		t.Fatal("not claimable at next_due_at")
	}
}

func TestPostgresSQLTranslation(t *testing.T) {
	cases := map[string]string{
		"ALTER TABLE cluster_members ADD COLUMN pending_inbound_secret_hash BLOB":                                         "ALTER TABLE cluster_members ADD COLUMN pending_inbound_secret_hash BYTEA",
		"UPDATE users SET username = CASE WHEN instr(email,'@')>0 THEN substr(email,1,instr(email,'@')-1) ELSE email END": "UPDATE users SET username = CASE WHEN position('@' in email)>0 THEN substr(email,1,position('@' in email)-1) ELSE email END",
		"CREATE TABLE x (id INTEGER PRIMARY KEY, data BLOB)":                                                              "CREATE TABLE x (id SERIAL PRIMARY KEY, data BYTEA)",
	}
	for in, want := range cases {
		if got := postgresSQL(in); got != want {
			t.Errorf("postgresSQL(%q) = %q, want %q", in, got, want)
		}
	}
}

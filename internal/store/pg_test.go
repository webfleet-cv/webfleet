package store_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webfleet-cv/webfleet/internal/analytics"
	"github.com/webfleet-cv/webfleet/internal/apitokens"
	"github.com/webfleet-cv/webfleet/internal/audit"
	"github.com/webfleet-cv/webfleet/internal/auth"
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/crawler"
	"github.com/webfleet-cv/webfleet/internal/databasesetup"
	"github.com/webfleet-cv/webfleet/internal/deployments"
	"github.com/webfleet-cv/webfleet/internal/dnsobs"
	"github.com/webfleet-cv/webfleet/internal/incidents"
	"github.com/webfleet-cv/webfleet/internal/maintenance"
	"github.com/webfleet-cv/webfleet/internal/monitor"
	"github.com/webfleet-cv/webfleet/internal/netguard"
	"github.com/webfleet-cv/webfleet/internal/notifications"
	"github.com/webfleet-cv/webfleet/internal/sites"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
	"github.com/webfleet-cv/webfleet/internal/tlshealth"
)

// openFreshPG creates a unique database on a real PostgreSQL server (configured
// via WEBFLEET_TEST_POSTGRES_URL), opens it with the application store (running
// all migrations), and returns the store plus its DSN. The database is dropped
// on cleanup.
func openFreshPG(t *testing.T) (*store.Store, string) {
	t.Helper()
	base := os.Getenv("WEBFLEET_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("WEBFLEET_TEST_POSTGRES_URL not set; real PostgreSQL parity not run")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("wf_test_%d", time.Now().UnixNano())
	admin, err := store.OpenPostgres(context.Background(), base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	if _, err := admin.DB.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	admin.Close()
	u.Path = "/" + name
	dsn := u.String()
	st, err := store.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open fresh postgres: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		admin, err := store.OpenPostgres(context.Background(), base)
		if err != nil {
			t.Logf("cleanup admin connect: %v", err)
			return
		}
		defer admin.Close()
		_, _ = admin.DB.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return st, dsn
}

func TestPostgresFreshMigrationAndRestartIdempotent(t *testing.T) {
	st, _ := openFreshPG(t)
	v, err := st.SchemaVersion()
	if err != nil || v < 1 {
		t.Fatalf("fresh postgres schema version = %d err=%v", v, err)
	}
	rows, err := sqlite.Query(st.DB, `SELECT COUNT(*) n FROM _webfleet_schema_migrations`)
	if err != nil || rows[0]["n"].Int64 != int64(v) {
		t.Fatalf("migration history rows = %v err=%v (want %d)", rows, err, v)
	}
}

func TestPostgresRestartIsIdempotent(t *testing.T) {
	st, dsn := openFreshPG(t)
	st.Close()
	st2, err := store.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("reopen migrated postgres: %v", err)
	}
	defer st2.Close()
	v, err := st2.SchemaVersion()
	if err != nil || v < 1 {
		t.Fatalf("post-restart schema version = %d err=%v", v, err)
	}
}

func TestPostgresRefusesFutureSchema(t *testing.T) {
	st, dsn := openFreshPG(t)
	if _, err := st.DB.ExecContext(context.Background(), `INSERT INTO _webfleet_schema_migrations(version,name,applied_at) VALUES(?,?,?)`, 999, "future", store.Now()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := store.OpenPostgres(context.Background(), dsn); err == nil {
		t.Fatal("future schema accepted on postgres")
	}
}

// TestPostgresCoreParity exercises the normal product storage paths against a
// real PostgreSQL server and asserts the same observable results the SQLite
// suite relies on.
func TestPostgresCoreParity(t *testing.T) {
	st, _ := openFreshPG(t)
	ctx := context.Background()

	authSvc := auth.New(st)
	if err := authSvc.CreateAdmin("admin", "admin@example.com", "secret7"); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := authSvc.Login("admin@example.com", "secret7")
	if err != nil || tok == "" || sess.CSRF == "" {
		t.Fatalf("login: %v", err)
	}
	if _, err := authSvc.Session(tok); err != nil {
		t.Fatalf("session: %v", err)
	}
	org, err := st.PrimaryOrgID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mem, err := sqlite.Query(st.DB, `SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?`, org, sess.UserID)
	if err != nil || len(mem) != 1 || mem[0]["role"].Text != "owner" {
		t.Fatalf("owner membership: %v %v", mem, err)
	}

	sitesSvc := sites.New(st)
	group, err := sitesSvc.CreateGroup(org, "Clients")
	if err != nil {
		t.Fatal(err)
	}
	site, err := sitesSvc.Create(org, "Example", "https://127.0.0.1:1/", group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := sitesSvc.SetTags(org, site.ID, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	tags, err := sitesSvc.Tags(org, site.ID)
	if err != nil || len(tags) != 1 || tags[0] != "prod" {
		t.Fatalf("tags: %v %v", tags, err)
	}

	webSvc := notifications.New(st)
	if _, _, err := webSvc.Create(org, "hook", "https://8.8.8.8/hook"); err != nil {
		t.Fatal(err)
	}

	inc := incidents.New(st)
	if err := inc.Transition(site.ID, "unknown", "down", store.Now()); err != nil {
		t.Fatal(err)
	}
	if err := inc.Transition(site.ID, "down", "healthy", store.Now()); err != nil {
		t.Fatal(err)
	}
	il, err := inc.List(site.ID)
	if err != nil || len(il) != 1 || il[0].State != "resolved" {
		t.Fatalf("incidents: %v %v", il, err)
	}
	rows, err := sqlite.Query(st.DB, `SELECT event_kind,status FROM notification_deliveries`)
	if err != nil || len(rows) < 1 {
		t.Fatalf("webhook outbox: %v %v", rows, err)
	}

	auditSvc := audit.NewWithRunner(st, fakeAuditRunner{})
	if _, err := auditSvc.Run(ctx, site.ID); err != nil {
		t.Fatal(err)
	}
	if on, _ := auditSvc.HistoryEnabled(site.ID); on {
		t.Fatal("audit history must default off")
	}

	an := analytics.New(st)
	prop, err := an.Enable(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := an.Ingest(analytics.Event{Key: prop.PublicKey, Kind: "pageview", Path: "/"}, "https://127.0.0.1:1", "198.51.100.4", "Mozilla/5.0"); err != nil {
		t.Fatal(err)
	}
	sum, err := an.Summary(site.ID, 7)
	if err != nil || sum.Pageviews != 1 {
		t.Fatalf("analytics summary: %+v %v", sum, err)
	}

	dep := deployments.New(st)
	if _, err := dep.Record(deployments.Event{SiteID: site.ID, Provider: "github", ExternalID: "x1", Revision: "abc"}); err != nil {
		t.Fatal(err)
	}

	tokSvc := apitokens.New(st)
	created, err := tokSvc.Create(sess.UserID, org, "ci", []string{"sites:read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, scopes, err := tokSvc.Authenticate(created.Token); err != nil || !apitokens.HasScope(scopes, "sites:read") {
		t.Fatalf("token authenticate: %v", err)
	}
	if err := tokSvc.Revoke(created.ID, sess.UserID, org); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tokSvc.Authenticate(created.Token); err == nil {
		t.Fatal("revoked token authenticated on postgres")
	}

	maint := maintenance.New(st)
	if err := maint.Set(maintenance.Settings{CheckDays: 30, AnalyticsRawDays: 14, AuditDays: 90}); err != nil {
		t.Fatal(err)
	}
	if err := maint.Run(); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := st.ClaimDue(ctx, "check", site.ID, "worker-a", time.Now().UTC(), time.Now().UTC().Add(time.Minute)); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := st.ClaimDue(ctx, "check", site.ID, "worker-b", time.Now().UTC(), time.Now().UTC().Add(time.Minute)); ok {
		t.Fatal("second worker claimed the same postgres due slot")
	}
}

type fakeAuditRunner struct{}

func (fakeAuditRunner) Run(ctx context.Context, u string) (audit.Result, error) {
	return audit.Result{Status: "complete", Performance: 90, Accessibility: 90, BestPractices: 90, Discoverability: 90}, nil
}

func TestPostgresBackupRestoreRehearsal(t *testing.T) {
	st, dsn := openFreshPG(t)
	ctx := context.Background()
	authSvc := auth.New(st)
	if err := authSvc.CreateAdmin("admin", "admin@example.com", "secret7"); err != nil {
		t.Fatal(err)
	}
	site, err := sites.New(st).Create(1, "Example", "https://127.0.0.1:1/", 0)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "webfleet.pgdump")
	if err := store.PostgresBackup(ctx, dsn, backup); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if fi, err := os.Stat(backup); err != nil || fi.Size() == 0 {
		t.Fatalf("backup file: %v", err)
	}
	// Destructive change: wipe the schema, then restore.
	st.Close()
	st2, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.DB.ExecContext(ctx, `DROP TABLE sites CASCADE`); err != nil {
		st2.Close()
		t.Fatal(err)
	}
	st2.Close()
	if err := store.PostgresRestore(ctx, dsn, backup); err != nil {
		t.Fatalf("restore: %v", err)
	}
	st3, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	rows, err := sqlite.Query(st3.DB, `SELECT COUNT(*) n FROM sites WHERE id=?`, site.ID)
	if err != nil || rows[0]["n"].Int64 != 1 {
		t.Fatalf("restored site missing: %v %v", rows, err)
	}
}

func TestPostgresBackupRestoreBadInputFailsSafely(t *testing.T) {
	_, dsn := openFreshPG(t)
	ctx := context.Background()
	// A bogus source is not a pg_dump archive: restore must fail cleanly.
	if err := store.PostgresRestore(ctx, dsn, "/nonexistent/file"); err == nil {
		t.Fatal("restore from nonexistent file succeeded")
	}
	// A non-archive file must fail cleanly too.
	bad := filepath.Join(t.TempDir(), "not-an-archive")
	if err := os.WriteFile(bad, []byte("this is not a postgres archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.PostgresRestore(ctx, dsn, bad); err == nil {
		t.Fatal("restore from a non-archive succeeded")
	}
	// Backup to an unwritable path fails cleanly.
	if err := store.PostgresBackup(ctx, dsn, "/proc/nope/webfleet.pgdump"); err == nil {
		t.Fatal("backup to unwritable path succeeded")
	}
}

func TestProviderDetection(t *testing.T) {
	if store.Provider("") != "sqlite" {
		t.Fatal("empty url must be sqlite")
	}
	if store.Provider("postgres://u@h/db") != "postgres" {
		t.Fatal("postgres url must be postgres")
	}
}

// TestPostgresParityExtended covers the remaining explicitly-requested storage
// paths against real PostgreSQL: monitoring check results, incident
// acknowledgement, TLS/DNS/crawler observation persistence, audit history
// behavior and scheduler due/claim state.
func TestPostgresParityExtended(t *testing.T) {
	st, _ := openFreshPG(t)
	ctx := context.Background()
	if err := auth.New(st).CreateAdmin("admin", "admin@example.com", "secret7"); err != nil {
		t.Fatal(err)
	}
	org, err := st.PrimaryOrgID(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Monitoring check-result persistence through the real service path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "http://")
	host := strings.Split(hostport, ":")[0]
	mSite, err := sites.New(st).Create(org, "mon", "http://"+hostport+"/", 0)
	if err != nil {
		t.Fatal(err)
	}
	g := netguard.New()
	g.Resolver = mapResolver{host: {netip.MustParseAddr("127.0.0.1")}}
	g.AllowPrivate = true
	mon := monitor.NewForTests(st, g.Resolver, true)
	res, err := mon.CheckSite(ctx, mSite.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.StatusCode != 204 {
		t.Fatalf("check result: %+v", res)
	}
	hist, err := mon.Recent(mSite.ID, 5)
	if err != nil || len(hist) != 1 {
		t.Fatalf("check history on postgres: %v %v", hist, err)
	}

	// Incident acknowledgement.
	inc := incidents.New(st)
	if err := inc.Transition(mSite.ID, "unknown", "down", store.Now()); err != nil {
		t.Fatal(err)
	}
	il, _ := inc.List(mSite.ID)
	if len(il) != 1 {
		t.Fatalf("incidents: %v", il)
	}
	if err := inc.Acknowledge(org, il[0].ID, store.Now()); err != nil {
		t.Fatal(err)
	}
	il2, _ := inc.List(mSite.ID)
	if il2[0].AcknowledgedAt == "" {
		t.Fatal("acknowledgement not persisted on postgres")
	}

	// TLS observation persistence.
	if err := sqlite.Exec(st.DB, `INSERT INTO tls_observations(site_id,valid,hostname_valid,issuer,subject,serial,not_before,not_after,days_remaining,error_class,error,checked_at) VALUES(?,1,1,'iss','sub','ser','2026-01-01T00:00:00Z','2027-01-01T00:00:00Z',120,'','',?)`, mSite.ID, store.Now()); err != nil {
		t.Fatal(err)
	}
	tlsSvc := tlshealth.New(st)
	if obs, err := tlsSvc.Latest(mSite.ID); err != nil || !obs.Valid {
		t.Fatalf("tls observation on postgres: %+v %v", obs, err)
	}

	// DNS observation persistence.
	if err := sqlite.Exec(st.DB, `INSERT INTO dns_observations(site_id,a_records,aaaa_records,cname,status,changed,error,checked_at) VALUES(?,'1.1.1.1','','','ok',0,'',?)`, mSite.ID, store.Now()); err != nil {
		t.Fatal(err)
	}
	dnsSvc := dnsobs.New(st)
	if rows, err := dnsSvc.History(mSite.ID); err != nil || len(rows) != 1 {
		t.Fatalf("dns observation on postgres: %v %v", rows, err)
	}

	// Crawler persistence.
	r, err := sqlite.Query(st.DB, `INSERT INTO crawl_runs(site_id,status,started_at) VALUES(?,'complete',?) RETURNING id`, mSite.ID, store.Now())
	if err != nil {
		t.Fatal(err)
	}
	runID := r[0]["id"].Int64
	if err := sqlite.Exec(st.DB, `INSERT INTO crawl_pages(run_id,site_id,url,status_code,depth) VALUES(?,?,'https://example.com/',200,0)`, runID, mSite.ID); err != nil {
		t.Fatal(err)
	}
	crawlSvc := crawler.New(st)
	if d, err := crawlSvc.Detail(runID); err != nil || len(d.Pages) != 1 {
		t.Fatalf("crawl persistence on postgres: %+v %v", d, err)
	}

	// Audit history opt-in accumulates runs on postgres.
	auditSvc := audit.NewWithRunner(st, fakeAuditRunner{})
	if err := auditSvc.SetHistory(mSite.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := auditSvc.Run(ctx, mSite.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := auditSvc.Run(ctx, mSite.ID); err != nil {
		t.Fatal(err)
	}
	ah, _ := auditSvc.History(mSite.ID)
	if len(ah) != 2 {
		t.Fatalf("audit history on postgres: %d runs", len(ah))
	}

	// Scheduler due/claim state persists and fences on postgres.
	now := time.Now().UTC()
	gen, ok, err := st.ClaimDue(ctx, "check", mSite.ID, "worker-a", now, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := st.ClaimDue(ctx, "check", mSite.ID, "worker-b", now, now.Add(time.Minute)); ok {
		t.Fatal("second worker claimed the same postgres due slot")
	}
	if ok, _ := st.RenewClaim(ctx, "check", mSite.ID, "worker-a", gen, now.Add(2*time.Minute)); !ok {
		t.Fatal("postgres renewal failed")
	}
	if err := st.CompleteClaim(ctx, "check", mSite.ID, "worker-a", gen, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

// TestPostgresFirstRunLifecycle proves the real first-run database-selection
// lifecycle against a real PostgreSQL server: SQLite default, choose PG,
// restart-required, reopen on PG, admin creation, stable restart.
func TestPostgresFirstRunLifecycle(t *testing.T) {
	dir := t.TempDir()
	base := os.Getenv("WEBFLEET_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("WEBFLEET_TEST_POSTGRES_URL not set")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("wf_fr_%d", time.Now().UnixNano())
	admin, err := store.OpenPostgres(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.DB.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()
	u.Path = "/" + name
	pgDSN := u.String()
	t.Cleanup(func() {
		admin, err := store.OpenPostgres(context.Background(), base)
		if err != nil {
			return
		}
		defer admin.Close()
		_, _ = admin.DB.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})

	// 1. Initial SQLite/default state: chooser selectable.
	sqliteSt, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := databasesetup.StateFor(sqliteSt, dir)
	if err != nil || !pre.Selectable || pre.Provider != "sqlite" {
		t.Fatalf("sqlite default state: %+v %v", pre, err)
	}
	// 2/3. Choose the real PostgreSQL URL; connection+schema validation succeeds.
	applied, err := databasesetup.Apply(context.Background(), sqliteSt, dir, "postgres", pgDSN)
	if err != nil {
		t.Fatalf("apply postgres: %v", err)
	}
	// 4. Persisted state reports restart required, provider locked.
	if !applied.RestartRequired || applied.Selectable || applied.Provider != "postgres" {
		t.Fatalf("applied state: %+v", applied)
	}
	post, _ := databasesetup.StateFor(sqliteSt, dir)
	if !post.RestartRequired || post.Selectable {
		t.Fatalf("persisted pre-restart state: %+v", post)
	}
	sqliteSt.Close()
	// 5. Reopen the application store on the real PostgreSQL database.
	pgSt, err := store.OpenPostgres(context.Background(), pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pgSt.Close()
	// 6. Setup state now permits first-admin creation while provider remains
	// locked (running postgres, not restart-required).
	post2, err := databasesetup.StateFor(pgSt, dir)
	if err != nil || post2.Selectable || post2.RestartRequired || post2.Provider != "postgres" {
		t.Fatalf("post-restart state: %+v %v", post2, err)
	}
	// 7. Create the first administrator on PostgreSQL.
	a := auth.New(pgSt)
	if err := a.CreateAdmin("admin", "admin@example.com", "secret7"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Login("admin@example.com", "secret7"); err != nil {
		t.Fatal(err)
	}
	// 8. Restart again and prove the deployment is stable.
	pgSt.Close()
	pgSt2, err := store.OpenPostgres(context.Background(), pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pgSt2.Close()
	if need, _ := auth.New(pgSt2).NeedsSetup(); need {
		t.Fatal("setup reappeared after restart on postgres")
	}
	// 9. Environment-provisioned path behaves consistently.
	envSt, err := store.OpenPostgres(context.Background(), pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer envSt.Close()
	env, err := databasesetup.StateFor(envSt, dir)
	if err != nil || env.Selectable {
		t.Fatalf("env-provisioned state: %+v %v", env, err)
	}
}

type mapResolver map[string][]netip.Addr

func (m mapResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ips, ok := m[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host}
}

func TestPostgresDeploymentIdempotency(t *testing.T) {
	st, _ := openFreshPG(t)
	site, err := sites.New(st).Create(1, "x", "https://example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	dep := deployments.New(st)
	a1, err := dep.Record(deployments.Event{SiteID: site.ID, Provider: "github", ExternalID: "rev-1", Revision: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	a2, err := dep.Record(deployments.Event{SiteID: site.ID, Provider: "github", ExternalID: "rev-1", Revision: "def"})
	if err != nil {
		t.Fatal(err)
	}
	if a1.ID != a2.ID {
		t.Fatalf("postgres dedup produced two rows: %d vs %d", a1.ID, a2.ID)
	}
	// Empty external_id must not collapse, and the auto id sequence must not
	// collide with preserved ids after the rebuild.
	empty1, err := dep.Record(deployments.Event{SiteID: site.ID, Provider: "github", Revision: "one"})
	if err != nil {
		t.Fatal(err)
	}
	empty2, err := dep.Record(deployments.Event{SiteID: site.ID, Provider: "github", Revision: "two"})
	if err != nil {
		t.Fatal(err)
	}
	if empty1.ID == empty2.ID || empty1.ID == a1.ID || empty2.ID == a1.ID {
		t.Fatalf("postgres empty external_id collapse or sequence collision: %d %d %d", empty1.ID, empty2.ID, a1.ID)
	}
}

// TestEnvProvisionedPostgresStartup proves the real startup path: setting
// WEBFLEET_DATABASE_URL causes configuration to select PostgreSQL, the store
// opens on that database, and first-run setup state behaves correctly without
// any browser database chooser.
func TestEnvProvisionedPostgresStartup(t *testing.T) {
	base := os.Getenv("WEBFLEET_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("WEBFLEET_TEST_POSTGRES_URL not set")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("wf_env_%d", time.Now().UnixNano())
	admin, err := store.OpenPostgres(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.DB.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()
	u.Path = "/" + name
	dsn := u.String()
	t.Cleanup(func() {
		admin, err := store.OpenPostgres(context.Background(), base)
		if err == nil {
			_, _ = admin.DB.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			admin.Close()
		}
	})

	dir := t.TempDir()
	t.Setenv("WEBFLEET_DATA_DIR", dir)
	t.Setenv("WEBFLEET_DATABASE_URL", dsn)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != dsn {
		t.Fatalf("env database url not selected: %q", cfg.DatabaseURL)
	}
	if store.Provider(cfg.DatabaseURL) != "postgres" {
		t.Fatal("provider not detected as postgres")
	}
	st, err := store.OpenPostgres(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("open via startup path: %v", err)
	}
	defer st.Close()
	state, err := databasesetup.StateFor(st, dir)
	if err != nil || state.Selectable || state.RestartRequired || state.Provider != "postgres" {
		t.Fatalf("env-provisioned setup state: %+v %v", state, err)
	}
	if err := auth.New(st).CreateAdmin("admin", "admin@example.com", "secret7"); err != nil {
		t.Fatal(err)
	}
	if need, _ := auth.New(st).NeedsSetup(); need {
		t.Fatal("setup still required after env-provisioned admin creation")
	}
}

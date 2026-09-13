package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/webfleet-cv/webfleet/internal/database"
	_ "github.com/webfleet-cv/webfleet/internal/postgresdriver"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	_ "github.com/webfleet-cv/webfleet/internal/sqlitedriver"
)

type Store struct {
	DB   *database.DB
	path string
}

const schemaVersion = 35

type migration struct {
	version int
	name    string
	stmts   []string
}

var migrations = []migration{
	{1, "application foundation", []string{
		`CREATE TABLE _webfleet_schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);`,
		`CREATE TABLE organizations(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);`,
		`INSERT INTO organizations(name,created_at) VALUES('My Web Fleet', datetime('now'));`,
		`CREATE TABLE app_events(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL);`,
	}},
	{2, "first administrator authentication", []string{
		`CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL);`,
		`CREATE TABLE sessions(id INTEGER PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);`,
		`CREATE TABLE audit_events(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);`,
	}},
	{3, "sites and groups", []string{
		`CREATE TABLE groups(id INTEGER PRIMARY KEY, organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id), name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(organization_id,name));`,
		`CREATE TABLE sites(id INTEGER PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, primary_url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL, archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`,
		`CREATE INDEX sites_name_idx ON sites(name);`,
		`CREATE INDEX sites_group_idx ON sites(group_id);`,
	}},
	{4, "http monitoring", []string{
		`CREATE TABLE monitors(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, kind TEXT NOT NULL DEFAULT 'http', timeout_ms INTEGER NOT NULL DEFAULT 10000, expected_min INTEGER NOT NULL DEFAULT 200, expected_max INTEGER NOT NULL DEFAULT 399, created_at TEXT NOT NULL);`,
		`CREATE UNIQUE INDEX monitors_site_kind_idx ON monitors(site_id,kind);`,
		`INSERT INTO monitors(site_id,kind,timeout_ms,expected_min,expected_max,created_at) SELECT id,'http',10000,200,399,datetime('now') FROM sites;`,
		`CREATE TABLE check_results(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE, ok INTEGER NOT NULL, status_code INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER NOT NULL DEFAULT 0, final_url TEXT NOT NULL DEFAULT '', error_class TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL);`,
		`CREATE INDEX check_results_site_time_idx ON check_results(site_id,checked_at DESC);`,
	}},
	{5, "fleet health", []string{
		`CREATE TABLE site_health(site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE, state TEXT NOT NULL DEFAULT 'unknown', consecutive_failures INTEGER NOT NULL DEFAULT 0, last_check_id INTEGER REFERENCES check_results(id) ON DELETE SET NULL, last_change_at TEXT NOT NULL, last_success_at TEXT, last_failure_at TEXT);`,
		`INSERT INTO site_health(site_id,state,last_change_at) SELECT id,'unknown',datetime('now') FROM sites;`,
	}},
	{6, "incidents and alerts", []string{
		`CREATE TABLE incidents(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, state TEXT NOT NULL, summary TEXT NOT NULL, opened_at TEXT NOT NULL, closed_at TEXT, acknowledged_at TEXT);`,
		`CREATE INDEX incidents_site_time_idx ON incidents(site_id,opened_at DESC);`,
		`CREATE TABLE alert_policies(id INTEGER PRIMARY KEY, organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id), name TEXT NOT NULL, transport TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);`,
		`INSERT INTO alert_policies(organization_id,name,transport,enabled,created_at) VALUES(1,'Dashboard alerts','in_app',1,datetime('now'));`,
		`CREATE TABLE alert_deliveries(id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, transport TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);`,
	}},
	{7, "tls observations", []string{
		`CREATE TABLE tls_observations(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, valid INTEGER NOT NULL, hostname_valid INTEGER NOT NULL, issuer TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '', not_before TEXT NOT NULL DEFAULT '', not_after TEXT NOT NULL DEFAULT '', days_remaining INTEGER NOT NULL DEFAULT 0, error_class TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL);`,
		`CREATE INDEX tls_observations_site_idx ON tls_observations(site_id,id DESC);`,
	}},
	{8, "dns observations", []string{
		`CREATE TABLE dns_observations(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, a_records TEXT NOT NULL DEFAULT '', aaaa_records TEXT NOT NULL DEFAULT '', cname TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, changed INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL);`,
		`CREATE INDEX dns_observations_site_idx ON dns_observations(site_id,id DESC);`,
	}},
	{9, "headers and redirects", []string{
		`CREATE TABLE header_expectations(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, name TEXT NOT NULL, required INTEGER NOT NULL DEFAULT 1, UNIQUE(site_id,name));`,
		`INSERT INTO header_expectations(site_id,name,required) SELECT id,'Content-Security-Policy',1 FROM sites;`,
		`INSERT INTO header_expectations(site_id,name,required) SELECT id,'Strict-Transport-Security',1 FROM sites;`,
		`INSERT INTO header_expectations(site_id,name,required) SELECT id,'X-Content-Type-Options',1 FROM sites;`,
		`INSERT INTO header_expectations(site_id,name,required) SELECT id,'Referrer-Policy',1 FROM sites;`,
		`CREATE TABLE http_observations(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, check_id INTEGER NOT NULL REFERENCES check_results(id) ON DELETE CASCADE, redirect_chain TEXT NOT NULL DEFAULT '[]', headers_json TEXT NOT NULL DEFAULT '{}', missing_headers TEXT NOT NULL DEFAULT '', changed INTEGER NOT NULL DEFAULT 0, observed_at TEXT NOT NULL);`,
		`CREATE INDEX http_observations_site_idx ON http_observations(site_id,id DESC);`,
	}},
	{10, "crawl and link health", []string{
		`CREATE TABLE crawl_runs(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, status TEXT NOT NULL, pages_crawled INTEGER NOT NULL DEFAULT 0, internal_links INTEGER NOT NULL DEFAULT 0, external_links INTEGER NOT NULL DEFAULT 0, broken_internal INTEGER NOT NULL DEFAULT 0, broken_external INTEGER NOT NULL DEFAULT 0, new_broken INTEGER NOT NULL DEFAULT 0, robots_found INTEGER NOT NULL DEFAULT 0, sitemap_found INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, finished_at TEXT);`,
		`CREATE INDEX crawl_runs_site_idx ON crawl_runs(site_id,id DESC);`,
		`CREATE TABLE crawl_pages(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES crawl_runs(id) ON DELETE CASCADE, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, url TEXT NOT NULL, status_code INTEGER NOT NULL DEFAULT 0, depth INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '');`,
		`CREATE INDEX crawl_pages_run_idx ON crawl_pages(run_id);`,
		`CREATE TABLE crawl_links(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES crawl_runs(id) ON DELETE CASCADE, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, from_url TEXT NOT NULL, to_url TEXT NOT NULL, kind TEXT NOT NULL, status_code INTEGER NOT NULL DEFAULT 0, broken INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '');`,
		`CREATE INDEX crawl_links_run_idx ON crawl_links(run_id);`,
	}},
	{11, "performance history", []string{
		`ALTER TABLE check_results ADD COLUMN response_bytes INTEGER NOT NULL DEFAULT 0;`,
		`CREATE TABLE performance_baselines(site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE, baseline_latency_ms INTEGER NOT NULL DEFAULT 0, baseline_response_bytes INTEGER NOT NULL DEFAULT 0, sample_count INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);`,
	}},
	{12, "manual browser audits", []string{
		`CREATE TABLE audit_settings(site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE, history_enabled INTEGER NOT NULL DEFAULT 0, pages_json TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL);`,
		`CREATE TABLE audit_runs(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, status TEXT NOT NULL, performance_score INTEGER NOT NULL DEFAULT 0, accessibility_score INTEGER NOT NULL DEFAULT 0, best_practices_score INTEGER NOT NULL DEFAULT 0, discoverability_score INTEGER NOT NULL DEFAULT 0, findings_json TEXT NOT NULL DEFAULT '[]', duration_ms INTEGER NOT NULL DEFAULT 0, audited_url TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);`,
		`CREATE INDEX audit_runs_site_idx ON audit_runs(site_id,id DESC);`,
	}},
	{13, "analytics property and tracker", []string{
		`CREATE TABLE analytics_properties(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE, public_key TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, allowed_origin TEXT NOT NULL, created_at TEXT NOT NULL);`,
		`CREATE TABLE analytics_events(id INTEGER PRIMARY KEY, property_id INTEGER NOT NULL REFERENCES analytics_properties(id) ON DELETE CASCADE, kind TEXT NOT NULL, path TEXT NOT NULL DEFAULT '/', referrer TEXT NOT NULL DEFAULT '', visitor_key TEXT NOT NULL DEFAULT '', user_agent_class TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', payload_json TEXT NOT NULL DEFAULT '{}', occurred_at TEXT NOT NULL);`,
		`CREATE INDEX analytics_events_property_time_idx ON analytics_events(property_id,occurred_at DESC);`,
	}},
	{14, "analytics rollups", []string{
		`CREATE TABLE analytics_daily(property_id INTEGER NOT NULL REFERENCES analytics_properties(id) ON DELETE CASCADE, day TEXT NOT NULL, pageviews INTEGER NOT NULL DEFAULT 0, visitors INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(property_id,day));`,
		`CREATE TABLE analytics_daily_visitors(property_id INTEGER NOT NULL REFERENCES analytics_properties(id) ON DELETE CASCADE, day TEXT NOT NULL, visitor_key TEXT NOT NULL, PRIMARY KEY(property_id,day,visitor_key));`,
	}},
	{15, "analytics goals", []string{
		`CREATE TABLE analytics_goals(id INTEGER PRIMARY KEY, property_id INTEGER NOT NULL REFERENCES analytics_properties(id) ON DELETE CASCADE, name TEXT NOT NULL, event_kind TEXT NOT NULL, path_match TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, UNIQUE(property_id,name));`,
	}},
	{16, "retention and maintenance", []string{
		`CREATE TABLE maintenance_settings(id INTEGER PRIMARY KEY, check_days INTEGER NOT NULL DEFAULT 90, analytics_raw_days INTEGER NOT NULL DEFAULT 30, audit_days INTEGER NOT NULL DEFAULT 180, updated_at TEXT NOT NULL);`,
		`INSERT INTO maintenance_settings(id,check_days,analytics_raw_days,audit_days,updated_at) VALUES(1,90,30,180,CURRENT_TIMESTAMP);`,
	}},
	{17, "persistent analytics secret", []string{
		`CREATE TABLE app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);`,
	}},
	{18, "organizations and rbac", []string{
		`CREATE TABLE organization_memberships(organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK(role IN ('owner','admin','operator','viewer')), created_at TEXT NOT NULL, PRIMARY KEY(organization_id,user_id));`,
		`INSERT INTO organization_memberships(organization_id,user_id,role,created_at) SELECT 1,id,'owner',CURRENT_TIMESTAMP FROM users;`,
		`CREATE TABLE security_audit(id INTEGER PRIMARY KEY, actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL, action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);`,
	}},
	{19, "api tokens", []string{
		`CREATE TABLE api_tokens(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, scopes TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL);`,
	}},
	{20, "oidc configuration", []string{
		`CREATE TABLE oidc_config(id INTEGER PRIMARY KEY, issuer TEXT NOT NULL, client_id TEXT NOT NULL, client_secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, auto_provision INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);`,
		`CREATE TABLE oidc_states(state TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires_at TEXT NOT NULL);`,
	}},
	{21, "deployment observations", []string{
		`CREATE TABLE deployment_events(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, provider TEXT NOT NULL, external_id TEXT NOT NULL DEFAULT '', revision TEXT NOT NULL DEFAULT '', environment TEXT NOT NULL DEFAULT 'production', status TEXT NOT NULL DEFAULT 'deployed', url TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}', deployed_at TEXT NOT NULL, received_at TEXT NOT NULL, UNIQUE(site_id,provider,external_id));`,
		`CREATE INDEX deployment_events_site_time_idx ON deployment_events(site_id,deployed_at DESC);`,
	}},
	{22, "notification integrations", []string{
		`CREATE TABLE notification_webhooks(id INTEGER PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, name TEXT NOT NULL, url TEXT NOT NULL, secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);`,
		`CREATE TABLE notification_deliveries(id INTEGER PRIMARY KEY, webhook_id INTEGER NOT NULL REFERENCES notification_webhooks(id) ON DELETE CASCADE, event_kind TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, response_code INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, delivered_at TEXT);`,
	}},
	{23, "site tags", []string{
		`CREATE TABLE site_tags(site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, tag TEXT NOT NULL, PRIMARY KEY(site_id,tag));`,
		`CREATE INDEX site_tags_tag_idx ON site_tags(tag);`,
	}},
	{24, "webhook outbox payloads", []string{
		`ALTER TABLE notification_deliveries ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}';`,
	}},
	{25, "oidc browser binding", []string{
		`ALTER TABLE oidc_states ADD COLUMN browser TEXT NOT NULL DEFAULT '';`,
	}},
	{26, "scheduler job leases", []string{
		`CREATE TABLE job_leases(lease_kind TEXT NOT NULL, resource_id INTEGER NOT NULL, owner TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(lease_kind, resource_id));`,
	}},
	{27, "scheduler due claims", []string{
		`CREATE TABLE scheduler_claims(claim_kind TEXT NOT NULL, site_id INTEGER NOT NULL, next_due_at TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL DEFAULT 0, lease_until TEXT NOT NULL DEFAULT '', PRIMARY KEY(claim_kind, site_id));`,
	}},
	{28, "deployment idempotency partial index", []string{
		`ALTER TABLE deployment_events RENAME TO deployment_events_old;`,
		`CREATE TABLE deployment_events(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, provider TEXT NOT NULL, external_id TEXT NOT NULL DEFAULT '', revision TEXT NOT NULL DEFAULT '', environment TEXT NOT NULL DEFAULT 'production', status TEXT NOT NULL DEFAULT 'deployed', url TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}', deployed_at TEXT NOT NULL, received_at TEXT NOT NULL);`,
		`INSERT INTO deployment_events(id,site_id,provider,external_id,revision,environment,status,url,metadata_json,deployed_at,received_at) SELECT id,site_id,provider,external_id,revision,environment,status,url,metadata_json,deployed_at,received_at FROM deployment_events_old;`,
		`DROP TABLE deployment_events_old;`,
		`CREATE INDEX deployment_events_site_time_idx ON deployment_events(site_id,deployed_at DESC);`,
		`CREATE UNIQUE INDEX deployment_events_idem_idx ON deployment_events(site_id,provider,external_id) WHERE external_id <> '';`,
	}},
	{29, "crawl result transparency", []string{
		`ALTER TABLE crawl_runs ADD COLUMN pages_discovered INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN page_limit INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN limit_reached INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN sitemap_urls_discovered INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN current_url TEXT NOT NULL DEFAULT '';`,
	}},
	{30, "crawl site inventory", []string{
		`ALTER TABLE crawl_runs ADD COLUMN pages_failed INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN css_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN javascript_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN image_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN font_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN media_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN document_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN data_feed_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_runs ADD COLUMN other_asset_files INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE crawl_pages ADD COLUMN kind TEXT NOT NULL DEFAULT 'page';`,
		`ALTER TABLE crawl_pages ADD COLUMN asset_class TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE crawl_pages ADD COLUMN origin TEXT NOT NULL DEFAULT 'internal';`,
		`ALTER TABLE crawl_pages ADD COLUMN ok INTEGER NOT NULL DEFAULT 1;`,
	}},
	{31, "audit progress + analytics country", []string{
		`ALTER TABLE audit_runs ADD COLUMN started_at TEXT NOT NULL DEFAULT '';`,
	}},
	{32, "instance launcher", []string{
		`CREATE TABLE launcher_instances(id TEXT PRIMARY KEY, position INTEGER NOT NULL, name TEXT NOT NULL, domain TEXT NOT NULL, port INTEGER);`,
	}},
	{33, "gantry cluster membership", []string{
		`CREATE TABLE cluster_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), node_id TEXT NOT NULL UNIQUE, installation_id TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '', public_endpoint TEXT NOT NULL DEFAULT '', public_key BLOB NOT NULL, private_key BLOB NOT NULL, capabilities_json TEXT NOT NULL, protocol_version INTEGER NOT NULL, product_version TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);`,
		`CREATE TABLE cluster_members(node_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '', public_endpoint TEXT NOT NULL, public_key BLOB NOT NULL, capabilities_json TEXT NOT NULL, protocol_version INTEGER NOT NULL, product_version TEXT NOT NULL DEFAULT '', state TEXT NOT NULL CHECK(state IN ('active','disabled','revoked')), outbound_secret TEXT NOT NULL, inbound_secret_hash BLOB NOT NULL, credential_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, paired_at TEXT NOT NULL, last_seen_at TEXT, last_latency_ms INTEGER, revoked_at TEXT);`,
		`CREATE TABLE cluster_invitations(id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, state TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);`,
		`CREATE TABLE cluster_nonces(node_id TEXT NOT NULL REFERENCES cluster_members(node_id) ON DELETE CASCADE, nonce TEXT NOT NULL, seen_at TEXT NOT NULL, PRIMARY KEY(node_id,nonce));`,
		`CREATE INDEX cluster_nonces_seen ON cluster_nonces(seen_at);`,
	}},
	{34, "cluster pairing lifecycle", []string{
		`CREATE TABLE cluster_join_requests(id TEXT PRIMARY KEY, request_secret_hash BLOB NOT NULL UNIQUE, invitation_id TEXT NOT NULL REFERENCES cluster_invitations(id), node_id TEXT NOT NULL, installation_id TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '', public_endpoint TEXT NOT NULL, public_key BLOB NOT NULL, capabilities_json TEXT NOT NULL DEFAULT '[]', protocol_version INTEGER NOT NULL, product_version TEXT NOT NULL DEFAULT '', credential_for_local TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, decided_at TEXT, response_consumed_at TEXT);`,
		`CREATE TABLE cluster_outbound_joins(id TEXT PRIMARY KEY, remote_url TEXT NOT NULL, request_id TEXT NOT NULL, request_secret TEXT NOT NULL, local_inbound_credential TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT '');`,
	}},
	{35, "propagation profiles and history", []string{
		`CREATE TABLE propagation_profiles(id TEXT PRIMARY KEY, name TEXT NOT NULL, selector_json TEXT NOT NULL, kinds_json TEXT NOT NULL, mode TEXT NOT NULL, schedule TEXT NOT NULL DEFAULT '', maintenance_window TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`,
		`CREATE TABLE propagation_history(id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, rolled_back INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);`,
		`CREATE INDEX propagation_history_created_idx ON propagation_history(created_at DESC);`,
	}},
	{36, "propagation scheduling state", []string{
		`ALTER TABLE propagation_profiles ADD COLUMN last_run_at TEXT;`,
	}},
}

func Open(dataDir string) (*Store, error) {
	return OpenContext(context.Background(), dataDir)
}

func OpenContext(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	path := filepath.Join(dataDir, "webfleet.db")
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	// SQLite's connection-local PRAGMAs and single-writer model are easiest to
	// reason about with one owned connection. This matches Trestle's SQLite path.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{DB: &database.DB{DB: db, Dialect: "sqlite"}, path: path}
	if err := s.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func OpenPostgres(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("postgres DSN is required")
	}
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	raw.SetMaxOpenConns(20)
	raw.SetMaxIdleConns(5)
	raw.SetConnMaxLifetime(30 * time.Minute)
	s := &Store{DB: &database.DB{DB: raw, Dialect: "postgres"}, path: "postgres"}
	if err := raw.PingContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if err := s.initializePostgres(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return s, nil
}
func postgresSQL(q string) string {
	q = strings.ReplaceAll(q, "INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")
	q = strings.ReplaceAll(q, " BLOB ", " BYTEA ")
	q = strings.ReplaceAll(q, "datetime('now')", "CURRENT_TIMESTAMP")
	q = strings.ReplaceAll(q, "CURRENT_TIMESTAMP", "CURRENT_TIMESTAMP::text")
	return q
}
func (s *Store) initializePostgres(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _webfleet_schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT version,name FROM _webfleet_schema_migrations ORDER BY version`)
	if err != nil {
		return err
	}
	defer rows.Close()
	version := 0
	for rows.Next() {
		var v int
		var n string
		if err := rows.Scan(&v, &n); err != nil {
			return err
		}
		if v < 1 || v > len(migrations) || migrations[v-1].name != n {
			return fmt.Errorf("postgres migration history mismatch at %d", v)
		}
		version = v
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= version {
			continue
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		ok := false
		defer func() {
			if !ok {
				_ = tx.Rollback()
			}
		}()
		for _, q := range m.stmts {
			if strings.Contains(q, "CREATE TABLE _webfleet_schema_migrations") {
				continue
			}
			if _, err = tx.ExecContext(ctx, postgresSQL(q)); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply postgres migration %d: %w", m.version, err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO _webfleet_schema_migrations(version,name,applied_at) VALUES(?,?,?)`, m.version, m.name, Now()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		ok = true
	}
	return s.syncSerialSequences(ctx)
}

// syncSerialSequences repairs PostgreSQL sequences after migrations that rebuild
// tables by copying explicit ids (e.g. the deployment partial-index rebuild),
// so new auto ids never collide with preserved rows.
func (s *Store) syncSerialSequences(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, `SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND column_default LIKE 'nextval(%'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.column); err != nil {
			return err
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range cols {
		// setval(pg_get_serial_sequence(...), max(id), true) advances the
		// sequence to the highest preserved id.
		if _, err := s.DB.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence('`+c.table+`','`+c.column+`'), COALESCE(MAX(`+c.column+`),1), true) FROM `+c.table); err != nil {
			return fmt.Errorf("sync serial sequence for %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}
func (s *Store) Dialect() string { return s.DB.DialectName() }

// ClaimDue atomically claims a unit of scheduled work for one owner when it is
// actually due and either unclaimed or expired. Each successful claim bumps the
// generation (fencing token); a stale owner holding an older generation can
// never renew or complete the newer owner's slot. The upsert is atomic on both
// SQLite (single owned connection) and PostgreSQL.
func (s *Store) ClaimDue(ctx context.Context, kind string, siteID int64, owner string, now, leaseUntil time.Time) (int64, bool, error) {
	rows, err := sqlite.Query(s.DB, `INSERT INTO scheduler_claims(claim_kind,site_id,next_due_at,owner,generation,lease_until) VALUES(?,?,?,?,1,?) ON CONFLICT(claim_kind,site_id) DO UPDATE SET owner=excluded.owner,generation=scheduler_claims.generation+1,lease_until=excluded.lease_until WHERE scheduler_claims.next_due_at<=? AND (scheduler_claims.owner='' OR scheduler_claims.lease_until<=?) RETURNING generation`, kind, siteID, now.Format(time.RFC3339Nano), owner, leaseUntil.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return 0, false, err
	}
	if len(rows) == 0 {
		return 0, false, nil
	}
	return rows[0]["generation"].Int64, true, nil
}

// RenewClaim extends the lease only when the caller still owns the claim with
// the same generation. A false result means ownership moved and the caller's
// in-flight work must be cancelled (fencing).
func (s *Store) RenewClaim(ctx context.Context, kind string, siteID int64, owner string, generation int64, leaseUntil time.Time) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE scheduler_claims SET lease_until=? WHERE claim_kind=? AND site_id=? AND owner=? AND generation=?`, leaseUntil.Format(time.RFC3339Nano), kind, siteID, owner, generation)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// CompleteClaim advances next_due_at and releases the claim only when the
// caller still owns it with the same generation. A stale owner's completion is
// a no-op, so it cannot mark the newer owner's slot complete.
func (s *Store) CompleteClaim(ctx context.Context, kind string, siteID int64, owner string, generation int64, nextDue time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE scheduler_claims SET next_due_at=?,owner='',lease_until='' WHERE claim_kind=? AND site_id=? AND owner=? AND generation=?`, nextDue.Format(time.RFC3339Nano), kind, siteID, owner, generation)
	return err
}

// PrimaryOrgID returns the deployment's bootstrap organization created by
// migration 1. Identity bootstrap (first administrator, OIDC auto-provision)
// attaches memberships to it. Callers derive it from the store rather than
// hard-coding an organization id.
func (s *Store) PrimaryOrgID(ctx context.Context) (int64, error) {
	r, e := sqlite.Query(s.DB, `SELECT id FROM organizations ORDER BY id LIMIT 1`)
	if e != nil {
		return 0, e
	}
	if len(r) == 0 {
		return 0, errors.New("no organization exists for this deployment")
	}
	return r[0]["id"].Int64, nil
}

func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Path() string { return s.path }

func (s *Store) initialize(ctx context.Context) error {
	if err := s.DB.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite database: %w", err)
	}
	var foreignKeys int
	if err := s.DB.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		return errors.New("sqlite foreign keys are not enabled")
	}
	version, err := s.sqliteVersion(ctx)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version > version {
			if err := s.apply(ctx, m); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) sqliteVersion(ctx context.Context) (int, error) {
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_webfleet_schema_migrations'`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("inspect migration history: %w", err)
	}
	if exists == 0 {
		legacy, err := s.legacyVersion(ctx)
		if err != nil {
			return 0, err
		}
		if legacy > 0 {
			if err := s.importLegacyHistory(ctx, legacy); err != nil {
				return 0, err
			}
			return legacy, nil
		}
		var mirror int
		if err := s.DB.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&mirror); err != nil {
			return 0, fmt.Errorf("read schema version mirror: %w", err)
		}
		if mirror > schemaVersion {
			return 0, fmt.Errorf("database schema %d is newer than supported %d", mirror, schemaVersion)
		}
		if mirror != 0 {
			return 0, fmt.Errorf("database has schema version marker %d but no migration history", mirror)
		}
		return 0, nil
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT version,name FROM _webfleet_schema_migrations ORDER BY version`)
	if err != nil {
		return 0, fmt.Errorf("read migration history: %w", err)
	}
	defer rows.Close()
	expected := 1
	version := 0
	for rows.Next() {
		var got int
		var name string
		if err := rows.Scan(&got, &name); err != nil {
			return 0, err
		}
		if got > schemaVersion {
			return 0, fmt.Errorf("database schema %d is newer than supported %d", got, schemaVersion)
		}
		if got != expected {
			return 0, fmt.Errorf("database migration history is not contiguous: expected %d, found %d", expected, got)
		}
		if name != migrations[got-1].name {
			return 0, fmt.Errorf("database migration %d has unexpected name %q", got, name)
		}
		version = got
		expected++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	var mirror int
	if err := s.DB.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&mirror); err != nil {
		return 0, fmt.Errorf("read schema version mirror: %w", err)
	}
	if mirror > schemaVersion {
		return 0, fmt.Errorf("database schema %d is newer than supported %d", mirror, schemaVersion)
	}
	if version > 0 && mirror == 0 {
		if _, err := s.DB.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
			return 0, fmt.Errorf("restore schema version mirror: %w", err)
		}
	} else if mirror != version {
		return 0, fmt.Errorf("database schema version marker %d does not match migration history version %d", mirror, version)
	}
	return version, nil
}

func (s *Store) legacyVersion(ctx context.Context) (int, error) {
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_meta'`).Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	var version int
	if err := s.DB.QueryRowContext(ctx, `SELECT version FROM schema_meta LIMIT 1`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read legacy schema version: %w", err)
	}
	if version < 0 || version > schemaVersion {
		return 0, fmt.Errorf("legacy database schema %d is newer than supported %d", version, schemaVersion)
	}
	return version, nil
}

func (s *Store) importLegacyHistory(ctx context.Context, version int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE _webfleet_schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create migration history: %w", err)
	}
	for i := 1; i <= version; i++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO _webfleet_schema_migrations(version,name,applied_at) VALUES(?,?,?)`, i, migrations[i-1].name, Now()); err != nil {
			return fmt.Errorf("import migration %d: %w", i, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE schema_meta`); err != nil {
		return fmt.Errorf("remove legacy schema marker: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
		return fmt.Errorf("set schema version mirror: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy schema history import: %w", err)
	}
	return nil
}

func (s *Store) apply(ctx context.Context, m migration) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", m.version, err)
	}
	defer tx.Rollback()
	for _, q := range m.stmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", m.version, m.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO _webfleet_schema_migrations(version,name,applied_at) VALUES(?,?,?)`, m.version, m.name, Now()); err != nil {
		return fmt.Errorf("record migration %d: %w", m.version, err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, m.version)); err != nil {
		return fmt.Errorf("set schema version %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", m.version, err)
	}
	return nil
}

func (s *Store) SchemaVersion() (int, error) {
	r, err := sqlite.Query(s.DB, `SELECT version FROM _webfleet_schema_migrations ORDER BY version DESC LIMIT 1`)
	if err != nil || len(r) == 0 {
		return 0, err
	}
	return int(r[0]["version"].Int64), nil
}

func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) Backup(destination string) error {
	if strings.TrimSpace(destination) == "" {
		return errors.New("backup destination is required")
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}
	_ = os.Remove(abs)
	q := `VACUUM INTO '` + strings.ReplaceAll(abs, `'`, `''`) + `'`
	if _, err := s.DB.Exec(q); err != nil {
		return fmt.Errorf("backup sqlite database: %w", err)
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return fmt.Errorf("secure backup: %w", err)
	}
	return nil
}
func ValidateDatabase(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var ok string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&ok); err != nil {
		return err
	}
	if ok != "ok" {
		return fmt.Errorf("sqlite integrity check failed: %s", ok)
	}
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("backup schema %d is newer than supported %d", v, schemaVersion)
	}
	return nil
}
func Restore(dataDir, source string) error {
	if err := ValidateDatabase(source); err != nil {
		return fmt.Errorf("validate restore source: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dataDir, 0o700)
	dst := filepath.Join(dataDir, "webfleet.db")
	tmp := dst + ".restore"
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		bak := dst + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(dst, bak); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return nil
}

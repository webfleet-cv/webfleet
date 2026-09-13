# Web Fleet development roadmap

This is a living implementation plan. Update checkpoint status, evidence and follow-up work throughout development.

## Phase 1 - prove the monitoring loop

### CP1 - Application foundation ✅

- Establish Go module and package layout.
- Embed/build the Nift dashboard frontend through the normal repository workflow.
- Add configuration loading with explicit data/listen settings.
- Open SQLite database and version schema migrations.
- Add graceful startup/shutdown and structured application logging.
- Add `/healthz` and a minimal dashboard shell.
- Add unit tests for configuration and migration behaviour.

**Exit:** one binary starts from a fresh directory, initializes its database, serves the dashboard and exits cleanly.

**Completed:** Go application foundation, versioned SQLite schema, Nift-built embedded dashboard, configuration, structured logging, graceful shutdown, `/healthz`, and unit/integration coverage. SQLite now follows the same storage pattern as Trestle: `database/sql`, the cgo-free `modernc.org/sqlite` driver, one owned SQLite connection, WAL, foreign-key enforcement, a five-second busy timeout, secured data-directory permissions, validated migration history and transactional migrations.

### CP2 - First-admin authentication ✅

- Fresh-install setup flow.
- First admin creation.
- Modern password hashing.
- Login/logout/session lifecycle.
- CSRF protection and secure cookie settings.
- Minimum password length consistent with the project policy.
- Authentication audit events.

**Exit:** unauthenticated users cannot access the dashboard and session/security regression tests pass.

**Completed:** first-run admin creation, Argon2id password hashing, strict session cookies, hashed session tokens, CSRF enforcement, logout/session expiry, authentication audit records, and setup/login UI. The current Argon2 binding uses the system `libargon2.so.1` because external Go modules are unavailable in this build environment; portable dependency packaging remains a later release-hardening obligation.

### CP3 - Site model and CRUD ✅

- Organization foundation with a simple single-organization default UX.
- Site records with name, primary URL, enabled state and optional tags/group.
- URL canonicalization and validation.
- Site create/edit/archive/delete UX.
- Empty state and validation errors that ordinary users can understand.
- Search/filter foundation for future large fleets.

**Exit:** a user can add and manage several sites without monitoring yet.

**Completed:** persisted groups and sites, canonical HTTP/HTTPS URLs, create/edit/archive/delete flows, server-backed search/group filtering/page-number pagination, large-fleet inventory UX, and a stable SPA site-detail route. Search/pagination/grouping were deliberately promoted from the later large-fleet UX checkpoint because they are core inventory behaviour, while CP27 now focuses on accessibility and scale hardening rather than first implementation.

### CP4 - HTTP monitor engine ✅

- Monitor definitions and check-result persistence.
- HTTP/HTTPS request execution with timeout and redirect policy.
- Status/latency/final URL capture.
- Error classification.
- SSRF protections for private/reserved targets, redirect hops and DNS resolution.
- Unit and integration tests with controlled local HTTP fixtures.

**Exit:** checks are correct, security-bounded and queryable from storage.

**Completed:** persisted HTTP monitor definitions/results, timeout and redirect bounds, expected-status evaluation, latency/final-URL capture, structured DNS/connection/TLS/timeout/redirect/status error classes, and SSRF-safe DNS/dial/redirect validation. Private/reserved targets are blocked at resolved-address and dial time; controlled local fixtures use an explicit test-only private-network override.

### CP5 - Scheduler and fleet health ✅

- Background scheduler with bounded concurrency and jitter.
- Manual "check now" action.
- Consecutive failure/recovery state machine.
- Fleet health derivation.
- Fleet overview showing healthy/degraded/warning/down counts and "needs attention".
- Site overview with recent history.

**Exit:** adding a URL results in periodic checks and an immediately useful fleet dashboard.

**Completed:** bounded-concurrency scheduler with interval jitter, manual Check now, persisted healthy/degraded/warning/down/unknown state, consecutive failure and recovery transitions, fleet health counts, attention queue, health-aware site inventory, and recent check history on the individual site page.

### CP6 - Incident history and alerts foundation ✅

- Open/close incidents from monitor state transitions.
- Incident timeline and acknowledgement metadata.
- Alert policy model.
- First notification transport, kept deliberately simple.
- Deduplication and recovery notification behaviour.

**Exit:** an outage creates one coherent incident and recovery closes it without alert storms.

**Completed:** one persisted incident per unhealthy period, state escalation without duplicate incidents, recovery closure, acknowledgement metadata, alert policy model, and deduplicated in-app open/recovery delivery history. The site-detail view exposes incident history; external transports remain intentionally deferred to the integrations checkpoint.

## Phase 2 - understand websites as websites

### CP7 - TLS health ✅

- Certificate chain/hostname/expiry inspection.
- Expiry thresholds and fleet warnings.
- TLS failure classification and history.
- Dashboard/site-detail presentation.

**Completed:** shared public-target network guard reused by HTTP/TLS, certificate handshake/hostname validation, chain leaf metadata and expiry persistence, 30-day fleet warning query, manual inspection, 12-hour scheduler refresh, and site-detail TLS presentation.

### CP8 - DNS observation ✅

- Observe relevant A/AAAA/CNAME records.
- Record resolved values and meaningful changes.
- Distinguish transient resolution failures from changed configuration.
- DNS history UI.

**Completed:** A/AAAA/CNAME observation with normalized record sets, private/reserved-answer rejection, successful-state comparison, explicit error observations that do not masquerade as configuration changes, one-hour scheduler refresh, manual observation, history API, and site-detail presentation.

### CP9 - Headers and redirects ✅

- Security/header observations.
- Redirect chain recording.
- Configurable expectations without turning the feature into a generic rule engine.
- Regression/change history.

**Completed:** complete bounded redirect-chain capture, selected HTTP/security header observations, per-site configurable required-header expectations, missing-header evaluation, change detection against the prior observation, history API, and site-detail summary.

### CP10 - Website crawler and link health ✅

- Same-site crawler with explicit limits.
- robots/sitemap awareness where appropriate.
- Internal link graph and broken-link detection.
- Conservative external-link checking.
- Crawl schedule independent from high-frequency uptime checks.
- Per-page and fleet-level regressions.

**Completed:** bounded same-origin crawl queue (50 pages, depth 3, 200 links/page), robots.txt and sitemap awareness, persisted page/link graph, internal broken-link detection, conservative capped external checks with HEAD-to-GET fallback, new-broken comparison against the prior completed crawl, six-hour independent crawl scheduling, manual crawl API/UI, site-detail link health, and fleet-level regression surfacing. All crawler requests and redirects use the shared public-target network guard.

**Ordering review after CP10:** CP11 remains next. Performance history should establish honest server-side baselines before browser-rendered audits are added. CP12 is now a first-class Site Audits checkpoint rather than a vague optional browser-check note. CP13-CP16 then form the coherent privacy-first analytics slice. CP17 backup/restore remains a release gate and may be pulled ahead of analytics only if monitoring-only dogfooding begins before the analytics phase is ready.

### CP11 - Performance history [COMPLETE]

- Stable server-side timing metrics first.
- Response-size and transfer observations.
- Regression thresholds/baselines.
- Avoid presenting synthetic server timing as browser Core Web Vitals.
- Keep this checkpoint independent of a browser runtime so ordinary monitoring remains lightweight.

### CP12 - Audit [COMPLETE]

- Add an optional browser-rendered audit runner for representative pages.
- Present the feature in the site UI simply as **Audit**, not as Google Lighthouse compatibility.
- Audits are **manual by default**. Web Fleet must not automatically launch browser audits merely because a site is being monitored.
- Evaluate performance, accessibility, best-practice/security hygiene and technical discoverability/SEO-style signals with clearly documented scoring rules.
- Capture browser-derived metrics separately from CP11 server timings; never relabel synthetic HTTP timings as Core Web Vitals.
- Show the latest audit result without requiring history.
- Make **audit history opt-in** per site/property. With history disabled, a successful new run replaces the stored current result rather than accumulating historical runs.
- When history is enabled, retain category scores, individual findings and evidence so changes/regressions can be compared over time. Detailed retention controls belong with the later retention-policy work rather than complicating CP12.
- Allow per-site audit configuration, representative-page selection and a manual **Run audit** action.
- Add a **Batch audit** workflow for intentionally running audits across many sites.
- Reuse the normal fleet-selection model for batch targeting: selected sites, current search results, group/category, tags and other simple filters should be available without requiring advanced syntax.
- Provide an optional **Advanced** matcher for operators who need it, including name/URL regular expressions and useful predicates such as last-audited age or current audit state.
- Before starting an advanced/regex batch, show the resolved site count/list so a broad expression cannot unexpectedly launch audits across the whole fleet.
- Queue and bound batch work. Never launch one browser per matched site; audit concurrency must be configurable/limited independently from uptime monitoring.
- Surface current audit problems fleet-wide. Surface **regressions** only where history is enabled and sufficient historical evidence exists.
- Keep the browser runtime optional so basic self-hosting and all automatic monitoring remain usable without Chromium.
- Keep the audit engine internally abstract enough that a browser extension or remote audit worker can be explored later without changing the site/audit data model.

**Exit:** an operator can manually audit one site or deliberately batch-audit an understandable filtered set, inspect the latest browser-based quality evaluation, optionally retain/compare history, and do so without Web Fleet launching heavyweight browser work automatically or confusing the feature with Google Lighthouse itself.

**Phase 2 exit:** Web Fleet understands failures and regressions specific to websites, including browser-rendered quality regressions, not merely hosts.

## Phase 3 - privacy-first analytics

### CP13 - Analytics property and tracker [COMPLETE]

- Optional analytics property per site.
- Tiny cacheable tracker script.
- Ingestion endpoint with origin/property validation and rate limits.
- Pageview event contract.
- No-cookie default.
- Privacy review of every collected field.

### CP14 - Analytics storage and rollups [COMPLETE]

- Raw-event retention policy.
- Privacy-preserving visitor estimation.
- Hour/day aggregate tables.
- Top pages, sources/referrers and coarse client/geography dimensions.
- Bot filtering.
- Performance/load tests for SQLite-scale deployments.

### CP15 - Analytics dashboard [COMPLETE]

- Today/7d/30d/custom ranges.
- Visitors, pageviews, top pages, sources, countries and device/browser classes.
- Recent activity.
- Fleet-wide traffic overview.
- Clear "analytics not installed" onboarding for sites without the tracker.

### CP16 - Events and goals [COMPLETE]

- Custom event API.
- Goal definitions.
- Event/goal dashboards.
- Keep arbitrary user profiling out of scope.

**Phase 3 exit:** Web Fleet offers useful privacy-first analytics to static sites, including GitHub Pages, without needing to host those sites.

## Phase 4 - self-hosting and operational reliability

### CP17 - Backup and restore [COMPLETE]

- Consistent SQLite backup.
- Restore workflow with safety checks.
- Configuration/data export where appropriate.
- Documented disaster-recovery test.

### CP18 - Service install/update/rollback [COMPLETE]

- Linux systemd install path with clear privilege/ownership model.
- Release artifact verification.
- Update and rollback workflow.
- Fresh-install, upgrade and rollback tests.
- Keep non-Linux application builds compiling even if service installation is platform-specific.

### CP19 - PostgreSQL [COMPLETE]

The storage path and Trestle-style first-run database-selection experience are implemented. Live PostgreSQL behavioural/parity execution is intentionally retained for the CP30 battle-hardening campaign.

**Post-Campaign-5 truth:** a real-PostgreSQL parity suite (guarded by `WEBFLEET_TEST_POSTGRES_URL`) now runs the product's storage paths against a live server, catching and fixing two dialect bugs (bool-to-INTEGER binding and an unqualified conflict-update RHS). Fresh setup, restart idempotency, future-schema refusal and provider-aware backup/restore are proven on real PostgreSQL.

- Storage abstraction only where necessary.
- PostgreSQL migrations and integration tests.
- Behavioural equivalence for core monitoring/auth/analytics paths.
- Migration/import story from SQLite where feasible.
- **First-run database choice happens before first-admin registration.**
- Default to SQLite and explain that it is the simplest self-hosted choice.
- Offer PostgreSQL as an explicit alternative during first-run setup.
- When PostgreSQL is selected, show a connection URL field plus **Test and use PostgreSQL**. The action must remain visibly disabled, including hover state, while the URL is empty; once the URL is non-empty the enabled/hover styling must be unambiguous.
- Validate the PostgreSQL connection and schema compatibility before persisting the choice. Do not create the administrator until the database choice is settled.
- If switching to PostgreSQL requires a process restart, show a prominent **Restart required** state with an exact next action: stop/start Web Fleet, reload the page, then create the administrator account.
- After restart/reload, the auth gate must explicitly say **Create the administrator account** rather than looking like an ordinary sign-in form.
- Once a deployment contains application/admin data, database-provider switching must not remain casually available from the browser setup flow. Later migration tooling is a separate deliberate operation.
- Support non-interactive/server-managed configuration through `WEBFLEET_DATABASE_URL` for operators who provision configuration before first launch.
- Add a pure setup-state contract/regression suite, similar in spirit to Trestle's database setup state machine, covering SQLite, PostgreSQL URL empty/non-empty, persisted provider, restart-required and post-restart administrator-creation transitions.
- Run the full PostgreSQL behavioural/integration suite against a real PostgreSQL server during CP30 public-preview hardening, proving fresh setup, restart, migration, backup/recovery expectations and SQLite/PostgreSQL behavioural parity.

**Exit:** an ordinary user can choose SQLite or PostgreSQL before creating the first administrator, cannot accidentally proceed with an untested PostgreSQL URL, receives unmistakable restart instructions when required, and lands back on an unmistakable administrator-creation screen after restart.

### CP20 - Retention and maintenance [COMPLETE]

- Check-history retention/compaction.
- Analytics raw-event retention.
- Database maintenance jobs.
- Disk-usage visibility and guardrails.

**Phase 4 exit:** ordinary self-hosters can install, update, back up, restore and operate Web Fleet confidently.

## CP11-CP20 ordering review

The sequence remains sound after implementation. Performance and Audit needed to precede analytics so browser-derived and server-derived measurements stayed distinct. Analytics property/storage/dashboard/events formed one coherent block. Backup/restore and the Linux service lifecycle correctly preceded the larger-database path. PostgreSQL storage and first-run database selection are complete before enterprise identity work; CP21+ preserves both storage modes. Live PostgreSQL parity remains a CP30 release-hardening gate. CP20 retention belongs before multi-user scale because disk growth is already a concern for monitoring and analytics.

No checkpoint is being promoted ahead of CP21. The next block should start with users/organizations/RBAC, then API tokens and OIDC. CP19 is complete at the implementation checkpoint level. Live PostgreSQL integration/parity execution remains explicitly required by CP30 and must not be waived.

## Phase 5 - multi-user, agency and enterprise scale

### CP21 - Users, organizations and RBAC [COMPLETE]

- Multiple users.
- Organization membership.
- Roles/permissions scoped to organizations/groups/sites.
- Agency/client-friendly grouping.
- Audit logs for privileged actions.

### CP22 - API and tokens [COMPLETE]

- Documented API for site/monitor/reporting workflows.
- Scoped API tokens.
- Rotation/revocation.
- Rate limiting and auditability.

**CP30 wiring review:** scoped API tokens are persisted, hashed and revocable, but no HTTP route accepts token authentication yet (`apitokens.Authenticate` is exercised only by its unit test). Rate limiting is not implemented. CP22 reached its implementation checkpoint; wiring a deliberate token-authenticated API surface and proving scope enforcement, revocation, organization isolation and rate limiting remain CP30 obligations.

**Post-Campaign-4 truth:** a deliberate API-token surface is now wired. Routes declare token scopes in `docs/hardening/route-inventory.json`; `Authorization: Bearer` authentication grants exactly the token's scopes with the token's organization as the acting boundary; unknown/revoked/malformed tokens and missing scopes are denied; tokens cannot reach session-only routes; secrets are hashed at rest and returned only at creation; `last_used_at` is tracked. Rate limiting for login/setup landed in Campaign 3. See `docs/hardening/integrations.json`.

### CP23 - SSO/OIDC [COMPLETE]

- OIDC integration.
- Safe account linking/provisioning policy.
- Local-admin recovery path.
- Enterprise configuration documentation.

### CP24 - Worker separation and scale tests [COMPLETE]

- Optional scheduler/check worker processes.
- Optional independent analytics ingestion process.
- PostgreSQL-backed coordination.
- Load/stress tests for hundreds/thousands of sites.
- Preserve the one-binary integrated deployment as the default.

**CP30 wiring review:** the optional `serve`/`worker`/`analytics-ingest` process roles exist, but the scheduler has no claim/lease mechanism, so two worker processes would both schedule the full fleet and produce duplicate checks, crawls and incidents. "PostgreSQL-backed coordination" is not yet implemented; proving single-owner scheduling (or adding a claim/lease) is a CP30 concurrency obligation, not current behaviour.

**Post-Campaign-5 truth:** the scheduler now uses a database-backed claim/lease (`job_leases`, migration 26) with a unique owner identity, expiry and reclamation, proven equivalent on SQLite and PostgreSQL and exercised by two-worker adversarial tests.

### CP25 - High availability and larger ingestion decision gate [COMPLETE]

Measure real workload first. Only add queues, specialized analytics storage or HA coordination when evidence shows PostgreSQL/in-process buffering is insufficient.

**Exit:** document the measured limit that justified each added component. Current decision: no additional distributed component is justified; `SCALE.md` records the thresholds and CP30 measurement campaign.

## CP19/CP21-CP25 ordering review

Completing CP19 before enterprise identity was correct: the first-run database contract now exists before organizations/RBAC expand the data model. CP21 RBAC then establishes the authorization boundary used by CP22 API tokens and CP23 OIDC. CP24 process separation follows identity/storage so split processes do not invent a second product model. CP25 deliberately ends this block with a **no new infrastructure yet** decision rather than adding queues/HA without measurements.

The next checkpoint remains CP26 deployment observations. CP30 is the appropriate battle-hardening campaign for live PostgreSQL parity, OIDC provider interoperability and measured 100/1,000/10,000-site scale evidence.

## Phase 6 - integrations and release readiness

### CP26 - Deployment observations [COMPLETE]

- GitHub/webhook/API ingestion of external deployment events.
- Correlate deployments with uptime/performance/link/traffic changes.
- Web Fleet observes deployments initially; it does not become the deployment platform.

### CP27 - Notifications and integrations [COMPLETE]

- Additional notification transports based on user demand.
- Webhooks.
- Clear retry/delivery history.
- Secret handling and redaction tests.

**CP30 wiring review:** webhook CRUD and a delivery primitive exist, but no product event invokes delivery yet (`notifications.Deliver` has no callers). Webhooks will not fire until incident/check transitions are wired to delivery, and retry/signature/redaction behaviour needs end-to-end tests. CP27 reached its implementation checkpoint; wiring and proof remain CP30 obligations.

**Post-Campaign-4 truth:** webhook delivery is wired product behavior. Incident open/recover transitions write outbox rows atomically with the incident state; a background worker delivers with guarded outbound networking (public-only, dial-time re-check, no redirects), HMAC signatures, bounded retries/timeouts/output and a concurrency limit; disabled destinations never receive events; delivery history is visible. See `docs/hardening/integrations.json`.

### CP28 - Accessibility, mobile and large-fleet UX [COMPLETE]

- Keyboard navigation and screen-reader review.
- Responsive/mobile fleet management.
- Search/filter/tag/group workflows proven at large site counts.
- No page-level dashboard overflow regressions.

**CP30 wiring review:** search, group filter, pagination and the mobile navigation work, but the tag-filter input is not wired to the server (`sites.ListByTag` exists; the dashboard tag field has no handler and its state is never initialised). Native `<dialog>` markup provides baseline focus handling, but no keyboard/screen-reader audit evidence has been recorded. CP28 reached its implementation checkpoint; tag-filter wiring and an accessibility audit remain CP30 obligations.

### CP29 - Hosting and deployment documentation [COMPLETE]

- Publish substantial hosting/deployment documentation alongside the application.
- Document direct VPS/systemd deployment, reverse proxies, TLS termination, firewall/listen-address expectations, upgrades, rollback, backup/restore and PostgreSQL deployment considerations.
- Provide dedicated Caddy and nginx examples.
- Document the recommended company subdomain pattern, for example `webfleet.company.com`, including DNS, reverse proxy and HTTPS setup.
- Include a step-by-step **Set up Web Fleet on a subdomain** walkthrough starting from ownership of `company.com`: create the DNS record, configure `webfleet.company.com`, reverse proxy it to Web Fleet's private listen address, obtain/verify HTTPS, test `/healthz`, then load first-run setup.
- Show both Caddy and nginx variants for the subdomain walkthrough and explain common DNS/TLS propagation failures.
- Explain that related self-hosted tools can live independently on sibling subdomains such as `trestle.company.com`, `cortex.company.com` and `watchpost.company.com`; do not imply that Web Fleet manages or requires those products.
- Cover analytics tracker origin/CORS implications when the monitored website and Web Fleet live on different domains.
- Cover Chromium/browser requirements separately for manual Audit so ordinary monitoring deployments do not accidentally install heavyweight browser dependencies.
- Include deployment troubleshooting for 502/504 errors, TLS/certificate problems, DNS propagation, proxy headers, database connectivity and service permissions.

**Exit:** an operator can go from a fresh server and company domain to a correctly proxied HTTPS Web Fleet deployment using only the public documentation.

### CP30 - Public-preview hardening [READY FOR DEEPSEEK/CORTEX]

- Threat model and SSRF review. `SECURITY.md` defines the adversarial handoff.
- Fuzz/property tests for URL/parser/security boundaries. Initial netguard fuzz target is present; adversarial expansion remains part of the handoff.
- Fresh install and recovery rehearsal.
- SQLite and PostgreSQL matrix.
- Cross-platform application builds.
- Release provenance/checksums.
- Documentation/public website audit against actual shipped behaviour.

**Campaign 1 (complete):** project-truth correction and the identity/RBAC foundation. CP30 confirmed that RBAC was decorative (only four handlers consulted it), the fresh-install first administrator had no organization membership, organization ids were hard-coded in user-facing queries, and the first-admin setup path was not race-atomic. Campaign 1 repaired all of these: first-admin user + owner membership are now created atomically with a concurrency guard; route-level RBAC is enforced from one route table; site/group/list/fleet and audit-batch data paths filter by the acting organization resolved from membership; and the first-run restart-required state survives reload. The route/permission inventory lives in `docs/hardening/route-inventory.json`, is enforced by a route-inventory contract test that runs in isolation, and records the policy decision that operators may archive sites but only admin/owner may permanently delete them.

**Campaign 2 (complete):** the Audit/SSRF boundary. The previous browser Audit launched Chromium with `--no-sandbox` against an unguarded URL, giving Chromium a DNS/network path the Go-side guard never saw. Campaign 2 replaced that with a guarded-proxy architecture: Chromium is pinned to an in-process forward proxy (`--proxy-server`, `--proxy-bypass-list=<-loopback>`) that applies the public-network guard to every CONNECT and HTTP request, re-resolves at dial time (blocking DNS rebinding, including mixed public/private answer sets), and never follows redirects (each hop is re-validated). The browser sandbox is required by default with `--no-sandbox` only via explicit `WEBFLEET_AUDIT_SANDBOX=allow-no-sandbox`; per-audit timeout, bounded DOM output and a global concurrency semaphore bound resource use. The same fail-closed dial invariant hardens the shared monitor/crawler/TLS dialer. Evidence: `docs/hardening/audit-boundary.json`, `internal/audit/proxy_test.go`, `internal/audit/browser_test.go` (including a real-Chromium test proving traffic flows through the proxy).

**Campaign 3 (complete):** authentication, trusted proxy and OIDC. An explicit trusted-proxy model (`WEBFLEET_TRUSTED_PROXIES`) makes secure cookies, OIDC redirect URIs, externally generated URLs and client identity honor `X-Forwarded-Proto`/`X-Forwarded-For` only from configured trusted peers and ignore them from untrusted peers. Login and first-run setup are throttled per resolved client address with a bounded-memory fixed window. OIDC now uses `github.com/coreos/go-oidc` for standards-compliant discovery, keyset retrieval and ID-token verification (signature, issuer, audience, expiry), enforces one-time state consumption and nonce equality, requires a verified email, and keeps local password login as an independent recovery path. `[closure]` Each OIDC transaction is browser-bound via a short-lived HttpOnly SameSite=Lax cookie consumed atomically with the state (`DELETE ... WHERE state AND browser`), so a different browser can neither log in nor destroy the legitimate browser's transaction; the callback origin is canonical and fail-closed, coming only from `WEBFLEET_PUBLIC_URL` (required to enable/use OIDC). A standards-shaped local provider simulation covers the adversarial cases; real-provider interoperability remains an external CP30 gate.

**Campaign 4 (complete and reviewed):** API tokens and integrations. A deliberate API-token surface is wired through the route inventory (`tokenScopes`): Bearer authentication grants exactly the token's scopes with the token's organization as the acting boundary, tokens cannot reach session-only routes, secrets are hashed and returned only at creation, and unknown/revoked/missing-scope cases are denied; failed Bearer auth is throttled per trusted-proxy-resolved client address and error responses are single-JSON. Webhook delivery is real product behavior: incident open/recover transitions write an outbox atomically with the incident state **scoped to the site's own organization**, and a background worker delivers with guarded outbound networking, HMAC signatures with a stable `event_id`, bounded retries/timeouts/output and a concurrency limit; disabled destinations never receive events; the obsolete synchronous `Service.Deliver` was removed so the guarded worker is the only delivery boundary. See `docs/hardening/integrations.json`.

**Campaign 5 (approved and closed):** PostgreSQL parity, provider-aware backup and scheduler claim/lease. A real-PostgreSQL integration suite runs the product's storage paths against a live server (guarded by `WEBFLEET_TEST_POSTGRES_URL`) and caught two genuine dialect bugs (Go bools bound to INTEGER columns, and an unqualified conflict-update RHS); both are fixed at the shared database layer. Backup/restore is provider-aware: SQLite keeps its native path, PostgreSQL uses pg_dump/pg_restore with credentials passed via `PGPASSWORD` (never argv), temp-file security, bounded subprocesses, clean tool-absence detection and destructive-change rehearsals for both providers. `[closure]` The scheduler uses a fenced due/claim model (`scheduler_claims`, migration 27) with persistent `next_due_at`, unique owner, generation fencing token and `lease_until`; renewal and completion are owner+generation qualified and in-flight work is cancelled on ownership loss, with crash recovery at-least-once. Real-PostgreSQL parity now covers check/TLS/DNS/crawl/audit-history persistence, incident acknowledgement, scheduler claims and the full first-run database-selection lifecycle. Evidence: `docs/hardening/database.json`.

**Campaign 6 (approved and closed):** release portability and reproducibility. `go.mod`/`go.sum` are repaired and minimal: `go mod tidy` + `go mod verify` pass, and a clean checkout builds and tests with ordinary `go build ./...`/`go test ./...` (no `-mod=mod`). Password hashing is pure-Go Argon2id (`golang.org/x/crypto/argon2`), removing the cgo `libargon2` blocker; legacy libargon2 hashes verify unchanged (PHC migration fixtures). Linux/macOS/Windows amd64+arm64 cross-compile cleanly. systemd install creates the `webfleet` service account and data-dir ownership idempotently on a clean host. Release automation (`scripts/release.sh` + read-only exact-set `scripts/verify-release.sh`, CI `release-build` job with GitHub build-provenance attestations, and a read-only `scripts/verify-gh-release.sh` post-release verifier) produces and verifies the exact six-archive matrix with SHA-256 checksums and a provenance manifest; building and verification are separate responsibilities and nothing publishes a release or tag. The post-release verifier uses the real `gh attestation verify` policy interface (`--repo`, `--source-ref`, `--source-digest`, `--signer-workflow`) and the CI `release-build` job grants `attestations: write`. `[closure]` systemd `Install` rolls back cleanly on partial failure and the CI `systemd-lifecycle` job rehearses both rollback branches (existing binary restored / no existing binary removed) with install/idempotency/healthz/update/rollback/uninstall. **Native closure:** GitHub Actions run `33527521226` was green on `d153eac` — `test` (ubuntu/macos/windows), `race`, `crosscompile`, `systemd-lifecycle` and `release-build` all passed, with artifact attestations created for all six archives on that exact commit. Native CI during closure also exposed and drove correction of the canonical `/var/lib/webfleet` install path, first-start readiness (listener bind raced migrations), the Unix-only 0700 assertion, and the missing `/usr/sbin` in the injected systemd failure environment.

**Campaign 7 (approved and closed):** analytics is hardened as an intentionally public endpoint: the browser-tracker Origin contract now requires Origin to match the property (empty Origin is rejected unless the deliberate `WEBFLEET_ANALYTICS_SERVER_SIDE` mode is enabled); client identity uses the trusted-proxy-resolved address; unknown-property traffic is rate limited per client address and valid-property traffic per address+property with bounded-memory limiters (raw IPs never persisted); event kinds and payloads are shape-validated. Deployment deduplication now treats only non-empty `external_id` as an idempotency key via a partial unique index (migration 28) with a PG sequence sync, so empty-`external_id` events never collapse. Tag filtering is wired end-to-end (state, query param, pagination reset) and covered by combination/isolation tests. CP30 scale measurements at 100/1,000/10,000 sites are recorded in `SCALE.md`; the no-additional-infrastructure decision is unchanged.

**Campaign 8 (approved and closed):** the application frontend gained an accessibility pass (status live-region announcements, visible `:focus-visible` outlines, focus management on route changes, and dialog initial-focus moved to the primary field). A deterministic browser accessibility/interaction suite (`internal/server/a11y_test.go`, chromedp; guarded by `WEBFLEET_A11Y=1`, skipped under `-race`) covers the full browser contract: first-admin setup/logout/login through the real auth forms, add/edit-site and create-group dialogs, dialog initial focus + Escape/focus-return + focus containment/Tab cycling, site-detail navigation and heading/landmark structure, primary-navigation keyboard reachability, form-error live-region announcement, mobile-menu `aria-expanded` with keyboard open (focus enters navigation) and Escape close (focus returns to the toggle), 320px page-level overflow, and a 25-site large-fleet table/pagination regression (no page-level overflow, internal table scrolling, primary/filter/pagination controls in viewport, forward+backward pagination). Webhook evidence is end-to-end: `TestIncidentToWebhookDeliverySignature` drives incident open through the outbox worker to a real HTTP receiver and verifies the HMAC signature over the exact delivered body. `scripts/rehearse.sh` is a stranger-style rehearsal from a built archive covering SQLite and PostgreSQL setup/restart, incident open/ack/recover, backup/destructive-change/restore, and an artifact-derived update/rollback (second release produced by `scripts/release.sh`, checksum taken from that release's `SHA256SUMS`, verified archive, then rollback to the original artifact binary). Auth/setup-state endpoints send `Cache-Control: no-store`, and `TestFrontendSourceGeneratedEmbeddedSync` guards the Nift source/generated/embedded (`content` → `public` → `internal/server/web`) asset contract. **Crawler transparency (owner dogfood):** owner dogfood found that Web Fleet reported a Nift site as exactly "50 pages" because the bounded crawler silently stopped at its ceiling and presented the truncated crawl as a complete inventory. The defaults are now `MaxPages=500, MaxDepth=8, MaxLinksPerPage=1000` (same-site restriction, dedup, SSRF/private-network, redirect, body-size, timeout and bounded external-link protections all retained). A crawl result now distinguishes `pages_crawled`, `pages_discovered`, `page_limit`, `limit_reached` and `sitemap_urls_discovered` (persisted via migration 29), the UI shows "N crawled · M discovered" with a "Crawl limit reached" notice when applicable, `Crawl now` runs in the background with live polling (real `status: running` with crawled/discovered/current_url from the crawler, not fake JS progress), and concurrent crawls of one site are rejected deterministically via an in-memory claim. Regressions cover >50-page sites, the 500 ceiling with discovered>crawled, MaxDepth 8, >200 links/page discovery, duplicate-dedup, and the HTTP lifecycle (202 start, poll to terminal, 409 concurrent, re-accept after completion). A follow-up audit of the nift.dev crawl showed the count was inflated by non-pages: the crawler counted every linked same-host resource (34 static assets like `.css`/`.zip`/`.json`) as "pages crawled", and it followed documentation code-sample hrefs such as `href="$[item.url]"` and `@path(...)` as real links (10 URLs). The crawler now skips asset URLs (extension filter) and template-expression literals, and counts only HTML (or broken/errored) responses as pages. Re-crawling `https://nift.dev/` now reports: 114 pages crawled, 114 discovered, 65 sitemap URLs, limit not reached, 4,665 internal / 188 external links, 4 broken — the earlier "50 pages" was the old ceiling, and the 158 was the old ceiling plus asset/template-literal inflation; the real site has ~114 HTML pages (docs + top-level content ≈ the ~75 count, plus demo sub-sites and template previews the sitemap intentionally does not list).

The owner's ordinary-user dogfood and real external-provider OIDC interoperability remain outstanding CP31/CP30 gates.

**Campaign 5/6/8 closure corrections (final):** the scheduler claim/lease matrix is now provider-neutral and runs against both SQLite and real PostgreSQL (`internal/scheduler/claim_matrix_test.go`); an environment-provisioned startup test proves `WEBFLEET_DATABASE_URL` selects PostgreSQL through the real config path; `StateFor` reports the running provider for env-provisioned deployments; `scripts/verify-gh-release.sh` enforces the exact asset set, verifies all six archive attestations bound to repo/ref/source commit via the real `gh attestation verify` flags (missing/invalid/wrong repo/ref/digest/workflow = failure), and is proven by a mocked-`gh` contract test (`scripts/test-verify-gh.sh`); the CI `systemd-lifecycle` job now injects deterministic activation failures for both rollback branches. Campaign 8 closed with the mobile-menu focus-in/focus-return behavior, the browser-driven successful setup/login flow, the large-fleet overflow regression, and the Nift source/generated/embedded frontend re-synchronized (the embedded copy had drifted).

**First-run/authentication rebuild (owner dogfood):** the owner's ordinary-user dogfood on the real application found a release blocker in the first-run/auth path: database selection and administrator creation were blended into one form, a failed boot request could leave the shell on the eternal "Loading..." state, and the PostgreSQL chooser control was visually broken. The frontend was rebuilt as a real two-stage flow — **Stage 1 Database** (SQLite / PostgreSQL with URL and a proper "Test and use PostgreSQL" button that always reads as a button, disabled state recognizable, no layout overlap; SQLite needs no artificial test step) then **Stage 2 Administrator** (email/password, created only after the database decision succeeds). A successful administrator creation transitions immediately to the authenticated dashboard via the `/api/setup` response — no refresh. `boot()` now has deterministic states (loading, setup-database, restart-required, setup-administrator, login, dashboard, boot-error) and any failed boot request ends in an actionable error with Retry instead of an indefinite loading screen. A follow-up dogfood run then exposed an internally contradictory state: the chooser, restart notice and auth form could present together and submit as login against the old running database. The state machine is now strictly mutually exclusive (`setStage` renders exactly one panel), and a committed PostgreSQL choice pending a restart is reported by `/api/setup/database` **independent of whether an administrator already exists in the running database**, so a pending database transition always shows only the restart notice — never login/setup/dashboard against the old database. `boot()` checks the transition state before session auto-login. A further dogfood run exposed why the earlier "green" state-machine tests still contradicted the real browser: the tests asserted the DOM `hidden` property, but author CSS rules like `.auth-stage{display:grid}` and `.dashboard{display:grid}` override `hidden`, so panels painted despite `hidden=true`. The canonical stylesheet now enforces `[hidden]{display:none!important}` as an application-wide invariant, and every first-run/dashboard visibility assertion measures **real rendered state** (computed display/visibility + nonzero painted box), with an exact-screenshot regression that fails if more than one first-run panel is ever painted in a frame and an initial-load test proving nothing but "Loading..." renders before boot resolves. New production-path browser regressions (`internal/server/lifecycle_test.go`) start the application through the real `config.Load -> store.Open -> New -> TCP listener` path and drive the real UI for clean SQLite and env-provisioned PostgreSQL: database stage → administrator stage → immediate authenticated transition → logout → login → process restart → re-login (cookies cleared), the interactive PostgreSQL chooser (invalid URL inline error; valid URL commits and shows restart-required), and the boot-error/Retry state.

**Crawler site inventory (owner dogfood follow-up):** the crawler now records distinct resource classes rather than discarding non-pages: HTML pages (crawled/discovered/sitemap/failed sets kept separate via per-page `kind`/`origin`/`ok`, migration 30) plus unique asset inventories per class (`css`, `javascript`, `image`, `font`, `media`, `document`, `data/feed`, `other`). Assets are classified by URL extension when available and by authoritative response Content-Type for extensionless resources, are counted as unique normalized URLs (repeated references never inflate the count), are never pages_crawled, and are never enqueued for crawling (bounds preserved). The site-detail panel is now a **Site inventory** view: pages crawled/discovered/in-sitemap, sitemap-coverage details (discovered-not-in-sitemap, sitemap-only, sitemap-failed — each expandable to the actual URLs), and per-class asset counts. Live progress remains "N pages crawled · M pages discovered". A review then found the asset inventory only parsed `href=`, so normal `<script src>`/`<img src>`/`srcset` resources were invisible (Nift showed 0 JS / 2 images). Resource discovery now recognizes `<a href>` navigation links (the only thing counted in `internal_links`/`external_links`) separately from real resource markup: `<link rel=stylesheet/icon/manifest/preload/prefetch href>`, `src`/`poster` (script/img/source/video/audio) and `srcset` candidates — inventoried as unique per-class assets, never as pages. The sitemap counter was also corrected: `sitemap_urls` is now the exact count of unique HTML URLs obtained from sitemap data (the root is no longer pre-seeded as a sitemap URL, and known-from-another-source URLs still count), so the set arithmetic reconciles: `internal-only + sitemap-only + both == pages_discovered`. Re-crawling `https://nift.dev/` now reports: **111 HTML crawled/discovered, `sitemap_urls` = 66 (exact — matches the repo's 66 sitemap `<loc>` entries), 2 failed, limit not reached; assets 14 CSS / 18 JS / 7 images / 10 documents / 2 data / 5 other; navigation `internal_links` = 4,268 / `external_links` = 186**. The set partition is `internal-only = 45` (root + demo sub-sites `jsonic-website`/`minify-website`/`tscc-website`/`website-generator-benchmark` + template previews), `sitemap-only = 0`, `both = 66` — every sitemap page is reachable internally, and the 45 extra pages are the demo/template content the sitemap deliberately excludes. The Nift repo's own `check_agent_readiness.py` confirms: 65 tracked `.html` pages, 66 expected sitemap URLs, 66 unique sitemap `<loc>`s.

**Site-lifecycle + UI (owner dogfood):** site detail now offers **Archive / Unarchive** as the normal reversible action, and a destructive **Delete** lives inside the Edit/site-management dialog (not beside Check now), requires typing the site name to confirm, and transactionally deletes the site and all its owned records within the organization (the existing org-scoped `DELETE ... WHERE organization_id` + FK cascade). Select controls gained right-side padding so chevrons are not cramped, and pagination is now a vertically aligned centered `Previous · Page [ n ] of N · Next` control that wraps on narrow screens. **Notification rules and channels** (event-driven rules over the existing incident/outbox architecture; webhook + SMTP + SMS-provider channels; test-notification; no credential re-exposure) are recorded as a planned roadmap item after the current correctness work clears — not implemented here.

**Rendered-UX dogfood fixes:** owner dogfood found four rendered-UX defects now fixed as one focused correction. (1) The Add website dialog's top-right × did not close it — the close button was a default submit button whose submit was swallowed by the form's `preventDefault`, so the `method="dialog"` close never ran; the × buttons are now `type="button"` with explicit `dialog.close()` wiring, closing via ×, Escape and Save, with focus returning to Add website and the background interactive again (browser regression clicks the real × and asserts rendered disappearance + focus). (2) Select/dropdown chevrons were still cramped against the right border; selects now use `appearance:none` with a custom inset SVG chevron and roomy right padding (verified via computed style/geometry for the group filter). (3) The Analytics empty-state button is now stacked below the explanatory text (computed-geometry regression). (4) The application now serves the Web Fleet favicon (`web-fleet-mark.svg`, the same mark the public website uses) referenced from the application `<head>` and present in content/public/embedded (regression proves the reference and the embedded asset).

**Audit/Analytics usefulness (owner dogfood):** the Audit panel now shows a real persisted `Audit in progress…` state the moment Run audit is accepted (`audit_runs` gains a `running` status + `started_at`, migration 31; the run is backgrounded with a synchronous claim guard rejecting concurrent runs, and reloads keep the in-progress truth), with explicit complete/failed terminal states and a Retry; the "No audit findings." text has proper bottom breathing room. Analytics gained: (1) **Enable tracker** opens an install-code modal with the real `/wf.js` snippet (`data-webfleet` contract) plus Copy/Close and a permanent **Tracking code** button; (2) **Disable tracker** stops accepting/recording new events while preserving historical data and the property configuration; (3) two server-side-paginated breakdowns on the same 7-day window — **page views by normalized pathname** and **unique visitors by country** — 10 rows/page, descending, positive counts only. Privacy model (unchanged ethos): the anonymous visitor identity is **HMAC-SHA256 keyed by the per-instance secret over (fixed 7-day analytics bucket, normalized source IP)** — stable within the reporting period so a multi-day `COUNT(DISTINCT)` is a true unique-visitor estimate, rotating at the weekly privacy boundary so it is never a permanent tracking identity; the raw IP is never persisted and the user agent no longer fragments identity. The headline Visitors, the country breakdown and page views all derive from the same weekly-bucket pseudonym over the same 7-day window, and `/api/fleet/analytics?days=N` uses the same event-derived unique-visitor semantics for multi-day windows (an instance-wide identity observed on two properties counts once as one fleet visitor). The UI is explicit that this is a 7-day-window approximation: "Visitor identifiers rotate weekly for privacy. A visitor crossing the rotation boundary may be counted twice in the 7-day view." A boundary-crossing regression proves the same IP straddling the weekly boundary reports two pseudonyms within the 7-day window, which the documentation states. Country is resolved at ingestion time into a coarse code only, and the local GeoIP database lifecycle is now managed by Web Fleet itself: it uses the **DB-IP Lite country dataset (CC BY 4.0)** — freely redistributable, no registration — downloaded into the data directory (`WEBFLEET_GEOIP_URL`, default the DB-IP free CSV; `WEBFLEET_GEOIP_AUTO_UPDATE`, default on), validated before an **atomic swap** (a failed/corrupt update keeps the previous database), with `last-updated` status and gzip support; the Analytics panel shows "Country database active · updated <date> · N ranges" or a one-click **Install country database** action, with the required **DB-IP attribution** ("IP geolocation data by DB-IP" linking to https://db-ip.com) shown wherever geography is exposed — DB-IP's CC BY 4.0 license makes a link-back a condition of using the free dataset in a web application, an obligation recorded here so it is not accidentally removed. Auto-update refreshes a missing **or stale** (older than the 30-day refresh interval) database in the background while keeping the previous database active on failure; `WEBFLEET_GEOIP_AUTO_UPDATE=false` loads an existing database with no automatic network activity. Downloads are decompressed before being persisted as plain `.csv` so the database survives a restart. Manual path configuration is no longer the primary UX. Visitor IPs never leave the server.

**Actionable monitoring evidence (owner dogfood):** the owner-dogfood principle "if Web Fleet displays a problem count, the administrator must be able to find the problem" drove five corrections: (1) the tracking-code modal width now fits its content (scrollable snippet); (2) the Analytics headline visitors/pageviews are compact left-aligned metric columns (not distributed across the card); (3) the country GeoIP unavailable state is now operational — the panel offers Install/Update with an explanation of the DB-IP Lite source and the local-only privacy contract; (4) failed crawl pages are inspectable — the inventory's failed-pages count is singular/plural correct ("1 page failed" / "N pages failed") and expands to the URL + real reason (HTTP status or fetch error) per page; (5) broken links are no longer a dead-end number — the inventory renders a Source/Target/Result table (internal/external · HTTP status/error) so the site-level BROKEN LINKS metric leads to the evidence. Page-crawl failures and broken-links-discovered-while-fetching-ok remain distinct diagnostics.

**`webfleet service` CLI (cross-project operator contract):** Web Fleet ships the same hardened service-management family as Cortex/Warden/Trestle/Watchpost — `install`, `uninstall`, `start`, `stop`, `restart`, `status`, `enable`, `disable`, `logs`, `update`, `rollback` — but deliberately keeps the **systemd system-unit** architecture (a cross-project comparison confirmed the user-unit model suits personal dev tools while a persistent self-hosted server needs a system unit): the unit lives at `/etc/systemd/system/webfleet.service`, the binary at `/usr/local/bin/webfleet`, data at `/var/lib/webfleet` owned 0700 by a dedicated `webfleet` nologin account, listening on the loopback default (`127.0.0.1:7336`) behind the operator's reverse proxy, configurable per the shared host/port pattern (`--host`/`--port` flags, `WEBFLEET_HOST`/`WEBFLEET_PORT` env, legacy `--listen`/`WEBFLEET_LISTEN` retained, CLI > env > default, an explicit host/port recorded in the unit ExecStart so the runtime listener survives restart/reboot), and **boot-safe without any login or linger**. The managed unit carries a `# Managed by webfleet.` marker plus structural validation (required `[Unit]/[Service]/[Install]` directives, `ExecStart`, `User`, `WEBFLEET_DATA_DIR`, `WantedBy`): **every** service verb — including `update` and `rollback` — refuses a missing/foreign/malformed/stale unit at that path before touching the binary or restarting anything. `status` reports not-installed / disabled+stopped / enabled+stopped / enabled+running / failed / stale / foreign states with unit, binary, user, data, listen, enabled/active, pid and a live health result; `enable`/`disable` control boot activation independently of running state; install is idempotent (byte-identical unit **and** executable + enabled + active is a genuine no-op) and a **changed executable triggers a restart** even when the unit text is unchanged; on reinstall it snapshots prior enabled/active state and, on any failure, restores the **exact prior state (negative included)**, restoring the old binary **before** re-activating the service so a running service is never restarted on the failing binary. Paths and values are systemd-quoted and control characters are rejected; per-command CLI arguments are validated (no stray positionals/flags, explicit messages); service commands dispatch **before** application-config load so they stay usable when runtime config is unhealthy. `update` and `rollback` **preserve the prior operational state**: an active service is restarted on the new binary, a deliberately stopped service stays stopped (never silently started), a failed activation of an originally-running service stops the new binary, restores the old one and re-activates it, and enablement is never touched. A successful `restart` exit code is not trusted as proof of activation: after updating an active service, Web Fleet **polls a bounded window** for the service to be active and its `/healthz` to succeed. If the new version fails to activate or become healthy, recovery is **verified, not best-effort**, and it is unified across both failure branches (initial-restart failure and health failure): it stops the failed service, restores the old binary, re-activates and re-verifies health, and surfaces a combined "update failed + recovery also failed" error if any recovery step fails. Recovery uses the same fail-closed prior-state marker semantics as rollback (no guess-to-active), and once verified recovery completes it consumes both temporary rollback artifacts so no stale `.rollback`/`.prior-active` remains. Prior-state capture is **transactional and fail-closed**: `update` aborts (before touching the binary) if it cannot determine the current active state or cannot persist the rollback-state marker. The rollback binary **and** the prior-active marker are retained after a successful active update, so a later manual `service rollback` restores both the old binary and its operational state; the metadata is consumed only after a successful rollback. `rollback` refuses a missing/invalid marker rather than guessing. `uninstall` surfaces a failed stop/disable rather than pretending success, then removes the unit and lifecycle artifacts while **preserving `/var/lib/webfleet`** (SQLite/PostgreSQL data, analytics, audit history) and the binary, and never removes the `webfleet` account (avoiding UID-orphan hazards on retained data). Root is required for install/uninstall/start/stop/restart/enable/disable/update/rollback; `status` and `logs` are read-only. The real CI systemd-lifecycle rehearsal exercises the full sequence (install, daemon-reload, enable/start, healthz, status, stop/start/restart, disable/enable, idempotent reinstall, verified update, rollback, stop, uninstall, data preserved) plus deterministic activation-failure injection with both rollback branches.

### CP31 - Stable public preview [BLOCKED ON CP30]

**Planned (roadmap only, not yet implemented) — notification rules and channels:** first-class notification rules feeding from the existing event/incident + transactional webhook outbox architecture, rather than coupling delivery into monitors. Initial event candidates: `site.unhealthy`, `site.recovered`, `dns.changed`, `tls.expiring`, `tls.invalid`, `headers.changed`, `links.broken`, `deployment.observed`, `audit.regressed`. Rules scopeable to all sites, groups or individual sites with repeated-notification suppression while a condition is unchanged (e.g. one alert on entering unhealthy, one on recovery, no spam while it stays down). Initial channels: the existing guarded webhook, provider-neutral SMTP email (host/port/user/password/from/TLS — self-hosting friendly, works with SES/Mailgun/Postmark), and an SMS channel abstraction behind a provider interface (initially a Twilio-compatible HTTP API) so providers are swappable. Include a test-notification action and never expose notification credentials after creation. Implementation checkpoint: after the present owner-dogfood correctness work clears; not part of the current crawler/UX correction.

- Signed/tagged release. Do not create it until every `RELEASE.md` evidence gate passes.
- Install/update instructions tested by an ordinary-user dogfood pass.
- Public website points only at real release artifacts and truthful features.
- Known limitations published.

## Explicitly deferred

Do not pull these forward without a strong product reason:

- website hosting;
- DNS management;
- CDN/proxy service;
- deployment execution/PaaS;
- session replay;
- heatmaps;
- invasive visitor fingerprinting;
- arbitrary product-analytics cohorts;
- advertising attribution stack;
- host CPU/RAM/disk monitoring (Watchpost territory);
- mandatory agents;
- mandatory distributed infrastructure for small installs.

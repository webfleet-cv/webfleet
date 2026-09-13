# Web Fleet handover

## Shared operation campaign

Webfleet follows `gantry-core/docs/CLI_API_CLUSTER_ROADMAP.md`. Phase 1 CP8 adopts the v0.1.1 contract for site listing, creation and archival. Its CLI names are reserved, not marked implemented; Phase 5 must wire and runtime-observe them before executable coverage is advertised.

## Frontend asset ownership

Nift tracks and builds HTML pages only. CSS, JavaScript, images, icons and other
static assets are canonical in the generated web root (`public/`, `web/dist/`
or the repository's embedded-public directory). Edit those files directly.
Do not recreate asset copies under `content/`, do not add asset entries to
`.nift/tracked.json`, and do not let a Nift build overwrite them. After changing
HTML templates or content, run Nift and verify that direct assets are unchanged.

This is a living handover. Update it whenever implementation, architecture, product scope, repository state, verification requirements, or the next development checkpoint changes.

## Product

Web Fleet is a self-hosted website monitoring and analytics platform.

Its job is to answer, from one dashboard:

> What is happening across all of my websites, and what needs my attention?

Web Fleet is aimed at a single self-hoster or freelancer first, while keeping an architecture that can scale to agencies and enterprise web estates without replacing the product.

The product observes websites. It does not host them and should not become a general PaaS, DNS provider, CDN, or infrastructure manager.

## Product principles

1. **Useful in five minutes.** A user should be able to install one binary, create the first admin, add a URL, and see useful monitoring without deploying an agent or modifying the website.
2. **One site to thousands.** Small installations stay simple. Scale features must not make the small deployment miserable.
3. **Monitoring first.** Uptime, response behaviour, TLS, DNS, links, headers, performance, manually triggered browser-rendered audits and change history are the core product.
4. **Analytics is first-class but optional.** Public checks work without site changes. Analytics begins only after the operator installs the lightweight tracker.
5. **Privacy by default.** Do not collect visitor data merely because other analytics products do. Avoid persistent raw IP storage, fingerprinting and unnecessary cookies.
6. **Actionable dashboard.** Prefer "what needs attention" over walls of charts.
7. **Self-hosted ownership.** Configuration, backups, upgrades, rollback and data export must remain understandable.
8. **Simple default, scalable internals.** SQLite and an integrated process are valid defaults. PostgreSQL, split workers and larger ingestion paths can be added without changing the product model.
9. **No fake enterprise complexity.** RBAC, SSO, audit, retention and scale controls should appear when they solve real organizational requirements.
10. **Truthful public claims.** Documentation and the public website must distinguish shipped functionality from planned functionality throughout development.

## Initial technical direction

- Go application server and workers.
- SQLite default storage. Use `database/sql` with the cgo-free `modernc.org/sqlite` driver, matching Trestle's proven SQLite pattern. Keep SQLite at one owned connection, enable WAL, enforce foreign keys, use a five-second busy timeout, secure the data directory to `0700`, and make schema migrations transactional and fail-closed.
- PostgreSQL supported before broad production positioning.
- Nift-built HTML/CSS/JavaScript dashboard with vanilla JavaScript unless a concrete requirement justifies another frontend stack.
- Background scheduler for remote checks.
- Optional browser audit worker for manually triggered rendered performance/accessibility/best-practice/discoverability evaluations; basic monitoring must not require Chromium.
- HTTP/HTTPS checks performed agentlessly from the Web Fleet server.
- Analytics ingestion exposed as a separate HTTP endpoint inside the same application initially.
- Analytics subsystem kept architecturally separable from monitoring/crawling.
- One deployable binary for the normal installation.
- Optional process separation later for large installations.

Do not introduce Redis, Kafka, ClickHouse, Kubernetes, a separate frontend framework, or a service mesh into the default architecture without measured need.

## First-run database setup contract

Web Fleet supports SQLite and PostgreSQL, but database choice is part of **first-run setup**, not an environment-variable-only implementation detail.

Follow the Trestle-proven UX shape:

1. Before the first administrator exists, show the database choice.
2. SQLite is selected by default and requires no connection string.
3. Selecting PostgreSQL reveals the PostgreSQL URL and **Test and use PostgreSQL** action.
4. An empty URL keeps that action visibly disabled in every interaction state. A non-empty URL makes the enabled state visually clear.
5. Test the real connection before accepting PostgreSQL.
6. If applying PostgreSQL requires restarting Web Fleet, replace the setup form with a prominent restart-required message that tells the operator to restart Web Fleet and reload.
7. After restart, return to a page explicitly headed **Create the administrator account**. Do not make first-admin creation look like login.
8. Do not allow casual provider switching after the deployment contains administrator/application data.
9. `WEBFLEET_DATABASE_URL` remains available for non-interactive provisioning, but the ordinary-user dashboard flow must not require editing environment variables.

Keep the database-selection state machine pure/testable so the empty URL, enabled URL, restart and post-restart transitions can be regression tested without a browser.

## Core domain model

Keep these concepts explicit even when the first UI hides unnecessary hierarchy:

- **Organization** - ownership and access boundary. A single-user install can use one implicit organization.
- **Group** - optional organization of related sites, such as a client, team, product or portfolio.
- **Site** - a website Web Fleet monitors.
- **Environment** - production, staging, preview or another deployment context where needed.
- **Domain** - hostnames associated with a site.
- **Monitor** - an individual check definition.
- **Check result** - one observed monitor execution.
- **Incident** - a meaningful period of degraded or failed service.
- **Analytics property** - opt-in event collection associated with a site.
- **Analytics event** - a privacy-limited pageview or custom event.
- **Deployment event** - observed release/deployment metadata, initially from external integrations rather than deployment control.

Do not collapse site, domain and monitor into one record. A site can have multiple domains and multiple checks.

## Initial site experience

The fleet overview is the product centrepiece. It should answer these questions without drilling into individual sites:

- How many sites are healthy, degraded, warning or down?
- What needs attention now?
- Which problems are new?
- Which sites changed recently?
- Are there fleet-wide TLS, DNS, link, performance, audit or analytics anomalies?

A site detail view should eventually expose:

- Overview
- Uptime
- Performance
- Audit
- Pages and links
- TLS
- DNS
- Headers
- Incidents
- Analytics
- Deployments
- History
- Settings

Do not implement empty tabs merely because this list exists. Add a section when the underlying capability is usable.

## Monitoring contract

The first monitoring loop should support:

- HTTP status and request success/failure;
- response latency;
- redirects and final URL;
- timeout configuration;
- expected status/range;
- basic response metadata;
- retained check history;
- consecutive-failure handling before opening an incident;
- recovery and incident close;
- scheduler jitter so large fleets do not stampede at the same instant.

Monitoring failures must distinguish DNS failure, connection failure, TLS failure, timeout and unexpected HTTP response where possible.

## Website health expansion

After basic availability, add website-specific observations rather than generic host telemetry:

- TLS certificate validity and expiry;
- DNS record observation and change history;
- security/HTTP headers;
- crawl-based internal link health;
- external-link checks with conservative rate limits;
- redirects and redirect chains;
- sitemap and robots.txt discovery/health;
- page response/performance history;
- optional browser-rendered audits covering performance, accessibility, best-practice/security hygiene and technical discoverability;
- manual single-site and bounded batch audit execution, including simple fleet filters and optional advanced/regex targeting;
- latest audit results by default, with audit history/category-score regression tracking explicitly opt-in;
- basic metadata/structured-data checks where useful;
- regression/change detection.

Browser-rendered audits are a separate, heavyweight **manual** workload. They may use Chromium or another suitable browser engine, but basic monitoring, TLS/DNS checks and analytics ingestion must remain usable without a browser runtime. Audit history is opt-in rather than the default. Batch audits must resolve an explicit site set from selections/search/groups/tags or optional advanced/regex predicates, preview that scope before execution, and run through a bounded queue so they cannot starve availability monitoring. Do not claim Google Lighthouse compatibility unless Web Fleet literally executes and reports Lighthouse with a maintained compatibility contract; the product-facing feature/tab name is simply **Audit**.

## Analytics boundary

Analytics is part of Web Fleet's product, but keep the subsystem separable.

Initial analytics should target web analytics, not broad product analytics:

- pageviews;
- privacy-preserving visitor estimates;
- top pages;
- referrers/sources;
- country-level geography where feasible without retaining precise location;
- device/browser/OS classes derived conservatively;
- custom events;
- goals;
- realtime/recent activity;
- date-range filtering.

Default privacy posture:

- no cookies required;
- do not persist raw IP addresses by default;
- no browser fingerprinting;
- strip or allowlist sensitive query parameters;
- configurable raw-event retention;
- bot filtering;
- transparent documentation of collected fields.

Do not build session replay, heatmaps, arbitrary user profiling, ad-tech attribution or a PostHog replacement into the initial product.

## Scale path

The normal self-hosted deployment should remain:

```text
webfleet
  + SQLite
```

A larger installation may later become:

```text
webfleet serve
webfleet worker
webfleet analytics-ingest
  + PostgreSQL
```

The split must be an operational option, not a different product.

## Security baseline

Before public preview:

- password hashing with a modern memory-hard password KDF;
- secure session cookies;
- CSRF protection for state-changing browser requests;
- strict origin/CORS handling for analytics ingestion;
- site/property tokens that cannot grant dashboard access;
- request body and rate limits;
- SSRF protection for monitors and crawlers, including redirect revalidation;
- safe URL normalization;
- audit records for security-sensitive actions;
- backup/restore documentation and tests;
- least-privilege service installation.

Monitoring arbitrary URLs is an SSRF-sensitive feature. Treat private/reserved address handling, DNS rebinding and redirect destinations as security boundaries from the first implementation.

## Repository discipline

- Keep this file current after every substantial checkpoint.
- Keep `ROADMAP.md` current. Checkpoints may be split/merged as evidence changes, but do not silently delete unfinished obligations.
- Keep public documentation truthful about current maturity.
- Keep source and generated website repositories clean after website work.
- Do not commit secrets, analytics signing keys, test credentials or operator data.
- Prefer focused commits with tests/evidence for the behaviour changed.
- Treat database lifecycle as a contract: restart persistence, PRAGMA enforcement, future-schema refusal, migration-history integrity and migration rollback must remain covered by tests.
- Before declaring a checkpoint complete, run the relevant tests plus `git diff --check` and report the exact commit.

## Nift usage

Nift is the build-time templating/dependency layer for Web Fleet's frontend and public website. Use it for composition, tracked relationships and generated static assets where it helps. Use normal Go/JavaScript/CSS for application behaviour.

Use `@path` for internal tracked-page and local-asset relationships, and `@input` for shared reusable template fragments. Do not hand-maintain generated output.

## Current state

As of this handover revision:

- GitHub organization: `webfleet-cv`.
- Main application repository: `webfleet-cv/webfleet`.
- CP1-CP25 are complete in development. CP19 includes the Trestle-style first-run SQLite/PostgreSQL selection UX, and live PostgreSQL parity testing was completed as part of the CP30 battle-hardening work. CP21-CP23 add organizations/RBAC, scoped API tokens and OIDC; CP24 adds optional process roles; CP25 records the no-extra-distributed-infrastructure-yet decision.
- CP30 adversarial review and the release-hardening work are **complete**. It confirmed several implementation checkpoints were not yet wired/enforced when CP30 began: RBAC was consulted by only four handlers, the fresh-install first administrator had no organization membership, API-token authentication and webhook delivery had no callers, tag filtering was not wired in the dashboard, the scheduler had no claim/lease, and organization ids were hard-coded in user-facing queries. It also confirmed release blockers: an incomplete `go.sum`, a cgo `libargon2` password binding that breaks cross-platform builds, a systemd install that never creates the service account/ownership, and provider-agnostic backup/restore. These are recorded in `ROADMAP.md`, `SECURITY.md`, `SCALE.md`, `RELEASE.md` and the route inventory at `docs/hardening/route-inventory.json`.
- CP30 Campaign 1 (project-truth correction + identity/RBAC foundation) is **complete and reviewed**. It repaired: the fresh-install first-administrator membership bug, the first-admin setup race, and the reload-lost restart-required first-run state; and it enforced route-level RBAC plus organization isolation for the Campaign 1 API surface, backed by the machine-readable route/permission inventory at `docs/hardening/route-inventory.json` and adversarial viewer/operator/admin/owner server tests. Operators may archive sites but only admin/owner may permanently delete them.
- CP30 Campaign 2 (Audit/SSRF boundary) is **complete and reviewed**. The browser Audit no longer launches `--no-sandbox` Chromium at an unguarded URL. Chromium is pinned to an in-process guarded proxy that applies the public-network guard to every connection and re-checks the full resolution set at dial time (DNS rebinding blocked); the browser sandbox is the default with `--no-sandbox` only on explicit opt-in; execution timeout, bounded output and concurrency are enforced; Audit remains manual with opt-in history. Evidence: `docs/hardening/audit-boundary.json`.
- CP30 Campaign 3 (authentication, trusted proxy, OIDC) is **complete and reviewed**. An explicit `WEBFLEET_TRUSTED_PROXIES` model makes scheme, client identity, cookies and OIDC redirect URIs honor forwarded headers only from trusted peers; login/setup are throttled per resolved client address; OIDC verifies the ID token cryptographically (signature/issuer/audience/expiry) via `github.com/coreos/go-oidc`, enforces one-time state and nonce, requires verified email, and leaves local password login as the independent recovery path. `[closure]` OIDC transactions are browser-bound via a short-lived HttpOnly SameSite=Lax cookie consumed atomically with the state, and the callback origin is canonical and fail-closed, coming only from `WEBFLEET_PUBLIC_URL` (required to enable/use OIDC). Real-provider interoperability remains a post-release validation item.
- CP30 Campaign 4 (API tokens and integrations) is **complete and reviewed**. A deliberate API-token surface is wired through the route inventory (`tokenScopes`): Bearer tokens grant exactly their scopes within their own organization, cannot reach session-only routes, are hashed at rest and returned only at creation, and deny unknown/revoked/missing-scope cases; failed Bearer auth is throttled per trusted-proxy-resolved client address and error responses are single-JSON. Webhook delivery is real product behavior: incident open/recover transitions write an outbox atomically with incident state **scoped to the site's own organization**, and a background worker delivers with guarded outbound networking, HMAC signatures with a stable `event_id`, bounded retries/timeouts/output, no redirect-following, and disabled-destination filtering; the obsolete synchronous `Service.Deliver` was removed so the guarded worker is the only delivery boundary. CP22 and CP27 have moved from "implemented but unwired" to their post-Campaign-4 truth.
- CP30 Campaign 5 (PostgreSQL parity, provider-aware backup, scheduler claim/lease) is **complete and reviewed**. A real-PostgreSQL suite (guarded by `WEBFLEET_TEST_POSTGRES_URL`) exercises the product's storage paths against a live server, catching and fixing two dialect bugs at the shared database layer. Backup/restore is provider-aware (SQLite native, PostgreSQL pg_dump/pg_restore with PGPASSWORD-only credentials, bounded subprocesses, tool-absence detection, rehearsals for both). `[closure]` The scheduler uses a fenced due/claim model (`scheduler_claims`, migration 27) with persistent next_due, unique owner, generation fencing and lease_until; renewal/completion are owner+generation qualified, in-flight work cancels on ownership loss, and crash recovery is at-least-once. Real-PG parity now covers check/TLS/DNS/crawl/audit-history persistence, incident acknowledgement, scheduler claims and the first-run database-selection lifecycle. Evidence: `docs/hardening/database.json`.
- CP30 Campaign 6 (release portability and reproducibility) is **approved and closed** — native GitHub CI run `33527521226` was green on `d153eac` (test on ubuntu/macos/windows, race, crosscompile, systemd-lifecycle, release-build with attestations for all six archives on that exact commit). The module graph is repaired (`go mod verify` passes; clean-checkout build/test needs no `-mod=mod`); password hashing is pure-Go Argon2id with legacy libargon2 hashes verifying unchanged; Linux/macOS/Windows amd64+arm64 cross-compile; systemd install creates the service account and ownership idempotently and rolls back cleanly on partial failure across both rollback branches (existing binary restored / no pre-existing binary removed), rehearsed by the CI systemd-lifecycle job; release building and read-only verification are separate (`scripts/release.sh`, exact-set `scripts/verify-release.sh`, read-only `scripts/verify-gh-release.sh` using the real `--repo`/`--source-ref`/`--source-digest`/`--signer-workflow` interface, GitHub build-provenance attestations with `attestations: write`) and never publish. CP30 Campaign 7 (analytics hardening, deployment idempotency, tag filtering, scale) is **approved and closed**. Analytics enforces the browser-tracker Origin contract (server-side mode opt-in), uses trusted-proxy client identity, applies bounded per-address/property rate limiting (no raw-IP persistence) and validates event kind/payload shape. Deployment deduplication uses a partial unique index so empty `external_id` events never collapse and PG sequences are synced after the rebuild. Tag filtering is wired and tested end-to-end. Scale measurements at 100/1k/10k sites are recorded in `SCALE.md`; the no-new-infrastructure decision is unchanged. CP30 Campaign 8 (UX/a11y, docs, pre-release dogfood) is **approved and closed**. The chromedp browser suite (guarded by `WEBFLEET_A11Y=1`, skipped under `-race`) covers the full browser contract: browser-driven first-admin setup/logout/login, add/edit-site and create-group dialogs, dialog initial focus/Escape/focus-return/containment, site-detail navigation, primary-nav keyboard reachability, form-error live region, mobile-menu keyboard open (focus enters navigation) and Escape close (focus returns to the toggle), 320px page-level overflow, and a 25-site large-fleet table/pagination regression. Webhook delivery/signature is proven end-to-end, and the artifact rehearsal updates/rolls back between release artifacts (checksums from the release contract). Auth/setup-state endpoints send `Cache-Control: no-store` and `TestFrontendSourceGeneratedEmbeddedSync` guards the Nift source/generated/embedded asset contract. The owner's ordinary-user dogfood then found a first-run/auth release blocker, which was rebuilt: first-run setup is now a real two-stage flow (Stage 1 Database — SQLite or PostgreSQL with URL and "Test and use PostgreSQL"; Stage 2 Administrator — created only after the database decision succeeds, with an automatic authenticated transition and no refresh needed), `boot()` has deterministic states with an actionable boot-error/Retry instead of an eternal "Loading...". A further dogfood run exposed a contradictory state where the chooser, restart notice and auth form could appear together and submit as login against the old running database; the first-run state machine is now strictly mutually exclusive (exactly one panel per state), a pending PostgreSQL transition is reported independently of whether an administrator already exists in the running database (so only the restart notice is shown while a switch is pending, never auth/dashboard against the old database), and `boot()` checks the transition state before session auto-login. The earlier green state-matrix tests measured the DOM `hidden` property, which author CSS `display` rules override; the canonical stylesheet now enforces `[hidden]{display:none!important}` and the browser assertions measure real rendered visibility (computed display/visibility + nonzero painted box), with a screenshot regression that fails if more than one first-run panel is ever painted at once. New production-path lifecycle regressions (`internal/server/lifecycle_test.go`) drive the real `config.Load -> store.Open -> New -> TCP listener` server through clean SQLite and env-provisioned PostgreSQL first runs, logout/login, process restart, and re-login, plus the interactive PostgreSQL chooser and the boot-failure state. A crawler-transparency dogfood correction raised the bounded defaults to `MaxPages=500, MaxDepth=8, MaxLinksPerPage=1000` and stopped presenting a truncated crawl as a complete inventory: crawl results now expose `pages_crawled`, `pages_discovered`, `page_limit`, `limit_reached` and `sitemap_urls_discovered` (migration 29), the site page shows "N crawled · M discovered" plus a crawl-limit notice, `Crawl now` runs in the background with live polling of real crawler state, and concurrent crawls are rejected deterministically. A follow-up audit showed the initial re-crawl count was inflated: linked assets (`.css`/`.zip`/`.json`) and documentation code-sample literals (`$[item.url]`, `@path(`) were counted as pages. The crawler now excludes asset URLs and template-expression literals and counts only HTML (or broken) responses as pages; re-crawling nift.dev reports 114 pages crawled / 114 discovered / 65 sitemap URLs with no limit reached (the old "50 pages" was entirely Web Fleet's ceiling; the sitemap lists the ~65 main content URLs while the additional ~49 are demo sub-sites and template previews the sitemap intentionally omits). A site-inventory layer now keeps HTML pages and asset classes distinct (per-page kind/origin/ok, unique per-class asset counts classified by extension and Content-Type, migration 30), with a Site inventory panel exposing sitemap-coverage mismatches (expandable to the actual URLs) and per-class asset counts. The inventory now separates `<a href>` navigation links (the only thing counted in internal/external link metrics) from real resource markup (`link rel=stylesheet/icon/manifest/preload`, `script/img/source/video/audio` `src`/`poster`, `srcset`) inventoried as unique per-class assets, and `sitemap_urls` is the exact count of unique sitemap HTML URLs. A full nift.dev crawl reports 111 HTML pages (111 discovered, 66 in sitemap — exactly matching the repo's 66 `<loc>` entries, 2 failed), 45 discovered pages absent from the sitemap (confirmed as root + demo sub-sites and template previews), 0 sitemap pages unreachable internally, and assets 14 CSS / 18 JS / 7 images / 10 documents / 2 data / 5 other — so the Nift sitemap is not stale; the project's own agent-readiness check independently confirms 65 tracked `.html` pages == 66 expected sitemap URLs. Site detail now has Archive/Unarchive plus a name-confirmed destructive Delete in the edit dialog, select controls have roomier chevron padding, and pagination is a centered aligned Previous/Page n of N/Next control. A rendered-UX dogfood pass fixed four visible issues: the Add website dialog's × now actually closes it (the close button was a submit swallowed by the form's preventDefault; now type="button" with explicit close, plus Escape and Save), selects use an inset custom chevron with roomy right padding instead of a cramped native arrow, the Analytics empty-state button stacks below its text, and the application now references the Web Fleet favicon (the same mark the public website uses) served from the embedded frontend. An actionable-evidence dogfood pass made monitoring counts inspectable: the tracking-code modal fits its content, Analytics headline metrics are compact left-aligned columns, the country GeoIP state is operational (DB-IP Lite managed by Web Fleet with install/update and local-only lookup), failed crawl pages expand to URL + real reason with correct singular/plural grammar, and broken links render a Source/Target/Result table so the BROKEN LINKS metric leads to evidence. An Audit/Analytics dogfood pass added a persisted Audit-in-progress state (running/complete/failed with started_at, backgrounded with a concurrent-run guard), an Analytics install-code modal with the real tracker snippet plus Copy/Close and a permanent Tracking code button, a Disable tracker control that stops collection while preserving history, and server-side-paginated page-views-by-path and unique-visitors-by-country breakdowns on the 7-day window. The privacy model uses an HMAC-SHA256 anonymous visitor identity keyed by the per-instance secret over (fixed 7-day analytics bucket, normalized IP), stable within the reporting period (so headline, page and country unique-visitor counts are compatible), rotating at the weekly boundary, with no raw IP persisted; the UI documents the 7-day-window approximation (a visitor crossing the weekly boundary may count twice in the 7-day view) and fleet multi-day analytics use the same event-derived unique-visitor semantics as the site summary; country is resolved at ingestion into a coarse code only; the local GeoIP lifecycle is managed by Web Fleet using the DB-IP Lite country dataset (CC BY 4.0, no registration): downloaded into the data dir (decompressed and persisted as plain .csv so it survives restart), validated before an atomic swap (failed updates retain the previous database), auto-refreshed when missing or stale beyond a 30-day interval (no network for fresh databases; disabled via WEBFLEET_GEOIP_AUTO_UPDATE=false), with last-updated status, a one-click Install/Update in the Analytics panel, and the required DB-IP attribution link ("IP geolocation data by DB-IP") shown wherever geography is exposed (CC BY 4.0 link-back obligation). Web Fleet gained the full battle-hardened `webfleet service` CLI family (`install`/`uninstall`/`start`/`stop`/`restart`/`status`/`enable`/`disable`/`logs`/`update`/`rollback`) matching the sibling projects' operator contract while keeping the justified systemd system-unit architecture: `/etc/systemd/system/webfleet.service`, `/usr/local/bin/webfleet`, `/var/lib/webfleet` owned by the dedicated `webfleet` account, loopback default listen behind a reverse proxy, boot-safe without linger, managed-unit marker + structural validation refusing foreign/malformed/stale units across all verbs (including update/rollback), idempotent reinstall with a genuine no-op for identical unit+executable+enabled+active, changed-executable detection forcing a restart, exact prior enabled/running state restoration (negative states included) with the old binary restored before re-activation, systemd-quoted paths with control-character rejection, per-command CLI argument validation, service dispatch before config load, read-only status/logs, failure-surfacing uninstall, update/rollback preserving the prior operational state (stopped services stay stopped, active services are restarted), bounded health verification after an active update (restart-exit is not trusted; an unhealthy or non-starting new version is rolled back with verified, non-best-effort recovery unified across both failure branches and with metadata consumed after verified recovery), transactional fail-closed prior-state capture (update aborts if the state cannot be determined/persisted; rollback refuses a missing marker), rollback metadata retained after a successful update so a later manual rollback restores the prior binary and operational state, and `uninstall` preserving all data and the service account. Post-release validation/backlog: a real external-provider OIDC interoperability check (CP30) and a fresh owner's ordinary-user dogfood confirmation on a clean machine (CP31) remain as further validation work; they are not prerequisites that block the already-published release.
- The companion `webfleet-cv.github.io` source/generated workspace documents the current development state.

## Immediate next step

The CP30 adversarial review, the release-hardening campaigns, and the stable
`v0.1.0` public-preview release are complete. Development continues at **0.1.2**
on `main`.

Post-release validation/backlog (not release-blocking):

- Real external-provider OIDC interoperability check (CP30).
- A fresh owner's ordinary-user dogfood confirmation on a clean machine (CP31).

Continue development from the current state; the route/permission inventory at
`docs/hardening/route-inventory.json` remains the authorization contract and is
enforced by the route-inventory contract test.
## Current release state

- Released stable: **v0.1.1** (stable public preview).
- Current development: **0.1.2** on `main`. An ordinary development build
  reports 0.1.2 with commit `unknown`; release builds override the default via
  `-ldflags -X main.version` and are never confused with the released version.

# Release procedure

Web Fleet releases are produced from reviewed `vX.Y.Z` tags. Before tagging,
deploy any changed `install.sh`, `download.sh`, and `update.sh` to
`https://webfleet.cv`, fetch them back, compare exact bytes with the generated
repository, and run syntax plus fixture-based checksum and rollback tests.

Run formatting, the complete Go and race suites, vet, SQLite/PostgreSQL tests,
browser-audit tests, real systemd lifecycle, six-target cross-builds, release
verification, and a clean pushed-tree check. Rehearse first with an RC tag.
Verify exactly six archives plus `checksums.txt`, every checksum and GitHub
provenance against the tag commit. On a clean Linux host exercise public
download/install/update/rollback, SQLite and PostgreSQL first-run setup, one
website check, service lifecycle and an opt-in browser audit. Publish stable
only after approval, repeat the live installer smoke, and never mutate a tag or
overwrite an existing release asset.

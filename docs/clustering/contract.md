# Webfleet clustering contract

Webfleet clustering reuses the released `gantry-core` replication runtime and keeps Webfleet-specific fleet semantics in this repository.

## Consensus-owned first surface

The first clustered surface is deliberately bounded to fleet topology/configuration:

- groups: stable cluster identity, organization, name, creation time;
- sites: stable cluster identity, organization, name, canonical primary URL, group relation, enabled/archive state and timestamps;
- site tags;
- durable replication operation identity and applied position.

Numeric SQLite row IDs are node-local materialization details. Cross-node references use stable `cluster_id` values.

## Explicitly outside consensus

Authentication, users/sessions, API tokens, OIDC configuration, launcher state, Gantry pairing credentials, propagation policy/history, notification/webhook configuration and delivery, analytics properties/events/goals, maintenance configuration, checks, incidents, audit/crawl/TLS/DNS/performance observations, deployments, header expectations, GeoIP data, scheduler state and other external side effects remain node-local in this first campaign. Raft apply/replay must never execute checks, crawls, webhooks, notifications or other external effects.

Snapshot restore reconciles consensus-owned site/group rows in place so node-local observation/history rows attached to an existing clustered site are not destroyed merely by consensus recovery.

## Authority

- standalone: existing local mutation paths;
- replicated ready leader: semantic operation -> Raft -> FSM materialization;
- replicated ready follower: authenticated forward to leader -> commit -> wait for local apply;
- starting/catching-up/no-leader/unhealthy/shutting-down: reject; never fall back to local SQL.

Caller `Idempotency-Key` is propagated as the durable operation identity. Same identity with different semantic bytes is a caller conflict, not a second mutation.

## Storage and deployment boundary

The first clustered materialization is SQLite-only. Enabling replication with PostgreSQL fails closed at configuration load. Production replication requires cert/key/CA mTLS; plaintext is an explicit local/test opt-in.

A clustered Webfleet fleet must start with no pre-existing unclustered site/group rows. Import/adoption of an existing fleet is deferred to an explicit migration contract rather than silently merging independent databases.

Gantry pairing and Raft voter membership are distinct. Pair participants first, then add voters explicitly through the replication operator surface.

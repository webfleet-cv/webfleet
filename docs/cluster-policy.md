# Webfleet cluster operation policy

Webfleet clustering reuses the shared Gantry node identity, pairing, targeting and bounded fan-out contracts, while Webfleet remains responsible for execution ownership and its own database.

The initial distributed surface is intentionally limited to cluster health, aggregated monitor status, targeted reads/administration and per-node comparison. Results always retain the node that owns them; partial failures remain visible.

Monitor, request, environment and schedule definitions are marked only as candidates for the later controlled-propagation phase. Phase 4 does not synchronize them automatically.

Secrets, browser runtime state and scheduler lease/runtime state are node-local. A cluster does not imply shared SQL storage, shared credentials or automatic duplicate execution.

## Phase 4 parity

Webfleet uses the Gantry cluster lifecycle: `init`, `invite`, `join`, explicit `approve`/`reject`, one-time collection, `members`, `status`, credential `rotate`, `revoke`, and `remove`. Pairing and signed peer RPC use `/api/cluster/v1/`; the `/manage/` Cluster tab exposes pairing, membership, health, credential and audit concepts using the same vocabulary as the other clustered Gantry products.

Compatible product versions may coexist while the cluster protocol version remains compatible. Incompatible protocol versions fail closed. Removing all members returns the installation to valid standalone operation. Requests, environments, monitors and schedules remain node-owned definitions unless a later propagation phase explicitly handles them; secrets, scheduler claims, browser runtime state and result history are not database-replicated by clustering.

## Shared-database scheduling coordination

Webfleet also supports a **multi-worker deployment over one shared PostgreSQL
authority** (`WEBFLEET_DATABASE_URL`). This is the scheduling model exercised by
the four-node dogfood campaigns. It is **shared-database coordination, not peer
clustering**: workers do not talk to each other for scheduling; they coordinate
through the shared claim table.

| Aspect | Contract |
|---|---|
| scheduling authority | shared PostgreSQL `scheduler_claims` |
| ownership mechanism | atomic claim + lease ownership + generation fencing |
| worker-to-worker scheduling protocol | none |
| worker failure / takeover | remotely exercised; remaining workers cover all sites without duplicate committed checks |
| PostgreSQL outage | fail closed: workers cannot acquire claims, monitoring pauses |
| checks during DB outage | missed, not buffered |
| DB recovery | automatic; new claim generations; no duplicate committed checks observed |
| DB-isolated worker | PARTIAL (bounded single-cycle observation) |
| crawl / multi-page monitor | exercised |
| distinct DNS monitor type | NOT APPLICABLE / NOT IMPLEMENTED (`"dns"` is only an HTTP error classification for DNS lookup failure) |
| stale → recovery lifecycle | PARTIAL |
| monitor CRUD CLI parity | NOT APPLICABLE (CLI does not expose monitor CRUD) |

Duplicate-execution claim, stated precisely:

> No duplicate committed checks were observed across the tested worker-failure
> and database-recovery transitions, consistent with the `scheduler_claims`
> lease/generation fencing design.

PostgreSQL is a single point of failure for this deployment mode by design:
when it is unavailable, workers prefer loss of availability over unsafe
independent scheduling. Do not describe this architecture as "peer clustering";
the workers coordinate through the shared PostgreSQL authority rather than
directly with each other.

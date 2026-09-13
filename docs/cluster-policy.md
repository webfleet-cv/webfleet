# Webfleet cluster operation policy

Webfleet clustering reuses the shared Gantry node identity, pairing, targeting and bounded fan-out contracts, while Webfleet remains responsible for execution ownership and its own database.

The initial distributed surface is intentionally limited to cluster health, aggregated monitor status, targeted reads/administration and per-node comparison. Results always retain the node that owns them; partial failures remain visible.

Monitor, request, environment and schedule definitions are marked only as candidates for the later controlled-propagation phase. Phase 4 does not synchronize them automatically.

Secrets, browser runtime state and scheduler lease/runtime state are node-local. A cluster does not imply shared SQL storage, shared credentials or automatic duplicate execution.

## Phase 4 parity

Webfleet uses the Gantry cluster lifecycle: `init`, `invite`, `join`, explicit `approve`/`reject`, one-time collection, `members`, `status`, credential `rotate`, `revoke`, and `remove`. Pairing and signed peer RPC use `/api/cluster/v1/`; the `/manage/` Cluster tab exposes pairing, membership, health, credential and audit concepts using the same vocabulary as the other clustered Gantry products.

Compatible product versions may coexist while the cluster protocol version remains compatible. Incompatible protocol versions fail closed. Removing all members returns the installation to valid standalone operation. Requests, environments, monitors and schedules remain node-owned definitions unless a later propagation phase explicitly handles them; secrets, scheduler claims, browser runtime state and result history are not database-replicated by clustering.

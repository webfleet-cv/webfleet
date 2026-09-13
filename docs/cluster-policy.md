# Webfleet cluster operation policy

Webfleet clustering reuses the shared Gantry node identity, pairing, targeting and bounded fan-out contracts, while Webfleet remains responsible for execution ownership and its own database.

The initial distributed surface is intentionally limited to cluster health, aggregated monitor status, targeted reads/administration and per-node comparison. Results always retain the node that owns them; partial failures remain visible.

Monitor, request, environment and schedule definitions are marked only as candidates for the later controlled-propagation phase. Phase 4 does not synchronize them automatically.

Secrets, browser runtime state and scheduler lease/runtime state are node-local. A cluster does not imply shared SQL storage, shared credentials or automatic duplicate execution.

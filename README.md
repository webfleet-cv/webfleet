# Web Fleet

Web Fleet is a self-hosted website monitoring, crawling, analytics and alerting platform.

## Command line

```sh
webfleet version
webfleet --version
webfleet service status
```

Unknown commands and unsupported options fail with a non-zero exit status.
Run the binary without a subcommand to start the integrated server, or use
`webfleet serve` where that compatibility alias is supported.

Self-hosted monitoring and analytics for all your websites.

Web Fleet is in early development. The project is designed to give self-hosters, freelancers, agencies and larger web teams one place to understand website availability, performance, TLS, DNS, links, changes and opt-in privacy-first analytics.

See `HANDOVER.md` for the product/architecture contract and `ROADMAP.md` for the living implementation plan.

## Listen address

Web Fleet's default listener is `127.0.0.1:7336`. The foreground accepts `--host` and `--port`; both are also honored from `WEBFLEET_HOST` / `WEBFLEET_PORT`. Precedence per field is CLI > environment > default, and a port must be an integer from 1 through 65535 (empty, malformed, zero, negative or oversized values fail clearly; whitespace-only values fail; IPv6 hosts are bracketed).

The legacy single-address `WEBFLEET_LISTEN` environment variable and the `service install --listen` flag are retained. An explicit `--host`/`--port` overrides `WEBFLEET_LISTEN`; combining `--listen` with `--host`/`--port` fails; and when only environment variables are involved, `WEBFLEET_LISTEN` combined with `WEBFLEET_HOST`/`WEBFLEET_PORT` fails rather than silently picking one.

`webfleet service install` records the canonical listener in the generated unit so it survives restart/reboot: a new `--host`/`--port` install writes the pair into `ExecStart` (e.g. `webfleet service install --host 127.0.0.1 --port 7336`), while legacy bootstrap units (WEBFLEET_LISTEN environment or `--listen`) keep the recorded `WEBFLEET_LISTEN` environment. The managed unit records a `# webfleet-listen-mode: explicit|bootstrap` marker (old units default to bootstrap), and `service status`/its health check use the installed process's effective listener.

Running on `0.0.0.0` exposes the backend directly; prefer the loopback default behind a trusted reverse proxy (see the Web Fleet website's reverse-proxy docs).

## Headless administration

Use `webfleet setup --email-file FILE --password-file FILE`, `webfleet config show --json`, and backup, restore and service commands from provisioning agents. Stop the service before `webfleet reset --auth` or `webfleet reset --all`; confirmation is `WEBFLEET AUTH` or `WEBFLEET ALL`. SQLite resets retain timestamped backups. PostgreSQL resets fail closed and require a database-native backup/reset workflow.

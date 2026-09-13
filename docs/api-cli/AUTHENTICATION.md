# Webfleet authentication

Use `--session-file` for browser-equivalent administration or `--token-file` for routes whose coverage matrix declares API-token scopes.

The default browser session cookie is `webfleet_session` and state-changing session requests use `X-Webfleet-CSRF`. Session files are JSON credential containers created/read by the common CLI and written with mode `0600`; on Unix, token/session files accessible by group or others are rejected. Passwords and tokens are supplied through protected files or JSON input, never command-line credential flags.

Human accounts remain installation-local. Cluster/service identities are separate from human sessions wherever applicable.

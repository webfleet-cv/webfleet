#!/bin/sh
set -eu
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/webfleet
node scripts/test-database-setup.mjs
node scripts/test-session-expiry.mjs
node scripts/test-account-contract.mjs
node scripts/test-login-form-contract.mjs
git diff --check
echo "Local hardening gates passed. Real PostgreSQL/OIDC/provider/cross-platform/scale adversarial gates remain external."

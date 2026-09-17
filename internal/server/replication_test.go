package server

import (
	"testing"
)

// TestReplicationOperatorAuthorization exercises the composed HTTP surface for
// the replication operator endpoints with replication disabled (so the handler
// body is 503), proving the authorization middleware gates access first.
func TestReplicationOperatorAuthorization(t *testing.T) {
	s, st := newRBACServer(t)
	createUser(t, st, "admin@example.com", "pw", "admin")
	createUser(t, st, "viewer@example.com", "pw", "viewer")
	admin := loginAs(t, s, "admin@example.com", "pw")
	viewer := loginAs(t, s, "viewer@example.com", "pw")

	// Unauthenticated -> 401/403, never the handler's 503.
	if rr := doReq(t, s, nil, "GET", "/api/cluster/v1/replication/status", ""); rr.Code != 401 && rr.Code != 403 {
		t.Fatalf("unauthenticated status = %d, want 401/403", rr.Code)
	}
	if rr := doReq(t, s, nil, "POST", "/api/cluster/v1/replication/join", `{"node_id":"b","address":"x"}`); rr.Code != 401 && rr.Code != 403 {
		t.Fatalf("unauthenticated join = %d, want 401/403", rr.Code)
	}
	// Ordinary non-admin user -> 403 (membership.update requires admin).
	if rr := doReq(t, s, viewer, "GET", "/api/cluster/v1/replication/status", ""); rr.Code != 403 {
		t.Fatalf("viewer status = %d, want 403", rr.Code)
	}
	if rr := doReq(t, s, viewer, "POST", "/api/cluster/v1/replication/snapshot", ""); rr.Code != 403 {
		t.Fatalf("viewer snapshot = %d, want 403", rr.Code)
	}
	// Valid admin -> handler runs; with replication disabled it returns 503.
	if rr := doReq(t, s, admin, "GET", "/api/cluster/v1/replication/status", ""); rr.Code != 503 {
		t.Fatalf("admin status = %d, want 503 (replication disabled)", rr.Code)
	}
	// Malformed join with replication disabled -> the disabled guard (503) fires
	// before field validation; the missing-field 400 path is exercised once the
	// runtime is wired (decodeJSON after the disabled check).
	if rr := doReq(t, s, admin, "POST", "/api/cluster/v1/replication/join", `{}`); rr.Code != 503 {
		t.Fatalf("disabled join = %d, want 503", rr.Code)
	}
}

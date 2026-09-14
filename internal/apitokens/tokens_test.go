package apitokens

import (
	"github.com/webfleet-cv/webfleet/internal/auth"
	"github.com/webfleet-cv/webfleet/internal/store"
	"testing"
)

func TestScopeAndRevoke(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	a := auth.New(st)
	if e = a.CreateAdmin("a", "a@b.c", "password"); e != nil {
		t.Fatal(e)
	}
	var uid, oid int64
	if e = st.DB.QueryRow(`SELECT id FROM users WHERE email='a@b.c'`).Scan(&uid); e != nil {
		t.Fatal(e)
	}
	if e = st.DB.QueryRow(`SELECT id FROM organizations ORDER BY id LIMIT 1`).Scan(&oid); e != nil {
		t.Fatal(e)
	}
	s := New(st)
	x, e := s.Create(uid, oid, "ci", []string{"sites:read"})
	if e != nil {
		t.Fatal(e)
	}
	u, o, scopes, e := s.Authenticate(x.Token)
	if e != nil || u != uid || o != oid || !HasScope(scopes, "sites:read") {
		t.Fatalf("authenticate: uid=%d org=%d scopes=%v err=%v", u, o, scopes, e)
	}
	if HasScope(scopes, "sites:write") {
		t.Fatal("scope bypass: sites:write granted when not requested")
	}
	s.Revoke(x.ID, uid, oid)
	if _, _, _, e = s.Authenticate(x.Token); e == nil {
		t.Fatal("revoked accepted")
	}
	// Unknown and revoked tokens produce the same generic error (no existence
	// oracle).
	_, _, _, unknownErr := s.Authenticate("wf_doesnotexist")
	if unknownErr == nil || unknownErr.Error() != e.Error() {
		t.Fatal("token error leaks existence")
	}
}

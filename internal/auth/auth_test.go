package auth

import (
	"context"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
	"sync"
	"testing"
)

func TestFirstAdminAndSessionLifecycle(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	a := New(st)
	need, e := a.NeedsSetup()
	if e != nil || !need {
		t.Fatalf("need=%v err=%v", need, e)
	}
	if e = a.CreateAdmin("admin", "admin@example.com", "secret7"); e != nil {
		t.Fatal(e)
	}
	if e = a.CreateAdmin("other", "other@example.com", "secret7"); e == nil {
		t.Fatal("second first-admin allowed")
	}
	tok, s, e := a.Login("admin@example.com", "secret7")
	if e != nil || tok == "" || s.CSRF == "" {
		t.Fatalf("login failed: %v", e)
	}
	if _, e = a.Session(tok); e != nil {
		t.Fatal(e)
	}
	a.Logout(tok)
	if _, e = a.Session(tok); e == nil {
		t.Fatal("logged-out session survived")
	}
}

func TestChangePasswordKeepsCurrentSessionAndRevokesOthers(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := New(st)
	if err = a.CreateAdmin("admin", "admin@example.com", "old-password"); err != nil {
		t.Fatal(err)
	}
	currentToken, current, err := a.Login("admin@example.com", "old-password")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := a.Login("admin@example.com", "old-password")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.ChangePassword(context.Background(), current.UserID, "wrong-password", "new-password", currentToken); err != ErrInvalidCurrentPassword {
		t.Fatalf("wrong current password: %v", err)
	}
	if err = a.ChangePassword(context.Background(), current.UserID, "old-password", "new-password", currentToken); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Session(currentToken); err != nil {
		t.Fatalf("current session was revoked: %v", err)
	}
	if _, err = a.Session(otherToken); err == nil {
		t.Fatal("other session survived password change")
	}
	if _, _, err = a.Login("admin@example.com", "old-password"); err == nil {
		t.Fatal("old password remained valid")
	}
	if _, _, err = a.Login("admin@example.com", "new-password"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}

func TestFirstAdminGetsOwnerMembership(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	a := New(st)
	if e = a.CreateAdmin("admin", "admin@example.com", "secret7"); e != nil {
		t.Fatal(e)
	}
	org, e := st.PrimaryOrgID(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	rows, e := sqlite.Query(st.DB, `SELECT user_id,role FROM organization_memberships WHERE organization_id=?`, org)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one owner membership, got %d", len(rows))
	}
	if rows[0]["role"].Text != "owner" {
		t.Fatalf("expected owner role, got %q", rows[0]["role"].Text)
	}
}

func TestConcurrentFirstAdminRaceGuard(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	a := New(st)
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = a.CreateAdmin("admin"+string(rune('a'+i)), "admin"+string(rune('a'+i))+"@example.com", "secret7")
		}(i)
	}
	wg.Wait()
	created := 0
	for _, err := range errs {
		if err == nil {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("expected exactly one successful first-admin creation, got %d", created)
	}
	rows, e := sqlite.Query(st.DB, `SELECT COUNT(*) n FROM users`)
	if e != nil {
		t.Fatal(e)
	}
	if rows[0]["n"].Int64 != 1 {
		t.Fatalf("expected exactly one user, got %d", rows[0]["n"].Int64)
	}
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/password"
	"github.com/webfleet-cv/webfleet/internal/sites"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

func newRBACServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := New(config.Config{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return s, st
}

type client struct {
	cookie string
	csrf   string
}

func doReq(t *testing.T, s *Server, c *client, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c != nil && c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "webfleet_session", Value: c.cookie})
	}
	if c != nil && c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func sessionOf(t *testing.T, rr *httptest.ResponseRecorder) *client {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse session body: %v (%s)", err, rr.Body.String())
	}
	c := &client{}
	if v, ok := body["csrf"].(string); ok {
		c.csrf = v
	}
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == "webfleet_session" {
			c.cookie = ck.Value
		}
	}
	if c.cookie == "" || c.csrf == "" {
		t.Fatalf("setup/login did not issue session cookie and csrf: %s", rr.Body.String())
	}
	return c
}

func setupAdmin(t *testing.T, s *Server) *client {
	t.Helper()
	rr := doReq(t, s, nil, "POST", "/api/setup", `{"username":"admin", "email":"admin@example.com","password":"secret7"}`)
	if rr.Code != 201 {
		t.Fatalf("setup %d %s", rr.Code, rr.Body.String())
	}
	return sessionOf(t, rr)
}

func createUser(t *testing.T, st *store.Store, email, pw, role string) {
	t.Helper()
	h, e := password.Hash(pw)
	if e != nil {
		t.Fatal(e)
	}
	if e = sqlite.Exec(st.DB, `INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)`, strings.SplitN(email, "@", 2)[0], email, h, role, store.Now()); e != nil {
		t.Fatal(e)
	}
	r, e := sqlite.Query(st.DB, `SELECT id FROM users WHERE lower(email)=?`, email)
	if e != nil || len(r) == 0 {
		t.Fatalf("create user lookup: %v", e)
	}
	org, e := st.PrimaryOrgID(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = sqlite.Exec(st.DB, `INSERT INTO organization_memberships(organization_id,user_id,role,created_at) VALUES(?,?,?,?)`, org, r[0]["id"].Int64, role, store.Now()); e != nil {
		t.Fatal(e)
	}
}

func loginAs(t *testing.T, s *Server, email, pw string) *client {
	t.Helper()
	rr := doReq(t, s, nil, "POST", "/api/login", fmt.Sprintf(`{"email":%q,"password":%q}`, email, pw))
	if rr.Code != 200 {
		t.Fatalf("login %d %s", rr.Code, rr.Body.String())
	}
	return sessionOf(t, rr)
}

func createSiteViaAPI(t *testing.T, s *Server, c *client, name, url string) int64 {
	t.Helper()
	rr := doReq(t, s, c, "POST", "/api/sites", fmt.Sprintf(`{"name":%q,"primary_url":%q}`, name, url))
	if rr.Code != 201 {
		t.Fatalf("create site %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

func TestFirstAdminCanUsePrivilegedRoutes(t *testing.T) {
	s, st := newRBACServer(t)
	admin := setupAdmin(t, s)
	// The fresh-install admin must have an owner membership; otherwise these
	// privileged routes returned 403 before the CP30 fix.
	if rr := doReq(t, s, admin, "GET", "/api/organization/members", ""); rr.Code != 200 {
		t.Fatalf("members read %d %s", rr.Code, rr.Body.String())
	}
	createUser(t, st, "viewer@example.com", "secret7", "viewer")
	if rr := doReq(t, s, admin, "POST", "/api/organization/members", `{"email":"viewer@example.com","role":"operator"}`); rr.Code != 200 {
		t.Fatalf("membership.update %d %s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, s, admin, "POST", "/api/tokens", `{"name":"ci","scopes":["sites:read"]}`); rr.Code != 201 {
		t.Fatalf("tokens.manage %d %s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, s, admin, "PUT", "/api/maintenance", `{"check_days":30,"analytics_raw_days":14,"audit_days":90}`); rr.Code != 200 {
		t.Fatalf("maintenance.manage %d %s", rr.Code, rr.Body.String())
	}
}

func TestRBACViewerReadOnly(t *testing.T) {
	s, st := newRBACServer(t)
	admin := setupAdmin(t, s)
	siteID := createSiteViaAPI(t, s, admin, "Example", "https://127.0.0.1:1/")
	createUser(t, st, "viewer@example.com", "secret7", "viewer")
	v := loginAs(t, s, "viewer@example.com", "secret7")

	for _, tc := range []struct {
		method, path string
		body         string
		want         int
	}{
		{"GET", "/api/sites", "", 200},
		{"GET", fmt.Sprintf("/api/sites/%d", siteID), "", 200},
		{"GET", "/api/fleet", "", 200},
		{"GET", "/api/maintenance", "", 200},
		{"POST", "/api/sites", `{"name":"x","primary_url":"https://example.com"}`, 403},
		{"POST", fmt.Sprintf("/api/sites/%d/archive", siteID), `{"archived":true}`, 403},
		{"POST", fmt.Sprintf("/api/sites/%d/deployments", siteID), `{"provider":"github"}`, 403},
		{"POST", "/api/tokens", `{"name":"x","scopes":["sites:read"]}`, 403},
		{"POST", "/api/audits/batch", `{"site_ids":[]}`, 403},
		{"POST", "/api/organization/members", `{"email":"a@b.c","role":"viewer"}`, 403},
		{"PUT", "/api/maintenance", `{"check_days":30,"analytics_raw_days":14,"audit_days":90}`, 403},
	} {
		if rr := doReq(t, s, v, tc.method, tc.path, tc.body); rr.Code != tc.want {
			t.Errorf("viewer %s %s = %d, want %d (%s)", tc.method, tc.path, rr.Code, tc.want, rr.Body.String())
		}
	}
}

func TestRBACOperatorOperational(t *testing.T) {
	s, st := newRBACServer(t)
	setupAdmin(t, s)
	createUser(t, st, "op@example.com", "secret7", "operator")
	op := loginAs(t, s, "op@example.com", "secret7")

	rr := doReq(t, s, op, "POST", "/api/sites", `{"name":"opsite","primary_url":"https://127.0.0.1:1/"}`)
	if rr.Code != 201 {
		t.Fatalf("operator create site %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr := doReq(t, s, op, "POST", fmt.Sprintf("/api/sites/%d/archive", out.ID), `{"archived":true}`); rr.Code != 200 {
		t.Fatalf("operator archive %d %s", rr.Code, rr.Body.String())
	}
	// Operators may archive (reversible) but must not permanently delete sites.
	if rr := doReq(t, s, op, "DELETE", fmt.Sprintf("/api/sites/%d", out.ID), ""); rr.Code != 403 {
		t.Fatalf("operator site.delete %d, want 403", rr.Code)
	}
	// Privileged configuration stays admin/owner.
	if rr := doReq(t, s, op, "POST", "/api/tokens", `{"name":"x","scopes":["sites:read"]}`); rr.Code != 403 {
		t.Fatalf("operator tokens.manage %d", rr.Code)
	}
	if rr := doReq(t, s, op, "POST", "/api/organization/members", `{"email":"a@b.c","role":"viewer"}`); rr.Code != 403 {
		t.Fatalf("operator membership.update %d", rr.Code)
	}
	if rr := doReq(t, s, op, "PUT", "/api/maintenance", `{"check_days":30,"analytics_raw_days":14,"audit_days":90}`); rr.Code != 403 {
		t.Fatalf("operator maintenance.manage %d", rr.Code)
	}
}

// TestRBACAdminOperational proves the admin role at the server boundary: admin
// may perform the administrative operations that operators cannot, including
// the destructive site.delete action. The owner-only distinction (the
// unexposed organization.delete action) is proven separately in the
// route-inventory and rbac matrix tests because no HTTP route is owner-only.
func TestRBACAdminOperational(t *testing.T) {
	s, st := newRBACServer(t)
	setupAdmin(t, s)
	createUser(t, st, "adminrole@example.com", "secret7", "admin")
	a := loginAs(t, s, "adminrole@example.com", "secret7")
	createUser(t, st, "op@example.com", "secret7", "operator")
	op := loginAs(t, s, "op@example.com", "secret7")

	if rr := doReq(t, s, a, "GET", "/api/organization/members", ""); rr.Code != 200 {
		t.Fatalf("admin members read %d", rr.Code)
	}
	if rr := doReq(t, s, a, "POST", "/api/tokens", `{"name":"ci","scopes":["sites:read"]}`); rr.Code != 201 {
		t.Fatalf("admin tokens.manage %d %s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, s, a, "PUT", "/api/maintenance", `{"check_days":30,"analytics_raw_days":14,"audit_days":90}`); rr.Code != 200 {
		t.Fatalf("admin maintenance.manage %d", rr.Code)
	}
	// A literal public documentation address keeps this RBAC test independent
	// of the runner's DNS and outbound-network policy; netguard behavior has its
	// own resolver-injected adversarial suite.
	if rr := doReq(t, s, a, "POST", "/api/notifications/webhooks", `{"name":"hook","url":"https://8.8.8.8/hook"}`); rr.Code != 201 {
		t.Fatalf("admin webhooks.manage %d %s", rr.Code, rr.Body.String())
	}
	// Admin can update a membership that an operator cannot.
	if rr := doReq(t, s, a, "POST", "/api/organization/members", `{"email":"op@example.com","role":"viewer"}`); rr.Code != 200 {
		t.Fatalf("admin membership.update %d", rr.Code)
	}
	// Admin may permanently delete a site (after archiving); the same call is
	// denied to an operator.
	siteID := createSiteViaAPI(t, s, a, "Expired", "https://127.0.0.1:1/")
	if rr := doReq(t, s, a, "POST", fmt.Sprintf("/api/sites/%d/archive", siteID), `{"archived":true}`); rr.Code != 200 {
		t.Fatalf("admin archive %d", rr.Code)
	}
	if rr := doReq(t, s, a, "DELETE", fmt.Sprintf("/api/sites/%d", siteID), ""); rr.Code != 200 {
		t.Fatalf("admin site.delete %d %s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, s, op, "POST", "/api/tokens", `{"name":"x","scopes":["sites:read"]}`); rr.Code != 403 {
		t.Fatalf("operator must not cross into admin tokens.manage: %d", rr.Code)
	}
}

func TestCrossOrganizationIsolation(t *testing.T) {
	s, st := newRBACServer(t)
	admin := setupAdmin(t, s)
	mySite := createSiteViaAPI(t, s, admin, "Mine", "https://127.0.0.1:1/")

	// Create a second organization and a site inside it, out of the admin's org.
	if e := sqlite.Exec(st.DB, `INSERT INTO organizations(name,created_at) VALUES('Other',?)`, store.Now()); e != nil {
		t.Fatal(e)
	}
	var otherOrg int64
	if e := st.DB.QueryRow(`SELECT id FROM organizations WHERE name='Other'`).Scan(&otherOrg); e != nil {
		t.Fatal(e)
	}
	other, e := sites.New(st).Create(otherOrg, "Theirs", "https://127.0.0.1:1/", 0)
	if e != nil {
		t.Fatal(e)
	}

	createUser(t, st, "viewer@example.com", "secret7", "viewer")
	v := loginAs(t, s, "viewer@example.com", "secret7")
	createUser(t, st, "op@example.com", "secret7", "operator")
	op := loginAs(t, s, "op@example.com", "secret7")

	if rr := doReq(t, s, v, "GET", fmt.Sprintf("/api/sites/%d", mySite), ""); rr.Code != 200 {
		t.Fatalf("own-org site read %d", rr.Code)
	}
	if rr := doReq(t, s, v, "GET", fmt.Sprintf("/api/sites/%d", other.ID), ""); rr.Code != 404 {
		t.Fatalf("cross-org site read %d, want 404", rr.Code)
	}
	// Org-scoped listings never expose the other organization's site.
	rr := doReq(t, s, v, "GET", "/api/sites", "")
	if rr.Code != 200 {
		t.Fatalf("list %d", rr.Code)
	}
	var list struct {
		Sites []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"sites"`
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if list.Total != 1 || len(list.Sites) != 1 || list.Sites[0].ID != mySite {
		t.Fatalf("cross-org list leak: %s", rr.Body.String())
	}
	rr = doReq(t, s, v, "GET", "/api/fleet", "")
	var sum struct {
		Total int64 `json:"total"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &sum)
	if sum.Total != 1 {
		t.Fatalf("cross-org fleet leak: total=%d", sum.Total)
	}
	// Batch audit scope resolution must be org-limited.
	rr = doReq(t, s, v, "POST", "/api/audits/resolve", `{"search":""}`)
	if rr.Code != 200 {
		t.Fatalf("resolve %d", rr.Code)
	}
	var resolved struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resolved)
	if resolved.Count != 1 {
		t.Fatalf("cross-org audit scope leak: count=%d", resolved.Count)
	}
	// An operator may archive sites in general (authorization passes) but must
	// not be able to touch another organization's site (ownership fails).
	if rr := doReq(t, s, op, "POST", fmt.Sprintf("/api/sites/%d/archive", other.ID), `{"archived":true}`); rr.Code != 404 {
		t.Fatalf("cross-org site archive %d, want 404", rr.Code)
	}
	if rr := doReq(t, s, op, "POST", fmt.Sprintf("/api/sites/%d/archive", mySite), `{"archived":true}`); rr.Code != 200 {
		t.Fatalf("own-org site archive %d, want 200", rr.Code)
	}
}

func TestCrossOrganizationGroupOwnership(t *testing.T) {
	s, st := newRBACServer(t)
	setupAdmin(t, s)
	var otherOrg int64
	if e := sqlite.Exec(st.DB, `INSERT INTO organizations(name,created_at) VALUES('Other',?)`, store.Now()); e != nil {
		t.Fatal(e)
	}
	if e := st.DB.QueryRow(`SELECT id FROM organizations WHERE name='Other'`).Scan(&otherOrg); e != nil {
		t.Fatal(e)
	}
	g, e := sites.New(st).CreateGroup(otherOrg, "OtherGroup")
	if e != nil {
		t.Fatal(e)
	}
	createUser(t, st, "op@example.com", "secret7", "operator")
	op := loginAs(t, s, "op@example.com", "secret7")
	// An operator in the default org must not be able to attach a site to a
	// group owned by another organization.
	if rr := doReq(t, s, op, "POST", "/api/sites", fmt.Sprintf(`{"name":"x","primary_url":"https://example.com","group_id":%d}`, g.ID)); rr.Code != 400 {
		t.Fatalf("cross-org group attachment %d, want 400", rr.Code)
	}
}

func TestSetupRaceAtHTTP(t *testing.T) {
	s, _ := newRBACServer(t)
	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := doReq(t, s, nil, "POST", "/api/setup", fmt.Sprintf(`{"username":"u%d","email":"u%d@example.com","password":"secret7"}`, i, i))
			codes[i] = rr.Code
		}(i)
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == 201 {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("setup race produced %d first admins", created)
	}
}

func TestUnauthenticatedAndCSRFEnforced(t *testing.T) {
	s, st := newRBACServer(t)
	admin := setupAdmin(t, s)
	siteID := createSiteViaAPI(t, s, admin, "Example", "https://127.0.0.1:1/")
	// No cookie: 401 on a protected route.
	if rr := doReq(t, s, nil, "GET", "/api/sites", ""); rr.Code != 401 {
		t.Fatalf("unauthenticated GET /api/sites = %d, want 401", rr.Code)
	}
	// Cookie without CSRF: 403 on a state-changing route.
	noCSRF := &client{cookie: admin.cookie}
	if rr := doReq(t, s, noCSRF, "POST", fmt.Sprintf("/api/sites/%d/archive", siteID), `{"archived":true}`); rr.Code != 403 {
		t.Fatalf("missing CSRF = %d, want 403", rr.Code)
	}
	// createUser is used to guarantee the package links cleanly in this test file.
	_ = st
}

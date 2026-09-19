package monitor

import (
	"context"
	"github.com/webfleet-cv/webfleet/internal/netguard"
	"github.com/webfleet-cv/webfleet/internal/sites"
	"github.com/webfleet-cv/webfleet/internal/store"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if x, ok := f[host]; ok {
		return x, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host}
}
func setupSite(t *testing.T, raw string) (*store.Store, int64) {
	t.Helper()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	site, e := sites.New(st).Create(1, "Example", raw, 0)
	if e != nil {
		st.Close()
		t.Fatal(e)
	}
	return st, site.ID
}
func TestCheckPersistsHTTPResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	st, id := setupSite(t, srv.URL)
	defer st.Close()
	svc := NewForTests(st, fakeResolver{u.Hostname(): {netip.MustParseAddr("127.0.0.1")}}, true)
	res, e := svc.CheckSite(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	if !res.OK || res.StatusCode != 204 {
		t.Fatalf("result=%+v", res)
	}
	hist, e := svc.Recent(id, 5)
	if e != nil || len(hist) != 1 {
		t.Fatalf("history=%+v err=%v", hist, e)
	}
}
func TestPrivateAndReservedAddressesBlocked(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "198.51.100.2", "203.0.113.8", "::1", "fc00::1", "2001:db8::1"} {
		if !netguard.Blocked(netip.MustParseAddr(ip)) {
			t.Fatalf("not blocked: %s", ip)
		}
	}
}
func TestRedirectToPrivateIsBlocked(t *testing.T) {
	st, id := setupSite(t, "https://public.example/")
	defer st.Close()
	svc := NewForTests(st, fakeResolver{"public.example": {netip.MustParseAddr("93.184.216.34")}, "internal.example": {netip.MustParseAddr("127.0.0.1")}}, false)
	u, _ := url.Parse("http://internal.example/admin")
	if e := svc.guard.ValidateURL(context.Background(), u); e == nil {
		t.Fatal("private redirect target allowed")
	}
	_ = id
	_ = time.Second
}

func TestHealthTransitions(t *testing.T) {
	status := 503
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	st, id := setupSite(t, srv.URL)
	defer st.Close()
	svc := NewForTests(st, fakeResolver{u.Hostname(): {netip.MustParseAddr("127.0.0.1")}}, true)
	if _, e := svc.CheckSite(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	site, e := sites.New(st).GetForOrg(1, id)
	if e != nil || site.Health != "degraded" {
		t.Fatalf("first failure site=%+v err=%v", site, e)
	}
	if _, e = svc.CheckSite(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	site, _ = sites.New(st).GetForOrg(1, id)
	if site.Health != "down" || site.ConsecutiveFailures != 2 {
		t.Fatalf("second failure site=%+v", site)
	}
	status = 204
	if _, e = svc.CheckSite(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	site, _ = sites.New(st).GetForOrg(1, id)
	if site.Health != "healthy" || site.ConsecutiveFailures != 0 {
		t.Fatalf("recovery site=%+v", site)
	}
}

func TestRedirectAndHeaderObservation(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, base+"/final", http.StatusFound)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	base = srv.URL
	u, _ := url.Parse(srv.URL)
	st, id := setupSite(t, srv.URL)
	defer st.Close()
	svc := NewForTests(st, fakeResolver{u.Hostname(): {netip.MustParseAddr("127.0.0.1")}}, true)
	if _, e := svc.CheckSite(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	hist, e := svc.HTTPHistory(id)
	if e != nil || len(hist) != 1 {
		t.Fatalf("history=%+v err=%v", hist, e)
	}
	if len(hist[0].RedirectChain) != 2 {
		t.Fatalf("redirects=%v", hist[0].RedirectChain)
	}
	if _, ok := hist[0].Headers["Content-Security-Policy"]; !ok {
		t.Fatal("missing observed CSP")
	}
}

func TestGuardBlockedCheckKeepsSiteID(t *testing.T) {
	st, id := setupSite(t, "https://blocked.example/")
	defer st.Close()
	svc := NewForTests(st, fakeResolver{"blocked.example": {}}, false)
	res, e := svc.CheckSite(context.Background(), id)
	if e != nil {
		t.Fatalf("CheckSite returned error on guard-blocked URL: %v", e)
	}
	if res.SiteID != id {
		t.Fatalf("guard-blocked result SiteID=%d want %d", res.SiteID, id)
	}
	if res.MonitorID == 0 {
		t.Fatal("guard-blocked result MonitorID=0")
	}
	if res.ErrorClass != "blocked" {
		t.Fatalf("ErrorClass=%q want blocked", res.ErrorClass)
	}
	// The health transition must target the real site, never site_id 0, which
	// does not exist and would trip the sites() foreign key.
	var count int64
	if e := st.DB.QueryRow(`SELECT COUNT(*) FROM site_health WHERE site_id=?`, id).Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 1 {
		t.Fatalf("site_health rows=%d want 1 for site %d", count, id)
	}
	if e := st.DB.QueryRow(`SELECT COUNT(*) FROM site_health WHERE site_id=0`).Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 0 {
		t.Fatalf("site_health row with site_id=0 created (%d)", count)
	}
}

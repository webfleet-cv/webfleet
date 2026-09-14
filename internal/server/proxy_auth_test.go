package server

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

func newTrustedServer(t *testing.T, prefixes ...string) (*Server, *store.Store) {
	t.Helper()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Config{}
	for _, p := range prefixes {
		cfg.TrustedProxies = append(cfg.TrustedProxies, netip.MustParsePrefix(p))
	}
	s := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return s, st
}

func sessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "webfleet_session" {
			return c
		}
	}
	return nil
}

func TestSecureCookieDirectHTTPS(t *testing.T) {
	s, _ := newTrustedServer(t)
	req := httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"secret7"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.1:1234"
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("setup %d %s", rr.Code, rr.Body.String())
	}
	c := sessionCookie(rr)
	if c == nil || !c.Secure {
		t.Fatalf("direct HTTPS cookie must be Secure: %+v", c)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 86400 {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
}

func TestSecureCookieTrustedTLSProxy(t *testing.T) {
	s, _ := newTrustedServer(t, "127.0.0.1/32")
	req := httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"secret7"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:9999" // the trusted proxy
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("setup %d %s", rr.Code, rr.Body.String())
	}
	if c := sessionCookie(rr); c == nil || !c.Secure {
		t.Fatalf("cookie behind trusted TLS-terminating proxy must be Secure: %+v", c)
	}
}

func TestSecureCookieUntrustedSpoofCannotUpgrade(t *testing.T) {
	s, _ := newTrustedServer(t, "127.0.0.1/32")
	req := httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"secret7"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:1234" // untrusted direct peer
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("setup %d %s", rr.Code, rr.Body.String())
	}
	if c := sessionCookie(rr); c == nil || c.Secure {
		t.Fatalf("untrusted spoofed X-Forwarded-Proto must not set a Secure cookie: %+v", c)
	}
}

func TestOIDCRedirectRequiresCanonicalOrigin(t *testing.T) {
	s, _ := newTrustedServer(t, "127.0.0.1/32")
	// Without WEBFLEET_PUBLIC_URL the OIDC redirect URI fails closed: an
	// arbitrary Host header (or a trusted proxy's forwarded scheme) never
	// produces a redirect URI.
	r := httptest.NewRequest("GET", "http://wf.example.com/api/oidc/login", nil)
	r.Host = "wf.example.com"
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := s.oidcRedirect(r); got != "" {
		t.Fatalf("no-origin redirect = %q, want empty", got)
	}
	r.RemoteAddr = "198.51.100.7:1234"
	if got := s.oidcRedirect(r); got != "" {
		t.Fatalf("untrusted no-origin redirect = %q, want empty", got)
	}
	// With a configured canonical origin, both direct and trusted-proxy
	// deployments produce the same URI regardless of Host/forwarded headers.
	s.cfg.PublicURL = "https://webfleet.example.com"
	r.Host = "evil.example"
	if got := s.oidcRedirect(r); got != "https://webfleet.example.com/api/oidc/callback" {
		t.Fatalf("canonical redirect = %q", got)
	}
}

func TestLoginRateLimit(t *testing.T) {
	s, _ := newTrustedServer(t)
	// The limiter keys on the resolved client address (10 per minute).
	for i := 0; i < 10; i++ {
		rr := doReq(t, s, nil, "POST", "/api/login", `{"email":"a@b.c","password":"wrong"}`)
		if rr.Code != 401 {
			t.Fatalf("attempt %d = %d, want 401", i, rr.Code)
		}
	}
	if rr := doReq(t, s, nil, "POST", "/api/login", `{"email":"a@b.c","password":"wrong"}`); rr.Code != 429 {
		t.Fatalf("over-limit login = %d, want 429", rr.Code)
	}
}

func TestSetupRateLimit(t *testing.T) {
	s, _ := newTrustedServer(t)
	for i := 0; i < 5; i++ {
		rr := doReq(t, s, nil, "POST", "/api/setup", `{"username":"admin", "email":"a@b.c","password":"x"}`)
		if rr.Code != 400 {
			t.Fatalf("setup attempt %d = %d, want 400", i, rr.Code)
		}
	}
	if rr := doReq(t, s, nil, "POST", "/api/setup", `{"username":"admin", "email":"a@b.c","password":"x"}`); rr.Code != 429 {
		t.Fatalf("over-limit setup = %d, want 429", rr.Code)
	}
}

func TestSpoofedForwardedForDoesNotBypassLoginLimit(t *testing.T) {
	s, _ := newTrustedServer(t, "127.0.0.1/32")
	req := func() *httptest.ResponseRecorder {
		body := strings.NewReader(`{"email":"a@b.c","password":"wrong"}`)
		r := httptest.NewRequest("POST", "/api/login", body)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "127.0.0.1:9999"
		r.Header.Set("X-Forwarded-For", "198.51.100.1") // spoofed; real client is 127.0.0.1? No - see below
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, r)
		return rr
	}
	// The trusted proxy appends the real client; here the real client is
	// 198.51.100.1, so the limiter keys on it. An attacker cannot rotate
	// X-Forwarded-For to evade the limit because only the rightmost
	// non-trusted value is used.
	for i := 0; i < 10; i++ {
		if rr := req(); rr.Code != 401 {
			t.Fatalf("attempt %d = %d", i, rr.Code)
		}
	}
	if rr := req(); rr.Code != 429 {
		t.Fatalf("over-limit with spoofed header = %d, want 429", rr.Code)
	}
}

// TestLocalAdminRecoveryWithBrokenOIDC proves local password login keeps
// working when OIDC is configured but its provider is unreachable.
func TestLocalAdminRecoveryWithBrokenOIDC(t *testing.T) {
	s, st := newTrustedServer(t)
	admin := setupAdmin(t, s)
	// Simulate a provider that was once configured and is now unreachable.
	if e := sqlite.Exec(st.DB, `INSERT INTO oidc_config(id,issuer,client_id,client_secret,enabled,auto_provision,updated_at) VALUES(1,?,?,?,1,1,?)`, "https://127.0.0.1:1/", "cid", "csecret", store.Now()); e != nil {
		t.Fatal(e)
	}
	// OIDC login fails (provider unreachable) but must not affect the server.
	if rr := doReq(t, s, nil, "GET", "/api/oidc/login", ""); rr.Code != 400 {
		t.Fatalf("broken OIDC login = %d, want 400", rr.Code)
	}
	// Local admin login still works.
	if rr := doReq(t, s, admin, "GET", "/api/session", ""); rr.Code != 200 {
		t.Fatalf("local session after broken OIDC = %d", rr.Code)
	}
	if rr := doReq(t, s, nil, "POST", "/api/login", `{"email":"admin@example.com","password":"secret7"}`); rr.Code != 200 {
		t.Fatalf("local admin login with broken OIDC = %d %s", rr.Code, rr.Body.String())
	}
}

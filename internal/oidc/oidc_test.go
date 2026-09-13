package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/webfleet-cv/webfleet/internal/auth"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

const (
	testClientID     = "webfleet-client"
	testClientSecret = "provider-secret"
	testRedirect     = "https://wf.example/callback"
	testBrowser      = "browser-a"
)

// fakeProvider is a standards-shaped OIDC provider for adversarial tests. It
// serves discovery, JWKS, token and userinfo endpoints and signs ID tokens
// with an RSA key. Fields are settable to inject protocol violations.
type fakeProvider struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string

	mu                 sync.Mutex
	nonce              string
	email              string
	emailVerified      bool
	omitEmailFromIDTok bool
	issOverride        string
	audOverride        string
	expire             bool
	signKey            *rsa.PrivateKey
	userinfoIss        string
	userinfoEmailVer   *bool
}

func newFake(t *testing.T, email string, verified bool) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProvider{t: t, key: key, email: email, emailVerified: verified}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fp.handleDiscovery)
	mux.HandleFunc("/jwks", fp.handleJWKS)
	mux.HandleFunc("/token", fp.handleToken)
	mux.HandleFunc("/userinfo", fp.handleUserinfo)
	fp.srv = httptest.NewTLSServer(mux)
	fp.issuer = fp.srv.URL
	return fp
}

func (f *fakeProvider) Close() { f.srv.Close() }

func (f *fakeProvider) setNonce(n string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce = n
}
func (f *fakeProvider) setIssuerOverride(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issOverride = s
}
func (f *fakeProvider) setAudOverride(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audOverride = s
}
func (f *fakeProvider) setExpired() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire = true
}
func (f *fakeProvider) setWrongKey(k *rsa.PrivateKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signKey = k
}
func (f *fakeProvider) setOmitEmail() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.omitEmailFromIDTok = true
}
func (f *fakeProvider) setUserinfoVerified(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userinfoEmailVer = &v
}

func (f *fakeProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"userinfo_endpoint":                     f.issuer + "/userinfo",
		"jwks_uri":                              f.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	k := f.key
	e := encodeE(k.E)
	n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "testkey", "use": "sig", "alg": "RS256", "n": n, "e": e,
	}}})
}

func (f *fakeProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	form, _ := url.ParseQuery(string(body))
	if form.Get("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     f.idToken(),
	})
}

func (f *fakeProvider) idToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	iss := f.issuer
	if f.issOverride != "" {
		iss = f.issOverride
	}
	aud := testClientID
	if f.audOverride != "" {
		aud = f.audOverride
	}
	exp := time.Now().Add(time.Hour).Unix()
	if f.expire {
		exp = time.Now().Add(-time.Hour).Unix()
	}
	key := f.key
	if f.signKey != nil {
		key = f.signKey
	}
	header := map[string]any{"alg": "RS256", "kid": "testkey", "typ": "JWT"}
	claims := map[string]any{
		"iss":   iss,
		"sub":   "subject-123",
		"aud":   aud,
		"exp":   exp,
		"iat":   time.Now().Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"nonce": f.nonce,
	}
	if !f.omitEmailFromIDTok {
		claims["email"] = f.email
		claims["email_verified"] = f.emailVerified
	}
	return signJWT(f.t, key, header, claims)
}

func (f *fakeProvider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.userinfoEmailVer != nil && !*f.userinfoEmailVer {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "subject-123", "email": f.email, "email_verified": false, "iss": f.issuer})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"sub": "subject-123", "email": f.email, "email_verified": true, "iss": f.issuer})
}

func encodeE(e int) string {
	b := []byte{}
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func signJWT(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	msg := b64(hb) + "." + b64(cb)
	h := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return msg + "." + b64(sig)
}

func newOIDCService(t *testing.T, fp *fakeProvider, auto, enabled bool) (*Service, *store.Store) {
	t.Helper()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = st.Close() })
	if e = auth.New(st).CreateAdmin("admin@example.test", "secret7"); e != nil {
		t.Fatal(e)
	}
	svc := New(st, auth.New(st))
	// Trust the fake provider's TLS certificate for tests.
	svc.client = fp.srv.Client()
	if e := svc.Save(Config{Issuer: fp.issuer, ClientID: testClientID, ClientSecret: testClientSecret, Enabled: enabled, AutoProvision: auto}); e != nil {
		t.Fatal(e)
	}
	return svc, st
}

func beginStateNonce(t *testing.T, svc *Service) (state, nonce string) {
	t.Helper()
	authURL, e := svc.Begin(context.Background(), testRedirect, testBrowser)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(authURL)
	if e != nil {
		t.Fatal(e)
	}
	return u.Query().Get("state"), u.Query().Get("nonce")
}

func TestOIDCFullFlowAutoProvisionsViewer(t *testing.T) {
	fp := newFake(t, "new@example.com", true)
	defer fp.Close()
	svc, st := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	tok, sess, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser)
	if e != nil {
		t.Fatal(e)
	}
	if tok == "" || sess.Email != "new@example.com" {
		t.Fatalf("session %+v", sess)
	}
	rows, e := sqlite.Query(st.DB, `SELECT m.role FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE lower(u.email)=?`, "new@example.com")
	if e != nil || len(rows) != 1 || rows[0]["role"].Text != "viewer" {
		t.Fatalf("auto-provisioned membership: %v %v", rows, e)
	}
}

func TestOIDCStateMismatchAndReplay(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	if _, _, e := svc.Callback(context.Background(), "bogus-state", "code", testRedirect, testBrowser); e == nil {
		t.Fatal("bogus state accepted")
	}
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e != nil {
		t.Fatal(e)
	}
	// The state is single-use.
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("replayed state accepted")
	}
}

func TestOIDCNonceMismatch(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, _ := beginStateNonce(t, svc)
	fp.setNonce("attacker-chosen-nonce")
	_, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser)
	if e == nil || !strings.Contains(e.Error(), "nonce") {
		t.Fatalf("nonce mismatch not rejected: %v", e)
	}
}

func TestOIDCWrongIssuerRejected(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	fp.setIssuerOverride("https://evil.example")
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("wrong issuer accepted")
	}
}

func TestOIDCWrongAudienceRejected(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	fp.setAudOverride("another-client")
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("wrong audience accepted")
	}
}

func TestOIDCExpiredTokenRejected(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	fp.setExpired()
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("expired ID token accepted")
	}
}

func TestOIDCInvalidSignatureRejected(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp.setWrongKey(other)
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("token signed by a different key accepted")
	}
}

func TestOIDCVerifiedEmailRequired(t *testing.T) {
	fp := newFake(t, "user@example.com", false)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("unverified email accepted")
	}
}

func TestOIDCUserinfoFallbackVerifiedEmail(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	fp.setOmitEmail()
	tok, sess, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser)
	if e != nil {
		t.Fatalf("userinfo fallback failed: %v", e)
	}
	if tok == "" || sess.Email != "user@example.com" {
		t.Fatalf("session %+v", sess)
	}
}

func TestOIDCUserinfoFallbackUnverifiedRejected(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	fp.setOmitEmail()
	fp.setUserinfoVerified(false)
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("unverified userinfo email accepted")
	}
}

func TestOIDCAutoProvisionDisabledAndAccountLinking(t *testing.T) {
	fp := newFake(t, "admin@example.test", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, false, true)
	// A pre-existing user with a password can sign in through OIDC without
	// auto-provisioning, linking the verified email to the existing account.
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	tok, sess, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser)
	if e != nil {
		t.Fatal(e)
	}
	if tok == "" || sess.Email != "admin@example.test" {
		t.Fatalf("linked session %+v", sess)
	}
	// A brand-new email with auto-provision off is rejected.
	fp.setEmailForNext("other@example.com")
	state2, nonce2 := beginStateNonce(t, svc)
	fp.setNonce(nonce2)
	if _, _, e := svc.Callback(context.Background(), state2, "code", testRedirect, testBrowser); e == nil || !strings.Contains(e.Error(), "not provisioned") {
		t.Fatalf("auto-provision disabled leak: %v", e)
	}
}

func (f *fakeProvider) setEmailForNext(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.email = s
}

func TestOIDCDisabledProvider(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, st := newOIDCService(t, fp, true, false)
	if _, e := svc.Begin(context.Background(), testRedirect, testBrowser); e == nil {
		t.Fatal("disabled provider began a flow")
	}
	// Seed a state directly; a disabled provider must reject the callback.
	if e := sqlite.Exec(st.DB, `INSERT INTO oidc_states(state,nonce,browser,expires_at) VALUES('st','nc',?,?)`, testBrowser, time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)); e != nil {
		t.Fatal(e)
	}
	if _, _, e := svc.Callback(context.Background(), "st", "code", testRedirect, testBrowser); e == nil {
		t.Fatal("disabled provider accepted a callback")
	}
}

func TestOIDCBrowserBindingMismatchDoesNotConsume(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	// A different browser cannot use the transaction, and it does NOT destroy
	// the legitimate browser's valid state.
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, "browser-b"); e == nil {
		t.Fatal("cross-browser state consumption not rejected")
	}
	// The correct browser can still complete the transaction.
	tok, sess, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser)
	if e != nil {
		t.Fatalf("correct browser could not complete after wrong-browser attempt: %v", e)
	}
	if tok == "" || sess.Email != "user@example.com" {
		t.Fatalf("session %+v", sess)
	}
	// Once consumed by the correct browser, replay fails.
	if _, _, e := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser); e == nil {
		t.Fatal("replay after correct consumption allowed")
	}
}

func TestOIDCConcurrentConsumeOnlyOnce(t *testing.T) {
	fp := newFake(t, "user@example.com", true)
	defer fp.Close()
	svc, _ := newOIDCService(t, fp, true, true)
	state, nonce := beginStateNonce(t, svc)
	fp.setNonce(nonce)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := svc.Callback(context.Background(), state, "code", testRedirect, testBrowser)
			results[i] = err
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range results {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent callbacks consumed the state %d times, want 1", ok)
	}
}

func TestOIDCSaveRejectsBadDiscovery(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	svc := New(st, auth.New(st))
	if e := svc.Save(Config{Issuer: "http://not-https", ClientID: "x", ClientSecret: "y", Enabled: true, AutoProvision: false}); e == nil {
		t.Fatal("non-https issuer accepted")
	}
	// A reachable-but-invalid discovery endpoint must fail save time.
	if e := svc.Save(Config{Issuer: "https://127.0.0.1:1/", ClientID: "x", ClientSecret: "y", Enabled: true, AutoProvision: false}); e == nil {
		t.Fatal("unreachable issuer accepted")
	}
}

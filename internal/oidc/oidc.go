package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/webfleet-cv/webfleet/internal/auth"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

type Config struct {
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"`
	Enabled       bool   `json:"enabled"`
	AutoProvision bool   `json:"auto_provision"`
}

type Service struct {
	st     *store.Store
	auth   *auth.Service
	client *http.Client
	mu     sync.Mutex
	prov   map[string]*oidc.Provider
}

func New(st *store.Store, a *auth.Service) *Service {
	return &Service{st: st, auth: a, client: &http.Client{Timeout: 10 * time.Second}, prov: map[string]*oidc.Provider{}}
}

// SetHTTPClient replaces the outbound client (discovery, token, userinfo).
// Production uses the default bounded client; this is a test seam.
func (s *Service) SetHTTPClient(c *http.Client) {
	s.client = c
}

// rowConfig returns the stored configuration including the client secret.
// Callers that must sign a token request (Begin, Callback) use it; the public
// Config redacts the secret.
func (s *Service) rowConfig() (Config, error) {
	r, e := sqlite.Query(s.st.DB, `SELECT issuer,client_id,client_secret,enabled,auto_provision FROM oidc_config WHERE id=1`)
	if e != nil || len(r) == 0 {
		return Config{}, e
	}
	x := r[0]
	return Config{x["issuer"].Text, x["client_id"].Text, x["client_secret"].Text, x["enabled"].Int64 != 0, x["auto_provision"].Int64 != 0}, nil
}

func (s *Service) Config() (*Config, error) {
	c, e := s.rowConfig()
	if e != nil {
		return nil, e
	}
	c.ClientSecret = ""
	return &c, nil
}

func (s *Service) Save(c Config) error {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	if !strings.HasPrefix(c.Issuer, "https://") || c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("OIDC requires HTTPS issuer, client id and secret")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Discovery must succeed now so a misconfigured provider is rejected at
	// save time rather than at login time, and so the stored issuer is a
	// provider this deployment can actually reach.
	if _, e := s.provider(ctx, c.Issuer); e != nil {
		return fmt.Errorf("OIDC discovery failed: %w", e)
	}
	if e := sqlite.Exec(s.st.DB, `INSERT INTO oidc_config(id,issuer,client_id,client_secret,enabled,auto_provision,updated_at) VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET issuer=excluded.issuer,client_id=excluded.client_id,client_secret=excluded.client_secret,enabled=excluded.enabled,auto_provision=excluded.auto_provision,updated_at=excluded.updated_at`, c.Issuer, c.ClientID, c.ClientSecret, c.Enabled, c.AutoProvision, store.Now()); e != nil {
		return e
	}
	// Drop any cached provider so a reconfiguration (and a rotated JWKS) is
	// picked up on the next request.
	s.dropProvider(c.Issuer)
	return nil
}

func (s *Service) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s.mu.Lock()
	if p, ok := s.prov[issuer]; ok {
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()
	p, e := oidc.NewProvider(oidc.ClientContext(ctx, s.client), issuer)
	if e != nil {
		return nil, e
	}
	s.mu.Lock()
	s.prov[issuer] = p
	s.mu.Unlock()
	return p, nil
}

func (s *Service) dropProvider(issuer string) {
	s.mu.Lock()
	delete(s.prov, issuer)
	s.mu.Unlock()
}

func token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Begin starts an authorization transaction bound to the initiating browser.
// browser is a short-lived transient value carried in an HttpOnly cookie that
// the callback must reproduce; a state/code pair cannot be consumed by a
// different browser (login CSRF / session swapping protection).
func (s *Service) Begin(ctx context.Context, redirect, browser string) (string, error) {
	c, e := s.rowConfig()
	if e != nil || !c.Enabled {
		return "", errors.New("OIDC is not enabled")
	}
	p, e := s.provider(ctx, c.Issuer)
	if e != nil {
		return "", e
	}
	state, nonce := token(24), token(24)
	if e = sqlite.Exec(s.st.DB, `INSERT INTO oidc_states(state,nonce,browser,expires_at) VALUES(?,?,?,?)`, state, nonce, browser, time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339Nano)); e != nil {
		return "", e
	}
	v := url.Values{
		"client_id":     {c.ClientID},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"redirect_uri":  {redirect},
		"state":         {state},
		"nonce":         {nonce},
	}
	return p.Endpoint().AuthURL + "?" + v.Encode(), nil
}

// Callback exchanges the authorization code, cryptographically verifies the ID
// token (signature, issuer, audience, expiry) against the discovered keyset,
// enforces one-time state consumption, nonce equality and browser binding, and
// requires a verified email before creating a session. A syntactically
// JWT-shaped token is never accepted without passing this verification.
func (s *Service) Callback(ctx context.Context, state, code, redirect, browser string) (string, auth.Session, error) {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(code) == "" {
		return "", auth.Session{}, errors.New("OIDC callback is missing state or code")
	}
	// Atomic browser-bound one-time consume: the row is deleted only when both
	// the state and the initiating browser match. A different browser can
	// therefore neither establish a session nor destroy the legitimate
	// browser's transaction; two concurrent callbacks cannot both consume the
	// same state.
	r, e := sqlite.Query(s.st.DB, `DELETE FROM oidc_states WHERE state=? AND browser=? RETURNING expires_at,nonce`, state, browser)
	if e != nil || len(r) == 0 {
		return "", auth.Session{}, errors.New("invalid OIDC state")
	}
	storedNonce := r[0]["nonce"].Text
	exp, _ := time.Parse(time.RFC3339Nano, r[0]["expires_at"].Text)
	if time.Now().After(exp) {
		return "", auth.Session{}, errors.New("expired OIDC state")
	}
	c, e := s.rowConfig()
	if e != nil || !c.Enabled {
		return "", auth.Session{}, errors.New("OIDC disabled")
	}
	p, e := s.provider(ctx, c.Issuer)
	if e != nil {
		return "", auth.Session{}, e
	}
	rawID, accessToken, e := s.exchangeCode(ctx, p, c, code, redirect)
	if e != nil {
		return "", auth.Session{}, e
	}
	verifier := p.Verifier(&oidc.Config{ClientID: c.ClientID})
	idt, e := verifier.Verify(ctx, rawID)
	if e != nil {
		return "", auth.Session{}, fmt.Errorf("OIDC ID token verification failed: %w", e)
	}
	if idt.Nonce != storedNonce {
		return "", auth.Session{}, errors.New("OIDC nonce mismatch")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if e := idt.Claims(&claims); e != nil {
		return "", auth.Session{}, fmt.Errorf("OIDC claims invalid: %w", e)
	}
	if claims.Email == "" {
		// The provider omitted email/email_verified from the ID token; consult
		// userinfo only in that case. An explicit email_verified=false in the
		// ID token is authoritative and is rejected below.
		email, verified, ue := s.userinfo(ctx, p, accessToken, c.Issuer)
		if ue != nil {
			return "", auth.Session{}, ue
		}
		claims.Email, claims.EmailVerified = email, verified
	}
	if claims.Email == "" || !claims.EmailVerified {
		return "", auth.Session{}, errors.New("OIDC verified email required")
	}
	u, e := sqlite.Query(s.st.DB, `SELECT id,email FROM users WHERE lower(email)=lower(?)`, claims.Email)
	if e != nil {
		return "", auth.Session{}, e
	}
	if len(u) == 0 {
		if !c.AutoProvision {
			return "", auth.Session{}, errors.New("OIDC account is not provisioned")
		}
		org, e := s.st.PrimaryOrgID(ctx)
		if e != nil {
			return "", auth.Session{}, e
		}
		u, e = sqlite.Query(s.st.DB, `INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,'','viewer',?) RETURNING id,email`, strings.ToLower(strings.SplitN(claims.Email, "@", 2)[0]), strings.ToLower(claims.Email), store.Now())
		if e != nil {
			return "", auth.Session{}, e
		}
		_ = sqlite.Exec(s.st.DB, `INSERT INTO organization_memberships(organization_id,user_id,role,created_at) VALUES(?,?,'viewer',?)`, org, u[0]["id"].Int64, store.Now())
	}
	return s.auth.CreateSessionForUser(u[0]["id"].Int64, u[0]["email"].Text)
}

func (s *Service) exchangeCode(ctx context.Context, p *oidc.Provider, c Config, code, redirect string) (rawID, accessToken string, err error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}
	req, e := http.NewRequestWithContext(ctx, "POST", p.Endpoint().TokenURL, strings.NewReader(form.Encode()))
	if e != nil {
		return "", "", e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := s.client.Do(req)
	if e != nil {
		return "", "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", errors.New("OIDC token exchange failed")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if json.Unmarshal(body, &tr) != nil || tr.IDToken == "" {
		return "", "", errors.New("OIDC token exchange failed")
	}
	return tr.IDToken, tr.AccessToken, nil
}

// userinfo is a fallback source for verified email when the provider omits it
// from the ID token. The userinfo response is not signed; it is acceptable only
// after the ID token has been cryptographically verified and the issuer is
// consistent with the configured discovery issuer.
func (s *Service) userinfo(ctx context.Context, p *oidc.Provider, accessToken, issuer string) (email string, verified bool, err error) {
	ep := p.UserInfoEndpoint()
	if ep == "" {
		return "", false, errors.New("OIDC provider has no userinfo endpoint")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", ep, nil)
	if e != nil {
		return "", false, e
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, e := s.client.Do(req)
	if e != nil {
		return "", false, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false, errors.New("OIDC userinfo failed")
	}
	var ui struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Iss           string `json:"iss"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ui) != nil {
		return "", false, errors.New("OIDC userinfo failed")
	}
	if ui.Iss != "" && ui.Iss != issuer {
		return "", false, errors.New("OIDC userinfo issuer mismatch")
	}
	return ui.Email, ui.EmailVerified, nil
}

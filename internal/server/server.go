package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/webfleet-cv/webfleet/internal/analytics"
	"github.com/webfleet-cv/webfleet/internal/apitokens"
	"github.com/webfleet-cv/webfleet/internal/audit"
	"github.com/webfleet-cv/webfleet/internal/auth"
	clusterapi "github.com/webfleet-cv/webfleet/internal/cluster"
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/crawler"
	"github.com/webfleet-cv/webfleet/internal/databasesetup"
	"github.com/webfleet-cv/webfleet/internal/deployments"
	"github.com/webfleet-cv/webfleet/internal/dnsobs"
	"github.com/webfleet-cv/webfleet/internal/fleet"
	"github.com/webfleet-cv/webfleet/internal/geo"
	"github.com/webfleet-cv/webfleet/internal/incidents"
	"github.com/webfleet-cv/webfleet/internal/maintenance"
	"github.com/webfleet-cv/webfleet/internal/monitor"
	"github.com/webfleet-cv/webfleet/internal/notifications"
	"github.com/webfleet-cv/webfleet/internal/oidc"
	"github.com/webfleet-cv/webfleet/internal/performance"
	"github.com/webfleet-cv/webfleet/internal/rbac"
	"github.com/webfleet-cv/webfleet/internal/requestmeta"
	"github.com/webfleet-cv/webfleet/internal/sites"
	"github.com/webfleet-cv/webfleet/internal/store"
	"github.com/webfleet-cv/webfleet/internal/tlshealth"
)

//go:embed web/* web/assets/css/* web/assets/js/* web/assets/images/*
var embedded embed.FS

// principal is the resolved caller identity carried into authenticated
// handlers. OrgID and Role come from the caller's organization membership,
// never from a hard-coded organization id or URL.
type principal struct {
	UserID int64
	Email  string
	CSRF   string
	OrgID  int64
	Role   string
}

// handler is an authenticated handler signature. Unauthenticated routes are
// registered with the same signature and ignore the empty principal.
type handler func(http.ResponseWriter, *http.Request, principal)

// routeDef is one immutable route definition. The same definitions drive both
// actual registration (Server.routes) and the route-inventory contract test,
// so there is no mutable contract populated as a side effect of constructing a
// server, and the authorization contract cannot drift from what is shipped.
// tokenScopes declares which API-token scopes may authenticate this route; an
// empty value makes the route session-only (a Bearer token cannot reach it).
type routeDef struct {
	method      string
	path        string
	action      string
	csrf        bool
	build       func(*Server) handler
	tokenScopes []string
}

var apiRouteDefs = []routeDef{
	{"GET", "/healthz", "", false, func(s *Server) handler {
		return func(w http.ResponseWriter, r *http.Request, _ principal) {
			writeJSON(w, 200, map[string]any{"ok": true})
		}
	}, nil},
	{"GET", "/wf.js", "", false, func(s *Server) handler { return s.handleTracker }, nil},
	{"POST", "/api/analytics/event", "", false, func(s *Server) handler { return s.handleAnalyticsEvent }, nil},
	{"GET", "/api/setup/status", "", false, func(s *Server) handler { return s.handleSetupStatus }, nil},
	{"GET", "/api/setup/database", "", false, func(s *Server) handler { return s.handleDatabaseSetupStatus }, nil},
	{"POST", "/api/setup/database", "", false, func(s *Server) handler { return s.handleDatabaseSetup }, nil},
	{"POST", "/api/setup", "", false, func(s *Server) handler { return s.handleSetup }, nil},
	{"POST", "/api/login", "", false, func(s *Server) handler { return s.handleLogin }, nil},
	{"GET", "/api/oidc/login", "", false, func(s *Server) handler { return s.handleOIDCLogin }, nil},
	{"GET", "/api/oidc/callback", "", false, func(s *Server) handler { return s.handleOIDCCallback }, nil},
	{"GET", "/api/oidc/config", "organization.read", false, func(s *Server) handler { return s.handleOIDCConfig }, nil},
	{"PUT", "/api/oidc/config", "organization.update", true, func(s *Server) handler { return s.handleOIDCConfigSave }, nil},
	{"POST", "/api/logout", "session", true, func(s *Server) handler { return s.handleLogout }, nil},
	{"GET", "/api/session", "session", false, func(s *Server) handler { return s.handleSession }, nil},
	{"GET", "/api/launcher/instances", "", false, func(s *Server) handler { return s.handleLauncherInstances }, nil},
	{"PUT", "/api/launcher/config", "launcher.configure.all", true, func(s *Server) handler { return s.handleLauncherConfig }, nil},
	{"GET", "/api/cluster/v1/identity", "organization.read", false, func(s *Server) handler { return s.handleClusterIdentity }, nil},
	{"GET", "/api/cluster/v1/members", "organization.read", false, func(s *Server) handler { return s.handleClusterMembers }, nil},
	{"POST", "/api/cluster/v1/invitations", "membership.update", true, func(s *Server) handler { return s.handleClusterInvite }, nil},
	{"GET", "/api/cluster/v1/joins", "organization.read", false, func(s *Server) handler { return s.handleClusterPendingJoins }, nil},
	{"POST", "/api/cluster/v1/joins/{id}/{action}", "membership.update", true, func(s *Server) handler { return s.handleClusterJoinAction }, nil},
	{"GET", "/api/cluster/v1/outbound", "organization.read", false, func(s *Server) handler { return s.handleClusterOutbound }, nil},
	{"POST", "/api/cluster/v1/outbound", "membership.update", true, func(s *Server) handler { return s.handleClusterBeginOutbound }, nil},
	{"POST", "/api/cluster/v1/outbound/{id}/collect", "membership.update", true, func(s *Server) handler { return s.handleClusterCollectOutbound }, nil},
	{"POST", "/api/cluster/v1/members/{id}/{action}", "membership.update", true, func(s *Server) handler { return s.handleClusterMemberAction }, nil},
	{"GET", "/api/cluster/v1/status", "organization.read", false, func(s *Server) handler { return s.handleClusterStatus }, nil},
	{"GET", "/api/cluster/v1/audit", "organization.read", false, func(s *Server) handler { return s.handleClusterAudit }, nil},
	{"GET", "/api/cluster/v1/compare", "organization.read", false, func(s *Server) handler { return s.handleClusterCompare }, nil},
	{"POST", "/api/me/password", "session", true, func(s *Server) handler { return s.handleChangePassword }, nil},
	{"POST", "/api/tokens", "tokens.manage", true, func(s *Server) handler { return s.handleCreateToken }, nil},
	{"DELETE", "/api/tokens/{id}", "tokens.manage", true, func(s *Server) handler { return s.handleRevokeToken }, nil},
	{"GET", "/api/notifications/webhooks", "webhooks.read", false, func(s *Server) handler { return s.handleWebhooks }, nil},
	{"POST", "/api/notifications/webhooks", "webhooks.manage", true, func(s *Server) handler { return s.handleWebhookCreate }, nil},
	{"GET", "/api/notifications/deliveries", "webhooks.read", false, func(s *Server) handler { return s.handleNotificationDeliveries }, nil},
	{"GET", "/api/organization/members", "organization.read", false, func(s *Server) handler { return s.handleMembers }, nil},
	{"POST", "/api/organization/members", "membership.update", true, func(s *Server) handler { return s.handleMemberUpdate }, nil},
	{"GET", "/api/groups", "site.read", false, func(s *Server) handler { return s.handleGroups }, []string{"sites:read"}},
	{"POST", "/api/groups", "site.create", true, func(s *Server) handler { return s.handleCreateGroup }, []string{"sites:write"}},
	{"GET", "/api/sites", "site.read", false, func(s *Server) handler { return s.handleSites }, []string{"sites:read"}},
	{"POST", "/api/sites", "site.create", true, func(s *Server) handler { return s.handleCreateSite }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/tags", "site.read", false, func(s *Server) handler { return s.handleSiteTags }, []string{"sites:read"}},
	{"PUT", "/api/sites/{id}/tags", "site.update", true, func(s *Server) handler { return s.handleSiteTagsUpdate }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}", "site.read", false, func(s *Server) handler { return s.handleSite }, []string{"sites:read"}},
	{"PUT", "/api/sites/{id}", "site.update", true, func(s *Server) handler { return s.handleUpdateSite }, []string{"sites:write"}},
	{"POST", "/api/sites/{id}/archive", "site.archive", true, func(s *Server) handler { return s.handleArchiveSite }, []string{"sites:write"}},
	{"DELETE", "/api/sites/{id}", "site.delete", true, func(s *Server) handler { return s.handleDeleteSite }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/analytics", "analytics.read", false, func(s *Server) handler { return s.handleAnalyticsProperty }, []string{"analytics:read"}},
	{"POST", "/api/sites/{id}/analytics", "analytics.manage", true, func(s *Server) handler { return s.handleEnableAnalytics }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/analytics/summary", "analytics.read", false, func(s *Server) handler { return s.handleAnalyticsSummary }, []string{"analytics:read"}},
	{"GET", "/api/sites/{id}/analytics/pages", "analytics.read", false, func(s *Server) handler { return s.handleAnalyticsPages }, []string{"analytics:read"}},
	{"GET", "/api/sites/{id}/analytics/countries", "analytics.read", false, func(s *Server) handler { return s.handleAnalyticsCountries }, []string{"analytics:read"}},
	{"POST", "/api/sites/{id}/analytics/disable", "analytics.manage", true, func(s *Server) handler { return s.handleDisableAnalytics }, []string{"sites:write"}},
	{"POST", "/api/analytics/geo/update", "analytics.manage", true, func(s *Server) handler { return s.handleGeoUpdate }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/analytics/goals", "analytics.read", false, func(s *Server) handler { return s.handleAnalyticsGoals }, []string{"analytics:read"}},
	{"POST", "/api/sites/{id}/analytics/goals", "analytics.manage", true, func(s *Server) handler { return s.handleCreateAnalyticsGoal }, []string{"sites:write"}},
	{"GET", "/api/maintenance", "maintenance.read", false, func(s *Server) handler { return s.handleMaintenance }, nil},
	{"PUT", "/api/maintenance", "maintenance.manage", true, func(s *Server) handler { return s.handleMaintenanceUpdate }, nil},
	{"POST", "/api/maintenance/run", "maintenance.manage", true, func(s *Server) handler { return s.handleMaintenanceRun }, nil},
	{"GET", "/api/fleet", "fleet.read", false, func(s *Server) handler { return s.handleFleet }, []string{"fleet:read"}},
	{"GET", "/api/fleet/analytics", "analytics.read", false, func(s *Server) handler { return s.handleFleetAnalytics }, []string{"analytics:read"}},
	{"GET", "/api/sites/{id}/audit", "audit.read", false, func(s *Server) handler { return s.handleAudit }, []string{"sites:read"}},
	{"POST", "/api/sites/{id}/audit", "audit.run", true, func(s *Server) handler { return s.handleRunAudit }, []string{"audit:run"}},
	{"PUT", "/api/sites/{id}/audit/history", "audit.configure", true, func(s *Server) handler { return s.handleAuditHistorySetting }, []string{"sites:write"}},
	{"POST", "/api/audits/resolve", "audit.read", true, func(s *Server) handler { return s.handleResolveAudits }, []string{"audit:run"}},
	{"POST", "/api/audits/batch", "audit.run", true, func(s *Server) handler { return s.handleBatchAudits }, []string{"audit:run"}},
	{"POST", "/api/sites/{id}/check", "monitor.run", true, func(s *Server) handler { return s.handleCheckSite }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/deployments", "deployments.read", false, func(s *Server) handler { return s.handleDeployments }, []string{"sites:read"}},
	{"POST", "/api/sites/{id}/deployments", "deployments.record", true, func(s *Server) handler { return s.handleDeploymentRecord }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/deployments/correlation", "deployments.read", false, func(s *Server) handler { return s.handleDeploymentCorrelation }, []string{"sites:read"}},
	{"GET", "/api/sites/{id}/checks", "monitor.read", false, func(s *Server) handler { return s.handleSiteChecks }, []string{"sites:read"}},
	{"GET", "/api/sites/{id}/performance", "monitor.read", false, func(s *Server) handler { return s.handleSitePerformance }, []string{"sites:read"}},
	{"GET", "/api/sites/{id}/incidents", "incidents.read", false, func(s *Server) handler { return s.handleSiteIncidents }, []string{"sites:read"}},
	{"POST", "/api/incidents/{id}/ack", "incidents.acknowledge", true, func(s *Server) handler { return s.handleAckIncident }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/tls", "tls.read", false, func(s *Server) handler { return s.handleSiteTLS }, []string{"sites:read"}},
	{"POST", "/api/sites/{id}/tls/inspect", "tls.run", true, func(s *Server) handler { return s.handleInspectTLS }, []string{"sites:write"}},
	{"GET", "/api/fleet/tls", "tls.read", false, func(s *Server) handler { return s.handleFleetTLS }, []string{"fleet:read"}},
	{"GET", "/api/sites/{id}/dns", "dns.read", false, func(s *Server) handler { return s.handleSiteDNS }, []string{"sites:read"}},
	{"POST", "/api/sites/{id}/dns/observe", "dns.run", true, func(s *Server) handler { return s.handleObserveDNS }, []string{"sites:write"}},
	{"GET", "/api/sites/{id}/http-observations", "monitor.read", false, func(s *Server) handler { return s.handleHTTPObservations }, []string{"sites:read"}},
	{"GET", "/api/sites/{id}/crawl", "crawl.read", false, func(s *Server) handler { return s.handleSiteCrawl }, []string{"sites:read"}},
	{"POST", "/api/sites/{id}/crawl", "crawl.run", true, func(s *Server) handler { return s.handleCrawlSite }, []string{"sites:write"}},
	{"GET", "/api/fleet/link-regressions", "crawl.read", false, func(s *Server) handler { return s.handleFleetLinkRegressions }, []string{"fleet:read"}},
	{"GET", "/api/sites/{id}/header-expectations", "monitor.read", false, func(s *Server) handler { return s.handleHeaderExpectations }, []string{"sites:read"}},
	{"PUT", "/api/sites/{id}/header-expectations", "monitor.update", true, func(s *Server) handler { return s.handleHeaderExpectationUpdate }, []string{"sites:write"}},
}

type Server struct {
	cfg              config.Config
	store            *store.Store
	analytics        *analytics.Service
	tokens           *apitokens.Service
	audit            *audit.Service
	auth             *auth.Service
	sites            *sites.Service
	monitor          *monitor.Service
	maintenance      *maintenance.Service
	rbac             *rbac.Service
	oidc             *oidc.Service
	notifications    *notifications.Service
	incidents        *incidents.Service
	tls              *tlshealth.Service
	dns              *dnsobs.Service
	deployments      *deployments.Service
	crawler          *crawler.Service
	cluster          *clusterapi.Service
	clusterTransport *clusterapi.Transport
	geo              *geo.Manager
	log              *slog.Logger
	http             *http.Server
	mux              *http.ServeMux
	proxy            requestmeta.Config
	loginLim         *rateLimiter
	setupLim         *rateLimiter
	tokenLim         *rateLimiter
	passwordLim      *rateLimiter
}

func New(cfg config.Config, st *store.Store, log *slog.Logger) *Server {
	a := analytics.NewWithOptions(st, analytics.Options{AllowNoOrigin: cfg.AnalyticsServerSide})
	s := &Server{cfg: cfg, store: st, analytics: a, tokens: apitokens.New(st), audit: audit.NewWithOptions(st, audit.Options{Sandbox: cfg.AuditSandbox}), auth: auth.New(st), sites: sites.New(st), monitor: monitor.New(st), maintenance: maintenance.New(st), rbac: rbac.New(st), incidents: incidents.New(st), tls: tlshealth.New(st), dns: dnsobs.New(st), deployments: deployments.New(st), crawler: crawler.New(st), geo: geo.NewManager(cfg.DataDir, cfg.GeoIPURL), log: log, mux: http.NewServeMux(), proxy: requestmeta.Config{Trusted: cfg.TrustedProxies}, loginLim: newRateLimiter(time.Minute, 10, 10000), setupLim: newRateLimiter(time.Minute, 5, 1000), tokenLim: newRateLimiter(time.Minute, 20, 10000), passwordLim: newRateLimiter(time.Minute, 10, 10000)}
	s.cluster = clusterapi.New(st.DB)
	s.clusterTransport = clusterapi.NewTransport(st.DB, s.cluster, nil)
	s.oidc = oidc.New(st, s.auth)
	s.notifications = notifications.New(st)
	// Local country database: load any already-installed copy (no network); when
	// auto-update is enabled, install one in the background so country analytics
	// work out of the box.
	if s.geo.LoadExisting() {
		a.SetGeo(s.geo.DB())
	}
	// Auto-update covers both missing and stale databases (DB-IP Lite is
	// monthly); an existing fresh database is served without a network request.
	if cfg.GeoIPAutoUpdate && s.geo.NeedsRefresh() {
		go func() {
			if err := s.geo.EnsureCurrent(context.Background()); err == nil {
				a.SetGeo(s.geo.DB())
			} else {
				log.Warn("geoip auto-install/refresh failed", "error", err)
			}
		}()
	}
	s.routes()
	s.http = &http.Server{Addr: cfg.Listen, Handler: s.mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	return s
}

func NewAnalyticsIngest(cfg config.Config, st *store.Store, log *slog.Logger) *Server {
	a := analytics.NewWithOptions(st, analytics.Options{AllowNoOrigin: cfg.AnalyticsServerSide})
	s := &Server{cfg: cfg, store: st, analytics: a, geo: geo.NewManager(cfg.DataDir, cfg.GeoIPURL), log: log, mux: http.NewServeMux()}
	if s.geo.LoadExisting() {
		a.SetGeo(s.geo.DB())
	}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "mode": "analytics-ingest"})
	})
	s.mux.HandleFunc("GET /wf.js", func(w http.ResponseWriter, r *http.Request) { s.handleTracker(w, r, principal{}) })
	s.mux.HandleFunc("POST /api/analytics/event", func(w http.ResponseWriter, r *http.Request) { s.handleAnalyticsEvent(w, r, principal{}) })
	s.http = &http.Server{Addr: cfg.Listen, Handler: s.mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	return s
}

// OperationRoute describes one concrete runtime API route for functional
// coverage certification. It is projected directly from apiRouteDefs so the
// matrix cannot silently diverge from shipped authorization/token policy.
type OperationRoute struct {
	Method      string
	Path        string
	Action      string
	CSRF        bool
	TokenScopes []string
	Service     bool
}

// OperationRouteInventory returns the immutable runtime route surface,
// including the node-only cluster transport endpoints registered beside the
// human API table.
func OperationRouteInventory() []OperationRoute {
	out := make([]OperationRoute, 0, len(apiRouteDefs)+4)
	for _, d := range apiRouteDefs {
		out = append(out, OperationRoute{Method: d.method, Path: d.path, Action: d.action, CSRF: d.csrf, TokenScopes: append([]string(nil), d.tokenScopes...)})
	}
	out = append(out,
		OperationRoute{Method: "POST", Path: "/api/cluster/v1/join", Service: true},
		OperationRoute{Method: "GET", Path: "/api/cluster/v1/join/{id}", Service: true},
		OperationRoute{Method: "GET", Path: "/api/cluster/v1/rpc/summary", Service: true},
		OperationRoute{Method: "GET", Path: "/api/cluster/v1/rpc/compare", Service: true},
	)
	return out
}

// routes registers the application HTTP surface from the immutable apiRouteDefs
// table. Every authenticated route declares its required permission and CSRF
// posture here; adding a handler without a permission is a table change that
// the route-inventory contract test will reject.
func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/cluster/v1/join", s.handleClusterJoin)
	s.mux.HandleFunc("GET /api/cluster/v1/join/{id}", s.handleClusterPollJoin)
	s.mux.HandleFunc("GET /api/cluster/v1/rpc/summary", s.handleClusterRPCSummary)
	s.mux.HandleFunc("GET /api/cluster/v1/rpc/compare", s.handleClusterRPCCompare)
	for _, def := range apiRouteDefs {
		pattern := def.method + " " + def.path
		h := def.build(s)
		if def.action == "" {
			s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { h(w, r, principal{}) })
		} else {
			s.mux.HandleFunc(pattern, s.authorize(def.action, def.csrf, def.tokenScopes, h))
		}
	}
	sub, _ := fs.Sub(embedded, "web")
	static := http.FileServer(http.FS(sub))
	s.mux.Handle("/assets/", static)
	s.mux.Handle("/launcher.css", static)
	s.mux.Handle("/launcher.js", static)
	s.mux.Handle("/manage.css", static)
	s.mux.Handle("/manage.js", static)
	s.mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusPermanentRedirect)
	})
	s.mux.Handle("/app/", http.StripPrefix("/app", static))
	s.mux.HandleFunc("/manage", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/manage/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /manage/", s.authorize("membership.update", false, nil, func(w http.ResponseWriter, r *http.Request, _ principal) {
		clone := r.Clone(r.Context())
		clone.URL.Path = "/manage.html"
		static.ServeHTTP(w, clone)
	}))
	s.mux.Handle("/", s.launcherRoot(static))
}

// authorize resolves the caller for an authenticated request. A session cookie
// yields a session principal with CSRF enforcement and the membership-derived
// role; when no session cookie is present and the route exposes an API-token
// scope, a Bearer token is accepted as an alternative principal whose
// authorization is exactly its token scopes (never the creator's role or
// session). Routes without a token scope are session-only: a Bearer token
// cannot reach them.
func (s *Server) authorize(action string, csrf bool, tokenScopes []string, next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("webfleet_session"); err == nil {
			sess, serr := s.auth.Session(c.Value)
			if serr != nil {
				writeError(w, 401, "authentication required")
				return
			}
			if csrf && r.Header.Get("X-CSRF-Token") != sess.CSRF {
				writeError(w, 403, "invalid CSRF token")
				return
			}
			m, merr := s.rbac.Resolve(sess.UserID)
			if merr != nil {
				writeError(w, 403, "no organization membership")
				return
			}
			if action != "session" && !rbac.Can(m.Role, action) {
				writeError(w, 403, "permission denied")
				return
			}
			next(w, r, principal{UserID: sess.UserID, Email: sess.Email, CSRF: sess.CSRF, OrgID: m.OrgID, Role: m.Role})
			return
		}
		if len(tokenScopes) > 0 {
			if p, ok, handled := s.tokenPrincipal(w, r, tokenScopes); handled {
				return
			} else if ok {
				next(w, r, p)
				return
			}
		}
		writeError(w, 401, "authentication required")
	}
}

// tokenPrincipal authenticates an API token and grants exactly the token's
// scopes. The acting organization is the token's organization, so a token can
// never cross organization boundaries or inherit the privileges of the browser
// session that created it. Failed/malformed authentication is throttled per
// resolved client address (so spoofed X-Forwarded-For cannot bypass it) and
// never keyed on token material. Exactly one layer writes the HTTP response:
// handled=true means this function already did.
func (s *Server) tokenPrincipal(w http.ResponseWriter, r *http.Request, requiredScopes []string) (principal, bool, bool) {
	authz := r.Header.Get("Authorization")
	// Any request presenting a Bearer credential (including an empty or
	// malformed value) enters the abuse-control path so it is throttled like a
	// failed token; non-Bearer/absent Authorization headers fall through to
	// ordinary unauthenticated handling.
	if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return principal{}, false, false
	}
	raw := strings.TrimSpace(authz[len("Bearer "):])
	uid, org, tokScopes, err := s.tokens.Authenticate(raw)
	if err != nil {
		if !s.tokenLim.Allow("token:" + s.proxy.ClientIP(r)) {
			writeError(w, 429, "too many invalid token attempts")
			return principal{}, false, true
		}
		// A single generic message for unknown and revoked tokens avoids
		// leaking token existence.
		writeError(w, 401, "invalid API token")
		return principal{}, false, true
	}
	ok := false
	for _, scope := range requiredScopes {
		if apitokens.HasScope(tokScopes, scope) {
			ok = true
			break
		}
	}
	if !ok {
		writeError(w, 403, "token scope denied")
		return principal{}, false, true
	}
	return principal{UserID: uid, OrgID: org, Role: "token"}, true, false
}

// site loads a site after verifying it belongs to the caller's organization.
// Cross-organization access returns 404 so site existence is not disclosed.
func (s *Server) site(w http.ResponseWriter, p principal, id int64) (sites.Site, bool) {
	site, err := s.sites.GetForOrg(p.OrgID, id)
	if err != nil {
		writeError(w, 404, "site not found")
		return sites.Site{}, false
	}
	return site, true
}

func (s *Server) handleTracker(w http.ResponseWriter, r *http.Request, _ principal) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public,max-age=3600")
	_, _ = w.Write([]byte(analytics.Tracker))
}
func (s *Server) handleAnalyticsEvent(w http.ResponseWriter, r *http.Request, _ principal) {
	var in analytics.Event
	if !decodeJSON(w, r, &in) {
		return
	}
	origin := r.Header.Get("Origin")
	ip := s.proxy.ClientIP(r)
	if ip == "" {
		if h, _, e := net.SplitHostPort(r.RemoteAddr); e == nil {
			ip = h
		} else {
			ip = r.RemoteAddr
		}
	}
	if err := s.analytics.Ingest(in, origin, ip, r.UserAgent()); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request, p principal) {
	x, e := s.maintenance.Status()
	if e != nil {
		writeError(w, 500, "maintenance status unavailable")
		return
	}
	writeJSON(w, 200, x)
}
func (s *Server) handleMaintenanceUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	var v maintenance.Settings
	if !decodeJSON(w, r, &v) {
		return
	}
	if e := s.maintenance.Set(v); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleMaintenanceRun(w http.ResponseWriter, r *http.Request, p principal) {
	if e := s.maintenance.Run(); e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleFleetAnalytics(w http.ResponseWriter, r *http.Request, p principal) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	out, err := s.analytics.Fleet(p.OrgID, days)
	if err != nil {
		writeError(w, 500, "fleet analytics unavailable")
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleAnalyticsGoals(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	g, e := s.analytics.Goals(id)
	if e != nil {
		writeError(w, 500, "analytics goals unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"goals": g})
}
func (s *Server) handleCreateAnalyticsGoal(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var in struct {
		Name      string `json:"name"`
		EventKind string `json:"event_kind"`
		PathMatch string `json:"path_match"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	g, e := s.analytics.CreateGoal(id, in.Name, in.EventKind, in.PathMatch)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 201, g)
}
func (s *Server) handleAnalyticsSummary(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	out, err := s.analytics.Summary(id, days)
	if err != nil {
		writeError(w, 500, "analytics summary unavailable")
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleAnalyticsProperty(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	prop, err := s.analytics.Property(id)
	if err != nil {
		writeError(w, 500, "analytics unavailable")
		return
	}
	out := map[string]any{"property": prop}
	if prop != nil && prop.Enabled {
		origin := s.cfg.PublicURL
		if origin == "" {
			origin = "https://" + r.Host
		}
		out["snippet"] = s.analytics.TrackerSnippet(origin, prop.PublicKey)
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleEnableAnalytics(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	prop, err := s.analytics.Enable(id)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	origin := s.cfg.PublicURL
	if origin == "" {
		origin = "https://" + r.Host
	}
	writeJSON(w, 201, map[string]any{"property": prop, "snippet": s.analytics.TrackerSnippet(origin, prop.PublicKey)})
}

func (s *Server) handleDisableAnalytics(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	if err := s.analytics.Disable(id); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleAnalyticsPages(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	ps, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	out, err := s.analytics.Pages(id, days, page, ps)
	if err != nil {
		writeError(w, 500, "analytics pages unavailable")
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleAnalyticsCountries(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	ps, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	out, err := s.analytics.Countries(id, days, page, ps)
	if err != nil {
		writeError(w, 500, "analytics countries unavailable")
		return
	}
	out.Available = s.geo != nil && s.geo.DB() != nil
	out.Updated = ""
	out.Ranges = 0
	if s.geo != nil && s.geo.DB() != nil {
		out.Updated = s.geo.LastUpdated()
		out.Ranges = s.geo.DB().Ranges()
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleGeoUpdate(w http.ResponseWriter, r *http.Request, _ principal) {
	// Local country database install/refresh (DB-IP Lite, CC BY 4.0). Downloads
	// are validated before an atomic swap; a failed update keeps the previous
	// database. Runs in the background so the request does not block.
	if s.geo == nil {
		writeError(w, 500, "GeoIP not configured")
		return
	}
	go func() {
		if err := s.geo.Update(context.WithoutCancel(r.Context())); err == nil {
			s.analytics.SetGeo(s.geo.DB())
		}
	}()
	writeJSON(w, 202, map[string]any{"status": "installing"})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	runs, err := s.audit.History(id)
	if err != nil {
		writeError(w, 500, "audit unavailable")
		return
	}
	hist, _ := s.audit.HistoryEnabled(id)
	writeJSON(w, 200, map[string]any{"history_enabled": hist, "runs": runs})
}
func (s *Server) handleRunAudit(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	if !s.audit.Claim(id) {
		writeError(w, 409, "an audit is already running for this site")
		return
	}
	go func() {
		defer s.audit.Release(id)
		_, _ = s.audit.Run(context.WithoutCancel(r.Context()), id)
	}()
	writeJSON(w, 202, map[string]any{"status": "running"})
}
func (s *Server) handleAuditHistorySetting(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.audit.SetHistory(id, in.Enabled); err != nil {
		writeError(w, 500, "audit setting unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleResolveAudits(w http.ResponseWriter, r *http.Request, p principal) {
	var in audit.BatchFilter
	if !decodeJSON(w, r, &in) {
		return
	}
	ids, err := s.audit.ResolveBatch(p.OrgID, in)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"site_ids": ids, "count": len(ids)})
}
func (s *Server) handleBatchAudits(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		SiteIDs []int64 `json:"site_ids"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.SiteIDs) > 100 {
		writeError(w, 400, "batch audit limit is 100 sites")
		return
	}
	writeJSON(w, 200, map[string]any{"results": s.audit.RunBatch(r.Context(), p.OrgID, in.SiteIDs)})
}

func (s *Server) handleDatabaseSetupStatus(w http.ResponseWriter, r *http.Request, _ principal) {
	w.Header().Set("Cache-Control", "no-store")
	x, e := databasesetup.StateFor(s.store, s.cfg.DataDir)
	if e != nil {
		writeError(w, 500, "database setup unavailable")
		return
	}
	writeJSON(w, 200, x)
}
func (s *Server) handleDatabaseSetup(w http.ResponseWriter, r *http.Request, _ principal) {
	var in struct {
		Provider string `json:"provider"`
		URL      string `json:"url"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	x, e := databasesetup.Apply(r.Context(), s.store, s.cfg.DataDir, in.Provider, in.URL)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, x)
}

// oidcRedirect returns the canonical OIDC callback URI. The external origin is
// explicit and fail-closed: it comes only from WEBFLEET_PUBLIC_URL and never
// from the incoming Host header, X-Forwarded-Host or Forwarded. Without a
// configured canonical origin OIDC cannot be used (""), and the login/config
// handlers reject with a clear error rather than constructing an attacker-
// controllable redirect URI.
func (s *Server) oidcRedirect(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL + "/api/oidc/callback"
	}
	return ""
}

func (s *Server) oidcOriginReady() bool { return s.cfg.PublicURL != "" }

const oidcBindingCookie = "wf_oidc_binding"

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request, _ principal) {
	if !s.oidcOriginReady() {
		writeError(w, 400, "OIDC requires WEBFLEET_PUBLIC_URL (canonical external origin)")
		return
	}
	browser, e := randomToken(18)
	if e != nil {
		writeError(w, 500, "OIDC login unavailable")
		return
	}
	u, e := s.oidc.Begin(r.Context(), s.oidcRedirect(r), browser)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	// The binding cookie ties this authorization transaction to this browser
	// and follows the same trusted-proxy Secure decision as the session cookie.
	http.SetCookie(w, &http.Cookie{Name: oidcBindingCookie, Value: browser, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.proxy.Secure(r), MaxAge: 600})
	http.Redirect(w, r, u, http.StatusFound)
}
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request, _ principal) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		writeError(w, 401, "OIDC authorization failed")
		return
	}
	if !s.oidcOriginReady() {
		writeError(w, 400, "OIDC requires WEBFLEET_PUBLIC_URL (canonical external origin)")
		return
	}
	browser := ""
	if c, err := r.Cookie(oidcBindingCookie); err == nil {
		browser = c.Value
	}
	tok, _, e := s.oidc.Callback(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"), s.oidcRedirect(r), browser)
	if e != nil {
		writeError(w, 401, e.Error())
		return
	}
	// Consumed: clear the transient binding and establish the session.
	http.SetCookie(w, &http.Cookie{Name: oidcBindingCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.proxy.Secure(r), MaxAge: -1})
	s.setSessionCookie(w, r, tok)
	http.Redirect(w, r, "/", http.StatusFound)
}
func (s *Server) handleOIDCConfig(w http.ResponseWriter, r *http.Request, p principal) {
	c, e := s.oidc.Config()
	if e != nil {
		writeJSON(w, 200, map[string]any{"config": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"config": c})
}
func (s *Server) handleOIDCConfigSave(w http.ResponseWriter, r *http.Request, p principal) {
	var c oidc.Config
	if !decodeJSON(w, r, &c) {
		return
	}
	if c.Enabled && !s.oidcOriginReady() {
		writeError(w, 400, "OIDC requires WEBFLEET_PUBLIC_URL (canonical external origin)")
		return
	}
	if e := s.oidc.Save(c); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request, _ principal) {
	w.Header().Set("Cache-Control", "no-store")
	need, err := s.auth.NeedsSetup()
	if err != nil {
		writeError(w, 500, "setup status unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"needs_setup": need, "min_password_length": auth.MinPasswordLength})
}
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request, _ principal) {
	if !s.setupLim.Allow("setup:" + s.proxy.ClientIP(r)) {
		writeError(w, 429, "too many setup attempts, try again later")
		return
	}
	var in struct{ Email, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.auth.CreateAdmin(in.Email, in.Password); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	token, sess, err := s.auth.Login(in.Email, in.Password)
	if err != nil {
		writeError(w, 500, "admin created but login failed")
		return
	}
	s.setSessionCookie(w, r, token)
	writeJSON(w, 201, map[string]any{"email": sess.Email, "csrf": sess.CSRF})
}
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ principal) {
	if !s.loginLim.Allow("login:" + s.proxy.ClientIP(r)) {
		writeError(w, 429, "too many login attempts, try again later")
		return
	}
	var in struct{ Email, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	token, sess, err := s.auth.Login(in.Email, in.Password)
	if err != nil {
		writeError(w, 401, "invalid credentials")
		return
	}
	s.setSessionCookie(w, r, token)
	writeJSON(w, 200, map[string]any{"email": sess.Email, "csrf": sess.CSRF})
}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p principal) {
	c, _ := r.Cookie("webfleet_session")
	if c != nil {
		s.auth.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "webfleet_session", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.proxy.Secure(r), MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.passwordLim.Allow("password:" + s.proxy.ClientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "too many password attempts, try again later")
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	cookie, err := r.Cookie("webfleet_session")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if err = s.auth.ChangePassword(r.Context(), p.UserID, in.CurrentPassword, in.NewPassword, cookie.Value); err != nil {
		if errors.Is(err, auth.ErrInvalidCurrentPassword) {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
func (s *Server) handleSiteCrawl(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	detail, err := s.crawler.LatestDetail(id)
	if err != nil {
		writeJSON(w, 200, map[string]any{"crawl": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"crawl": detail})
}

func (s *Server) handleCrawlSite(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	if !s.crawler.Claim(id) {
		writeError(w, 409, "a crawl is already in progress for this site")
		return
	}
	// Run the crawl in the background so the SPA can poll live progress from
	// GET /api/sites/{id}/crawl (the running row is updated as pages are
	// processed). The request context must not cancel the crawl once this
	// handler returns.
	go func() {
		defer s.crawler.Release(id)
		s.crawler.CrawlSite(context.WithoutCancel(r.Context()), id)
	}()
	writeJSON(w, 202, map[string]any{"status": "running"})
}

func (s *Server) handleFleetLinkRegressions(w http.ResponseWriter, r *http.Request, p principal) {
	runs, err := s.crawler.FleetRegressions(p.OrgID)
	if err != nil {
		writeError(w, 500, "link regressions unavailable")
		return
	}
	out := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		site, err := s.sites.GetForOrg(p.OrgID, run.SiteID)
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"site": site, "crawl": run})
	}
	writeJSON(w, 200, map[string]any{"regressions": out})
}

func (s *Server) handleHTTPObservations(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	rows, err := s.monitor.HTTPHistory(id)
	if err != nil {
		writeError(w, 500, "HTTP observations unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"observations": rows})
}
func (s *Server) handleHeaderExpectations(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	x, err := s.monitor.HeaderExpectations(id)
	if err != nil {
		writeError(w, 500, "header expectations unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"expectations": x})
}
func (s *Server) handleHeaderExpectationUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var in struct {
		Name     string `json:"name"`
		Required bool   `json:"required"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.monitor.SetHeaderExpectation(id, in.Name, in.Required); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleSiteDNS(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	rows, err := s.dns.History(id)
	if err != nil {
		writeError(w, 500, "DNS history unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"observations": rows})
}
func (s *Server) handleObserveDNS(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	obs, err := s.dns.ObserveSite(r.Context(), id)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, obs)
}

func (s *Server) handleSiteTLS(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	obs, err := s.tls.Latest(id)
	if err != nil {
		writeJSON(w, 200, map[string]any{"observation": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"observation": obs})
}
func (s *Server) handleInspectTLS(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	obs, err := s.tls.InspectSite(r.Context(), id)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, obs)
}
func (s *Server) handleFleetTLS(w http.ResponseWriter, r *http.Request, p principal) {
	rows, err := s.tls.FleetWarnings(p.OrgID, 30)
	if err != nil {
		writeError(w, 500, "TLS warnings unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"warnings": rows})
}

func (s *Server) handleSiteIncidents(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	rows, err := s.incidents.List(id)
	if err != nil {
		writeError(w, 500, "incident history unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"incidents": rows})
}
func (s *Server) handleAckIncident(w http.ResponseWriter, r *http.Request, p principal) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid incident id")
		return
	}
	if err = s.incidents.Acknowledge(p.OrgID, id, store.Now()); err != nil {
		writeError(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request, p principal) {
	sum, err := fleet.SummaryFor(s.store, p.OrgID)
	if err != nil {
		writeError(w, 500, "fleet summary unavailable")
		return
	}
	writeJSON(w, 200, sum)
}
func (s *Server) handleCheckSite(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	res, err := s.monitor.CheckSite(r.Context(), id)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_, _ = s.tls.InspectSite(r.Context(), id)
	_, _ = s.dns.ObserveSite(r.Context(), id)
	writeJSON(w, 200, res)
}
func (s *Server) handleSitePerformance(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	out, err := performance.ForSite(s.store, id, 200)
	if err != nil {
		writeError(w, 500, "performance history unavailable")
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleDeployments(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	x, e := s.deployments.History(id)
	if e != nil {
		writeError(w, 500, "deployments unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"deployments": x})
}
func (s *Server) handleDeploymentRecord(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var x deployments.Event
	if !decodeJSON(w, r, &x) {
		return
	}
	x.SiteID = id
	v, e := s.deployments.Record(x)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 201, v)
}
func (s *Server) handleDeploymentCorrelation(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	x, e := s.deployments.Correlate(id)
	if e != nil {
		writeError(w, 500, "deployment correlation unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"correlation": x})
}
func (s *Server) handleSiteChecks(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	rows, err := s.monitor.Recent(id, 50)
	if err != nil {
		writeError(w, 500, "check history unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"checks": rows})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	x, e := s.tokens.Create(p.UserID, p.OrgID, in.Name, in.Scopes)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 201, x)
}
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, p principal) {
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		writeError(w, 400, "invalid token id")
		return
	}
	if e = s.tokens.Revoke(id, p.UserID, p.OrgID); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request, p principal) {
	x, e := s.notifications.List(p.OrgID)
	if e != nil {
		writeError(w, 500, "webhooks unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"webhooks": x})
}
func (s *Server) handleWebhookCreate(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	x, secret, e := s.notifications.Create(p.OrgID, in.Name, in.URL)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"webhook": x, "secret": secret})
}
func (s *Server) handleNotificationDeliveries(w http.ResponseWriter, r *http.Request, p principal) {
	x, e := s.notifications.History(p.OrgID)
	if e != nil {
		writeError(w, 500, "delivery history unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"deliveries": x})
}
func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request, p principal) {
	m, e := s.rbac.Members(p.OrgID)
	if e != nil {
		writeError(w, 500, "members unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"members": m, "role": p.Role})
}
func (s *Server) handleMemberUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if e := s.rbac.Add(p.UserID, p.OrgID, in.Email, in.Role); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, p principal) {
	groups, err := s.sites.Groups(p.OrgID)
	if err != nil {
		writeError(w, 500, "groups unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"groups": groups})
}
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	g, err := s.sites.CreateGroup(p.OrgID, in.Name)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, g)
}
func (s *Server) handleSites(w http.ResponseWriter, r *http.Request, p principal) {
	q := r.URL.Query()
	group, _ := strconv.ParseInt(q.Get("group"), 10, 64)
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	var out sites.List
	var err error
	if tag := q.Get("tag"); tag != "" && q.Get("archived") != "1" {
		out, err = s.sites.ListByTag(p.OrgID, q.Get("q"), group, tag, page, size)
	} else {
		out, err = s.sites.List(p.OrgID, q.Get("q"), group, page, size, q.Get("archived") == "1")
	}
	if err != nil {
		writeError(w, 500, "sites unavailable")
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		Name       string `json:"name"`
		PrimaryURL string `json:"primary_url"`
		GroupID    int64  `json:"group_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	site, err := s.sites.Create(p.OrgID, in.Name, in.PrimaryURL, in.GroupID)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, site)
}
func pathSiteID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := sites.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid site id")
		return 0, false
	}
	return id, true
}
func (s *Server) handleSiteTags(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	x, e := s.sites.Tags(p.OrgID, id)
	if e != nil {
		writeError(w, 500, "tags unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"tags": x})
}
func (s *Server) handleSiteTagsUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var in struct {
		Tags []string `json:"tags"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if e := s.sites.SetTags(p.OrgID, id, in.Tags); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleSite(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	site, ok := s.site(w, p, id)
	if !ok {
		return
	}
	writeJSON(w, 200, site)
}
func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var in struct {
		Name       string `json:"name"`
		PrimaryURL string `json:"primary_url"`
		GroupID    int64  `json:"group_id"`
		Enabled    bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	site, err := s.sites.Update(p.OrgID, id, in.Name, in.PrimaryURL, in.GroupID, in.Enabled)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, site)
}
func (s *Server) handleArchiveSite(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	var in struct {
		Archived bool `json:"archived"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.sites.Archive(p.OrgID, id, in.Archived); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request, p principal) {
	id, ok := pathSiteID(w, r)
	if !ok {
		return
	}
	if _, ok = s.site(w, p, id); !ok {
		return
	}
	if err := s.sites.Delete(p.OrgID, id); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, p principal) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"email": p.Email, "csrf": p.CSRF, "role": p.Role, "org_id": p.OrgID})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: "webfleet_session", Value: token, Path: "/", HttpOnly: true, Secure: s.proxy.Secure(r), SameSite: http.SameSiteStrictMode, MaxAge: 86400})
}

// randomToken returns a cryptographically random URL-safe token.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, 400, "invalid JSON request")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": strings.TrimSpace(msg)})
}
func (s *Server) ListenAndServe() error              { return s.http.ListenAndServe() }
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }
func (s *Server) Handler() http.Handler              { return s.mux }

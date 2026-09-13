package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/webfleet-cv/webfleet/internal/rbac"
)

// knownActions is the authoritative action vocabulary. Adding a route with a
// new action here is the only way to extend the permission matrix; the test
// below rejects unknown actions.
var knownActions = map[string]bool{
	"organization.read": true, "organization.update": true, "organization.delete": true,
	"membership.update": true,
	"tokens.manage":     true,
	"webhooks.read":     true, "webhooks.manage": true,
	"maintenance.read": true, "maintenance.manage": true,
	"fleet.read": true,
	"site.read":  true, "site.create": true, "site.update": true, "site.archive": true, "site.delete": true,
	"monitor.read": true, "monitor.run": true, "monitor.update": true,
	"audit.read": true, "audit.run": true, "audit.configure": true,
	"crawl.read": true, "crawl.run": true,
	"tls.read": true, "tls.run": true,
	"dns.read": true, "dns.run": true,
	"analytics.read": true, "analytics.manage": true,
	"incidents.read": true, "incidents.acknowledge": true,
	"deployments.read": true, "deployments.record": true,
	"launcher.configure.all": true,
	"session":                true,
}

// knownTokenScopes is the documented API-token scope vocabulary. A route may
// accept an API token only when it lists one or more of these scopes.
var knownTokenScopes = map[string]bool{
	"sites:read": true, "sites:write": true,
	"fleet:read": true, "analytics:read": true, "audit:run": true,
}

// minRoleFor returns the least-privileged role that can perform the action.
func minRoleFor(action string) string {
	if action == "session" {
		return "viewer"
	}
	for _, role := range []string{"viewer", "operator", "admin", "owner"} {
		if rbac.Can(role, action) {
			return role
		}
	}
	return ""
}

// docRoute mirrors docs/hardening/route-inventory.json entries.
type docRoute struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Action      string   `json:"action"`
	CSRF        bool     `json:"csrf"`
	SiteScoped  bool     `json:"siteScoped"`
	MinRole     string   `json:"minRole"`
	TokenScopes []string `json:"tokenScopes,omitempty"`
}
type docInventory struct {
	Actions []string   `json:"actions"`
	Routes  []docRoute `json:"routes"`
}

func TestRouteContractIsCompleteAndConsistent(t *testing.T) {
	if len(apiRouteDefs) == 0 {
		t.Fatal("route definitions are empty; apiRouteDefs must be populated")
	}
	seen := map[string]bool{}
	for _, rt := range apiRouteDefs {
		key := rt.method + " " + rt.path
		if seen[key] {
			t.Fatalf("duplicate route %s", key)
		}
		seen[key] = true
		if rt.action == "" {
			continue
		}
		if !knownActions[rt.action] {
			t.Fatalf("route %s uses unknown action %q; extend knownActions deliberately", key, rt.action)
		}
		for _, sc := range rt.tokenScopes {
			if !knownTokenScopes[sc] {
				t.Fatalf("route %s uses unknown token scope %q", key, sc)
			}
		}
		// CSRF posture: every state-changing authenticated route must be
		// CSRF-protected; GET routes are read-only and exempt.
		if rt.method != "GET" && !rt.csrf {
			t.Fatalf("authenticated non-GET route %s must require CSRF", key)
		}
		if rt.method == "GET" && rt.csrf {
			t.Fatalf("GET route %s must not require CSRF", key)
		}
	}
}

func TestRouteInventoryMatchesDocumentedInventory(t *testing.T) {
	b, err := os.ReadFile("../../docs/hardening/route-inventory.json")
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var doc docInventory
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse inventory: %v", err)
	}
	for _, a := range doc.Actions {
		if a == "session" {
			continue
		}
		if !knownActions[a] {
			t.Fatalf("documented action %q is not in the shipped vocabulary", a)
		}
	}
	docByKey := map[string]docRoute{}
	for _, d := range doc.Routes {
		key := d.Method + " " + d.Path
		if _, dup := docByKey[key]; dup {
			t.Fatalf("documented route duplicated: %s", key)
		}
		docByKey[key] = d
	}
	if len(docByKey) != len(apiRouteDefs) {
		t.Fatalf("inventory has %d routes, route table has %d", len(docByKey), len(apiRouteDefs))
	}
	for _, rt := range apiRouteDefs {
		key := rt.method + " " + rt.path
		d, ok := docByKey[key]
		if !ok {
			t.Fatalf("route %s is registered but missing from route-inventory.json", key)
		}
		action := d.Action
		if action == "" {
			action = rt.action
		}
		if action != rt.action {
			t.Fatalf("route %s action mismatch: doc=%q table=%q", key, action, rt.action)
		}
		if d.CSRF != rt.csrf {
			t.Fatalf("route %s csrf mismatch: doc=%v table=%v", key, d.CSRF, rt.csrf)
		}
		wantScoped := strings.HasPrefix(rt.path, "/api/sites/{id}")
		if d.SiteScoped != wantScoped {
			t.Fatalf("route %s siteScoped mismatch: doc=%v derived=%v", key, d.SiteScoped, wantScoped)
		}
		wantMin := ""
		if rt.action != "" {
			wantMin = minRoleFor(rt.action)
		}
		if d.MinRole != wantMin {
			t.Fatalf("route %s minRole mismatch: doc=%q derived=%q", key, d.MinRole, wantMin)
		}
		if len(d.TokenScopes) != len(rt.tokenScopes) {
			t.Fatalf("route %s tokenScopes mismatch: doc=%v table=%v", key, d.TokenScopes, rt.tokenScopes)
		}
		for i := range d.TokenScopes {
			if d.TokenScopes[i] != rt.tokenScopes[i] {
				t.Fatalf("route %s tokenScope[%d] mismatch: doc=%q table=%q", key, i, d.TokenScopes[i], rt.tokenScopes[i])
			}
		}
		delete(docByKey, key)
	}
	for key := range docByKey {
		t.Fatalf("route %s documented but not registered", key)
	}
}

func TestEveryAuthenticatedActionHasAMinimumRole(t *testing.T) {
	for _, rt := range apiRouteDefs {
		if rt.action == "" {
			continue
		}
		if minRoleFor(rt.action) == "" {
			t.Fatalf("action %q grants no role", rt.action)
		}
	}
}

// TestNoAuthenticatedRouteRequiresOwnerOnlyAction documents that the owner-only
// action (organization.delete) is deliberately not exposed over HTTP. Admin and
// owner therefore share the shipped API surface; the distinction is proven at
// the rbac matrix boundary (admin denied organization.delete, owner allowed).
func TestNoAuthenticatedRouteRequiresOwnerOnlyAction(t *testing.T) {
	for _, rt := range apiRouteDefs {
		if rt.action == "" || rt.action == "session" {
			continue
		}
		if minRoleFor(rt.action) == "owner" {
			t.Fatalf("route %s exposes an owner-only action %q; owner-only actions are not routed", rt.method+" "+rt.path, rt.action)
		}
	}
	if rbac.Can("admin", "organization.delete") {
		t.Fatal("admin must be denied the owner-only organization.delete action")
	}
	if !rbac.Can("owner", "organization.delete") {
		t.Fatal("owner must retain the owner-only organization.delete action")
	}
}

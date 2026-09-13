// Package operations declares Webfleet's canonical functional operation surface.
package operations

import (
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/gantry-tools/gantry-core/operation"
)

type spec struct {
	id, method, path, resource, verb, capability, test string
	kind                                               operation.Kind
	boundary                                           operation.Boundary
	scopes                                             []string
	automation                                         operation.Automation
	website                                            bool
	secrets                                            []string
}

var specs = []spec{
	{"webfleet.healthz.get", "GET", "/healthz", "healthz", "get", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.Automatable, true, nil},
	{"webfleet.wf.js.get", "GET", "/wf.js", "", "", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.BrowserProtocol, false, nil},
	{"webfleet.api.analytics.event.post", "POST", "/api/analytics/event", "", "", "", "internal/server/route_inventory_test.go", operation.Mutation, operation.Public, nil, operation.ServiceProtocol, false, nil},
	{"webfleet.setup.status.get", "GET", "/api/setup/status", "setup-status", "get", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.Automatable, true, nil},
	{"webfleet.setup.database.get", "GET", "/api/setup/database", "setup-database", "get", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.Automatable, true, nil},
	{"webfleet.setup.database.create", "POST", "/api/setup/database", "setup-database", "create", "", "internal/server/route_inventory_test.go", operation.Mutation, operation.Public, nil, operation.Automatable, true, nil},
	{"webfleet.setup.create", "POST", "/api/setup", "setup", "create", "", "internal/server/route_inventory_test.go", operation.Mutation, operation.Public, nil, operation.Automatable, true, []string{"/password"}},
	{"webfleet.login.create", "POST", "/api/login", "login", "create", "", "internal/server/route_inventory_test.go", operation.Mutation, operation.Public, nil, operation.Automatable, true, []string{"/password"}},
	{"webfleet.api.oidc.login.get", "GET", "/api/oidc/login", "", "", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.BrowserProtocol, true, nil},
	{"webfleet.api.oidc.callback.get", "GET", "/api/oidc/callback", "", "", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.BrowserProtocol, false, nil},
	{"webfleet.oidc.config.get", "GET", "/api/oidc/config", "oidc-config", "get", "organization.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.oidc.config.update", "PUT", "/api/oidc/config", "oidc-config", "update", "organization.update", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.logout.create", "POST", "/api/logout", "logout", "create", "", "internal/server/route_inventory_test.go", operation.Mutation, operation.Session, nil, operation.Automatable, true, nil},
	{"webfleet.session.get", "GET", "/api/session", "session", "get", "", "internal/server/route_inventory_test.go", operation.Read, operation.Session, nil, operation.Automatable, true, nil},
	{"webfleet.launcher.instances.list", "GET", "/api/launcher/instances", "launcher-instances", "list", "", "internal/server/route_inventory_test.go", operation.Read, operation.Public, nil, operation.Automatable, true, nil},
	{"webfleet.launcher.config.update", "PUT", "/api/launcher/config", "launcher-config", "update", "launcher.configure.all", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.identity.get", "GET", "/api/cluster/v1/identity", "cluster-identity", "get", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.members.list", "GET", "/api/cluster/v1/members", "cluster-members", "list", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.invitations.create", "POST", "/api/cluster/v1/invitations", "cluster-invitations", "create", "membership.update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.joins.list", "GET", "/api/cluster/v1/joins", "cluster-joins", "list", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.joins.create", "POST", "/api/cluster/v1/joins/{id}/{action}", "cluster-joins", "create", "membership.update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.outbound.list", "GET", "/api/cluster/v1/outbound", "cluster-outbound", "list", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.outbound.create", "POST", "/api/cluster/v1/outbound", "cluster-outbound", "create", "membership.update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.outbound.collect.collect", "POST", "/api/cluster/v1/outbound/{id}/collect", "cluster-outbound-collect", "collect", "membership.update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.members.create", "POST", "/api/cluster/v1/members/{id}/{action}", "cluster-members", "create", "membership.update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.status.get", "GET", "/api/cluster/v1/status", "cluster-status", "get", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.audit.get", "GET", "/api/cluster/v1/audit", "cluster-audit", "get", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.compare.get", "GET", "/api/cluster/v1/compare", "cluster-compare", "get", "organization.read", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.kinds.list", "GET", "/api/cluster/v1/propagation/kinds", "cluster-propagation", "kinds", "organization.read", "internal/server/propagation.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.export", "POST", "/api/cluster/v1/propagation/export", "cluster-propagation", "export", "membership.update", "internal/server/propagation.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.preview", "POST", "/api/cluster/v1/propagation/preview", "cluster-propagation", "preview", "membership.update", "internal/server/propagation.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.apply", "POST", "/api/cluster/v1/propagation/apply", "cluster-propagation", "apply", "membership.update", "internal/server/propagation.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.propagate", "POST", "/api/cluster/v1/propagation/propagate", "cluster-propagation", "propagate", "membership.update", "internal/server/propagation.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.history.list", "GET", "/api/cluster/v1/propagation/history", "cluster-propagation-history", "list", "organization.read", "internal/server/propagation.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.profiles.list", "GET", "/api/cluster/v1/propagation/profiles", "cluster-propagation-profiles", "list", "organization.read", "internal/server/propagation.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.profiles.update", "PUT", "/api/cluster/v1/propagation/profiles/{id}", "cluster-propagation-profiles", "update", "membership.update", "internal/server/propagation.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.profiles.delete", "DELETE", "/api/cluster/v1/propagation/profiles/{id}", "cluster-propagation-profiles", "delete", "membership.update", "internal/server/propagation.go", operation.Destructive, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.cluster.propagation.profiles.run-due", "POST", "/api/cluster/v1/propagation/profiles/run-due", "cluster-propagation-profiles", "run-due", "membership.update", "internal/server/propagation.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.me.password.create", "POST", "/api/me/password", "me-password", "create", "", "internal/server/route_inventory_test.go", operation.Mutation, operation.Session, nil, operation.Automatable, true, []string{"/current_password", "/new_password"}},
	{"webfleet.tokens.create", "POST", "/api/tokens", "tokens", "create", "tokens.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.tokens.delete", "DELETE", "/api/tokens/{id}", "tokens", "delete", "tokens.manage", "internal/server/route_inventory_test.go", operation.Destructive, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.notifications.webhooks.list", "GET", "/api/notifications/webhooks", "notifications-webhooks", "list", "webhooks.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.notifications.webhooks.create", "POST", "/api/notifications/webhooks", "notifications-webhooks", "create", "webhooks.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.notifications.deliveries.list", "GET", "/api/notifications/deliveries", "notifications-deliveries", "list", "webhooks.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.organization.members.list", "GET", "/api/organization/members", "organization-members", "list", "organization.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.organization.members.create", "POST", "/api/organization/members", "organization-members", "create", "membership.update", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.groups.list", "GET", "/api/groups", "groups", "list", "site.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.groups.create", "POST", "/api/groups", "groups", "create", "site.create", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.list", "GET", "/api/sites", "sites", "list", "site.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.create", "POST", "/api/sites", "sites", "create", "site.create", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.tags.get", "GET", "/api/sites/{id}/tags", "sites-tags", "get", "site.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.tags.update", "PUT", "/api/sites/{id}/tags", "sites-tags", "update", "site.update", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.get", "GET", "/api/sites/{id}", "sites", "get", "site.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.update", "PUT", "/api/sites/{id}", "sites", "update", "site.update", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.archive.archive", "POST", "/api/sites/{id}/archive", "sites-archive", "archive", "site.archive", "internal/server/route_inventory_test.go", operation.Destructive, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.delete", "DELETE", "/api/sites/{id}", "sites", "delete", "site.delete", "internal/server/route_inventory_test.go", operation.Destructive, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.get", "GET", "/api/sites/{id}/analytics", "sites-analytics", "get", "analytics.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"analytics:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.create", "POST", "/api/sites/{id}/analytics", "sites-analytics", "create", "analytics.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.summary.get", "GET", "/api/sites/{id}/analytics/summary", "sites-analytics-summary", "get", "analytics.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"analytics:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.pages.get", "GET", "/api/sites/{id}/analytics/pages", "sites-analytics-pages", "get", "analytics.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"analytics:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.countries.get", "GET", "/api/sites/{id}/analytics/countries", "sites-analytics-countries", "get", "analytics.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"analytics:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.disable.disable", "POST", "/api/sites/{id}/analytics/disable", "sites-analytics-disable", "disable", "analytics.manage", "internal/server/route_inventory_test.go", operation.Destructive, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.analytics.geo.update.create", "POST", "/api/analytics/geo/update", "analytics-geo-update", "create", "analytics.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.goals.get", "GET", "/api/sites/{id}/analytics/goals", "sites-analytics-goals", "get", "analytics.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"analytics:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.analytics.goals.create", "POST", "/api/sites/{id}/analytics/goals", "sites-analytics-goals", "create", "analytics.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.maintenance.get", "GET", "/api/maintenance", "maintenance", "get", "maintenance.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.maintenance.update", "PUT", "/api/maintenance", "maintenance", "update", "maintenance.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.maintenance.run.run", "POST", "/api/maintenance/run", "maintenance-run", "run", "maintenance.manage", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, nil, operation.Automatable, true, nil},
	{"webfleet.fleet.get", "GET", "/api/fleet", "fleet", "get", "fleet.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"fleet:read"}, operation.Automatable, true, nil},
	{"webfleet.fleet.analytics.list", "GET", "/api/fleet/analytics", "fleet-analytics", "list", "analytics.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"analytics:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.audit.get", "GET", "/api/sites/{id}/audit", "sites-audit", "get", "audit.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.audit.create", "POST", "/api/sites/{id}/audit", "sites-audit", "create", "audit.run", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"audit:run"}, operation.Automatable, true, nil},
	{"webfleet.sites.audit.history.update", "PUT", "/api/sites/{id}/audit/history", "sites-audit-history", "update", "audit.configure", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.audits.resolve.resolve", "POST", "/api/audits/resolve", "audits-resolve", "resolve", "audit.read", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"audit:run"}, operation.Automatable, true, nil},
	{"webfleet.audits.batch.batch", "POST", "/api/audits/batch", "audits-batch", "batch", "audit.run", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"audit:run"}, operation.Automatable, true, nil},
	{"webfleet.sites.check.check", "POST", "/api/sites/{id}/check", "sites-check", "check", "monitor.run", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.deployments.get", "GET", "/api/sites/{id}/deployments", "sites-deployments", "get", "deployments.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.deployments.create", "POST", "/api/sites/{id}/deployments", "sites-deployments", "create", "deployments.record", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.deployments.correlation.get", "GET", "/api/sites/{id}/deployments/correlation", "sites-deployments-correlation", "get", "deployments.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.checks.get", "GET", "/api/sites/{id}/checks", "sites-checks", "get", "monitor.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.performance.get", "GET", "/api/sites/{id}/performance", "sites-performance", "get", "monitor.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.incidents.get", "GET", "/api/sites/{id}/incidents", "sites-incidents", "get", "incidents.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.incidents.ack.ack", "POST", "/api/incidents/{id}/ack", "incidents-ack", "ack", "incidents.acknowledge", "internal/server/route_inventory_test.go", operation.Destructive, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.tls.get", "GET", "/api/sites/{id}/tls", "sites-tls", "get", "tls.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.tls.inspect.inspect", "POST", "/api/sites/{id}/tls/inspect", "sites-tls-inspect", "inspect", "tls.run", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.fleet.tls.list", "GET", "/api/fleet/tls", "fleet-tls", "list", "tls.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"fleet:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.dns.get", "GET", "/api/sites/{id}/dns", "sites-dns", "get", "dns.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.dns.observe.observe", "POST", "/api/sites/{id}/dns/observe", "sites-dns-observe", "observe", "dns.run", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.sites.http.observations.get", "GET", "/api/sites/{id}/http-observations", "sites-http-observations", "get", "monitor.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.crawl.get", "GET", "/api/sites/{id}/crawl", "sites-crawl", "get", "crawl.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.crawl.create", "POST", "/api/sites/{id}/crawl", "sites-crawl", "create", "crawl.run", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.fleet.link.regressions.list", "GET", "/api/fleet/link-regressions", "fleet-link-regressions", "list", "crawl.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"fleet:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.header.expectations.get", "GET", "/api/sites/{id}/header-expectations", "sites-header-expectations", "get", "monitor.read", "internal/server/route_inventory_test.go", operation.Read, operation.Capability, []string{"sites:read"}, operation.Automatable, true, nil},
	{"webfleet.sites.header.expectations.update", "PUT", "/api/sites/{id}/header-expectations", "sites-header-expectations", "update", "monitor.update", "internal/server/route_inventory_test.go", operation.Mutation, operation.Capability, []string{"sites:write"}, operation.Automatable, true, nil},
	{"webfleet.service.api.cluster.v1.join.post", "POST", "/api/cluster/v1/join", "", "", "", "internal/cluster/cluster_test.go", operation.Mutation, operation.Service, nil, operation.ServiceProtocol, false, nil},
	{"webfleet.service.api.cluster.v1.join.id.get", "GET", "/api/cluster/v1/join/{id}", "", "", "", "internal/cluster/cluster_test.go", operation.Read, operation.Service, nil, operation.ServiceProtocol, false, nil},
	{"webfleet.service.api.cluster.v1.rpc.summary.get", "GET", "/api/cluster/v1/rpc/summary", "", "", "", "internal/cluster/cluster_test.go", operation.Read, operation.Service, nil, operation.ServiceProtocol, false, nil},
	{"webfleet.service.api.cluster.v1.rpc.compare.get", "GET", "/api/cluster/v1/rpc/compare", "", "", "", "internal/cluster/cluster_test.go", operation.Read, operation.Service, nil, operation.ServiceProtocol, false, nil},
	{"webfleet.service.api.cluster.v1.rpc.propagation.preview", "POST", "/api/cluster/v1/rpc/propagation/preview", "", "", "", "internal/server/propagation.go", operation.Read, operation.Service, nil, operation.ServiceProtocol, false, nil},
	{"webfleet.service.api.cluster.v1.rpc.propagation.apply", "POST", "/api/cluster/v1/rpc/propagation/apply", "", "", "", "internal/server/propagation.go", operation.Mutation, operation.Service, nil, operation.ServiceProtocol, false, nil},
}

var Contracts = buildContracts()

func buildContracts() []operation.Contract {
	out := make([]operation.Contract, 0, len(specs))
	for _, s := range specs {
		var cli *operation.CLI
		if s.resource != "" {
			cli = &operation.CLI{Resource: s.resource, Verb: s.verb, Implemented: true}
		}
		audit := operation.Audit{}
		if s.kind != operation.Read {
			audit = operation.Audit{Required: true, Event: s.id + ".performed"}
		}
		schemas := operation.Schemas{Output: s.id + ".response.v1"}
		if s.kind != operation.Read {
			schemas.Input = s.id + ".request.v1"
		}
		out = append(out, operation.Contract{SchemaVersion: operation.SchemaVersion, ID: s.id, Kind: s.kind, Route: operation.Route{Method: s.method, Path: s.path}, CLI: cli, Authorization: operation.Authorization{Boundary: s.boundary, Capability: s.capability, TokenScopes: s.scopes}, Schemas: schemas, Audit: audit, Idempotency: operation.Idempotency{RetrySafe: s.kind == operation.Read}, Automation: s.automation, SecretInputs: s.secrets})
	}
	return out
}

func Manifest() contracttest.Manifest {
	routes := make([]operation.Route, 0, len(Contracts))
	commands := make([]operation.CLI, 0, len(Contracts))
	website := make([]string, 0, len(Contracts))
	evidence := map[string]contracttest.Evidence{}
	for i, c := range Contracts {
		routes = append(routes, c.Route)
		if c.CLI != nil && c.CLI.Implemented {
			commands = append(commands, *c.CLI)
		}
		if specs[i].website {
			website = append(website, c.ID)
		}
		evidence[c.ID] = contracttest.Evidence{Website: specs[i].website, Tests: []string{specs[i].test}}
	}
	return contracttest.Manifest{SchemaVersion: 1, Project: "webfleet", Operations: Contracts, ObservedRoutes: routes, ObservedCommands: commands, WebsiteOperations: website, Evidence: evidence}
}

func AdoptionManifest() contracttest.Manifest { return Manifest() }

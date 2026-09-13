package propagation

import (
	"fmt"
	core "github.com/gantry-tools/gantry-core/propagation"
)

type KindPolicy struct {
	Kind       string
	Reversible bool
	Mergeable  bool
	Permission string
}

var policies = map[string]KindPolicy{
	"request-definition": {Kind: "request-definition", Reversible: true, Permission: "sites.update"},
	"environment":        {Kind: "environment", Reversible: true, Permission: "sites.update"},
	"monitor-definition": {Kind: "monitor-definition", Reversible: true, Permission: "monitors.update"},
	"schedule":           {Kind: "schedule", Reversible: true, Permission: "monitors.update"},
	"execution-policy":   {Kind: "execution-policy", Reversible: true, Permission: "monitors.update"},
}

func Policy(kind string) (KindPolicy, bool) { p, ok := policies[kind]; return p, ok }
func ValidateEnvelope(e core.Envelope) error {
	p, ok := Policy(e.Kind)
	if !ok {
		return fmt.Errorf("webfleet propagation kind %q is not supported", e.Kind)
	}
	if e.Actor.Permission != "" && e.Actor.Permission != p.Permission {
		return fmt.Errorf("permission %q does not match %q", e.Actor.Permission, p.Permission)
	}
	return e.Validate()
}
func Kinds() []string {
	return []string{"environment", "execution-policy", "monitor-definition", "request-definition", "schedule"}
}

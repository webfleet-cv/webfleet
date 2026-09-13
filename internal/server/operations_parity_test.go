package server

import (
	"github.com/webfleet-cv/webfleet/internal/operations"
	"testing"
)

func TestOperationContractsMatchRuntimeRoutes(t *testing.T) {
	want := map[string]bool{}
	for _, r := range OperationRouteInventory() {
		want[r.Method+" "+r.Path] = true
	}
	got := map[string]bool{}
	for _, c := range operations.Contracts {
		got[c.Route.Method+" "+c.Route.Path] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("runtime route missing operation contract: %s", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("operation contract missing runtime route: %s", k)
		}
	}
}

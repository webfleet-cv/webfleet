package propagation

import (
	"encoding/json"
	core "github.com/gantry-tools/gantry-core/propagation"
	"testing"
)

func TestWebfleetKinds(t *testing.T) {
	e := core.Envelope{Kind: "request-definition", ID: "r", SchemaVersion: 1, Revision: 1, SourceNode: "n", Target: "all", Conflict: core.ConflictReject, Actor: core.Actor{Permission: "sites.update"}, Payload: json.RawMessage(`{"url":"https://example.test"}`)}
	if err := ValidateEnvelope(e); err != nil {
		t.Fatal(err)
	}
	e.Kind = "run-result"
	if err := ValidateEnvelope(e); err == nil {
		t.Fatal("results must remain node-local")
	}
}

package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	core "github.com/gantry-tools/gantry-core/cluster"
	"github.com/webfleet-cv/webfleet/internal/store"
)

func openTest(t *testing.T) (*store.Store, *Service) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, New(st.DB)
}
func TestIdentityAndInvitationLifecycle(t *testing.T) {
	_, a := openTest(t)
	_, b := openTest(t)
	ctx := context.Background()
	ai, _ := a.EnsureIdentity(ctx, "test")
	again, _ := a.EnsureIdentity(ctx, "test")
	if ai.NodeID != again.NodeID {
		t.Fatal("identity changed")
	}
	bi, err := b.UpdateIdentity(ctx, "b", "https://b.example", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := a.Invite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := a.Pair(ctx, token, bi)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Credential == "" {
		t.Fatal("missing credential")
	}
	if _, err = a.Pair(ctx, token, bi); err == nil {
		t.Fatal("invitation replay accepted")
	}
}
func TestThreeNodeAggregationReportsPartialFailure(t *testing.T) {
	_, a := openTest(t)
	_, b := openTest(t)
	_, c := openTest(t)
	ctx := context.Background()
	ai, _ := a.UpdateIdentity(ctx, "a", "https://a.example", "1")
	bi, _ := b.UpdateIdentity(ctx, "b", "https://b.example", "1")
	ci, _ := c.UpdateIdentity(ctx, "c", "https://c.example", "1")
	mk := func() (string, string) { x, _ := core.NewSecret(32); y, _ := core.NewSecret(32); return x, y }
	x, y := mk()
	_ = a.AddMember(ctx, bi, x, y)
	x, y = mk()
	_ = a.AddMember(ctx, ci, x, y)
	members, _ := a.Members(ctx)
	report, err := Aggregate(ctx, ai.NodeID, Summary{NodeID: ai.NodeID}, members, "all", func(_ context.Context, id string) (Summary, error) {
		if id == ci.NodeID {
			return Summary{}, context.DeadlineExceeded
		}
		return Summary{NodeID: id}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || len(report.Results) != 3 {
		t.Fatalf("partial=%v results=%d", report.Partial, len(report.Results))
	}
	for _, r := range report.Results {
		if r.OwnerNode != r.NodeID {
			t.Fatalf("owner=%s node=%s", r.OwnerNode, r.NodeID)
		}
	}
}
func TestSignedTransport(t *testing.T) {
	ctx := context.Background()
	_, a := openTest(t)
	_, b := openTest(t)
	ai, _ := a.EnsureIdentity(ctx, "1")
	bi, _ := b.EnsureIdentity(ctx, "1")
	ab, _ := core.NewSecret(32)
	ba, _ := core.NewSecret(32)
	bt := NewTransport(b.db, b, nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := bt.Authenticate(r, "cluster.webfleet.summary"); err != nil {
			http.Error(w, err.Error(), 401)
			return
		}
		v, err := b.LocalSummary(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}))
	defer srv.Close()
	bi.PublicEndpoint = srv.URL
	ai.PublicEndpoint = "https://a.example"
	if err := a.AddMember(ctx, bi, ab, ba); err != nil {
		t.Fatal(err)
	}
	if err := b.AddMember(ctx, ai, ba, ab); err != nil {
		t.Fatal(err)
	}
	r := RemoteReader{NewTransport(a.db, a, srv.Client())}
	got, err := r.Summary(ctx, bi.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != bi.NodeID {
		t.Fatalf("node=%s want=%s", got.NodeID, bi.NodeID)
	}
}
func TestPolicyKeepsSecretsAndRuntimeLocal(t *testing.T) {
	for _, name := range []string{"secrets", "scheduler.runtime", "browser.runtime"} {
		p, ok := PolicyFor(name)
		if !ok || !p.NodeLocalOnly || p.PropagatableLater {
			t.Fatalf("unsafe policy for %s", name)
		}
	}
}

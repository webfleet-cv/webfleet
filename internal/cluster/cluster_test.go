package cluster

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestConcurrentEnsureIdentityConvergesOnOneNode(t *testing.T) {
	_, svc := openTest(t)
	ctx := context.Background()
	const callers = 16
	results := make(chan core.Identity, callers)
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := svc.EnsureIdentity(ctx, "test")
			if err != nil {
				errors <- err
				return
			}
			results <- id
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent EnsureIdentity failed: %v", err)
	}
	seen := map[string]bool{}
	for id := range results {
		seen[id.NodeID] = true
	}
	if len(seen) != 1 {
		t.Fatalf("concurrent first-run produced %d distinct identities, want 1", len(seen))
	}
	var rows int
	if err := svc.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cluster_identity`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("cluster_identity rows=%d err=%v", rows, err)
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
func TestRotationCompletesWithPeerPendingPromotion(t *testing.T) {
	ctx := context.Background()
	_, a := openTest(t)
	_, b := openTest(t)
	ai, _ := a.EnsureIdentity(ctx, "1")
	bi, _ := b.EnsureIdentity(ctx, "1")
	ab, _ := core.NewSecret(32)
	ba, _ := core.NewSecret(32)
	bt := NewTransport(b.db, b, nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/cluster/v1/rpc/rotate-inbound":
			body, _, err := bt.Authenticate(r, "cluster.health")
			if err != nil {
				http.Error(w, err.Error(), 401)
				return
			}
			nodeID := r.Header.Get(core.HeaderNode)
			var in struct {
				SecretHash string `json:"secret_hash"`
				ExpiresAt  string `json:"expires_at"`
			}
			if err := json.Unmarshal(body, &in); err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			hash, err := base64.RawURLEncoding.DecodeString(in.SecretHash)
			if err != nil {
				http.Error(w, "bad hash", 400)
				return
			}
			expiresAt, _ := time.Parse(time.RFC3339Nano, in.ExpiresAt)
			if err := b.RotateInbound(r.Context(), nodeID, hash, expiresAt); err != nil {
				http.Error(w, err.Error(), 409)
				return
			}
			w.WriteHeader(200)
		case "/api/cluster/v1/rpc/summary":
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
		default:
			http.NotFound(w, r)
		}
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
	at := NewTransport(a.db, a, srv.Client())
	// The old A->B secret works before rotation.
	if _, err := (RemoteReader{at}).Summary(ctx, bi.NodeID); err != nil {
		t.Fatalf("summary before rotation: %v", err)
	}
	// Rotation coordinates with the peer and completes.
	newSecret, err := a.Rotate(ctx, bi.NodeID, at)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// The new secret is promoted on first use and the old secret is rejected.
	if _, err := (RemoteReader{at}).Summary(ctx, bi.NodeID); err != nil {
		t.Fatalf("summary after rotation with new credential: %v", err)
	}
	var inbound []byte
	if err = b.db.QueryRowContext(ctx, `SELECT inbound_secret_hash FROM cluster_members WHERE node_id=?`, ai.NodeID).Scan(&inbound); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(inbound, core.SecretDigest(newSecret)) {
		t.Fatal("peer did not promote the rotated credential")
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

func TestJoinApproveCollectLifecycle(t *testing.T) {
	_, host := openTest(t)
	_, joiner := openTest(t)
	ctx := context.Background()
	hostID, err := host.UpdateIdentity(ctx, "host", "https://host.example", "test")
	if err != nil {
		t.Fatal(err)
	}
	joinID, err := joiner.UpdateIdentity(ctx, "joiner", "https://joiner.example", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := host.Invite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	localInbound, _ := core.NewSecret(32)
	receipt, err := host.SubmitJoin(ctx, JoinSubmission{InvitationToken: token, Identity: joinID, CredentialForHost: localInbound})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.SubmitJoin(ctx, JoinSubmission{InvitationToken: token, Identity: joinID, CredentialForHost: localInbound}); err == nil {
		t.Fatal("invitation replay accepted")
	}
	pending, err := host.PendingJoins(ctx)
	if err != nil || len(pending) != 1 || pending[0].Fingerprint == "" {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	if err := host.DecideJoin(ctx, receipt.RequestID, true); err != nil {
		t.Fatal(err)
	}
	result, err := host.PollJoin(ctx, receipt.RequestID, receipt.RequestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != core.PairingApproved || result.Remote == nil || result.Remote.NodeID != hostID.NodeID || result.Credential == "" {
		t.Fatalf("result=%+v", result)
	}
	if err := joiner.AcceptRemote(ctx, *result.Remote, result.Credential, localInbound); err != nil {
		t.Fatal(err)
	}
	again, err := host.PollJoin(ctx, receipt.RequestID, receipt.RequestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if again.State != core.PairingUsed || again.Credential != "" {
		t.Fatal("pairing result replay exposed credential")
	}
	hm, _ := host.Members(ctx)
	jm, _ := joiner.Members(ctx)
	if len(hm) != 1 || hm[0].NodeID != joinID.NodeID || len(jm) != 1 || jm[0].NodeID != hostID.NodeID {
		t.Fatalf("host=%+v joiner=%+v", hm, jm)
	}
}

func TestCompatibleProductVersionsAndStandaloneRemoval(t *testing.T) {
	_, a := openTest(t)
	_, b := openTest(t)
	ctx := context.Background()
	ai, err := a.UpdateIdentity(ctx, "a", "https://a.example", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	bi, err := b.UpdateIdentity(ctx, "b", "https://b.example", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	x, _ := core.NewSecret(32)
	y, _ := core.NewSecret(32)
	if err := a.AddMember(ctx, bi, x, y); err != nil {
		t.Fatalf("compatible rolling version rejected: %v", err)
	}
	bad := bi
	bad.NodeID = "bad_protocol"
	bad.InstallationID = "bad_install"
	bad.ProtocolVersion = ProtocolVersion + 1
	if err := a.AddMember(ctx, bad, x, y); err == nil {
		t.Fatal("incompatible protocol accepted")
	}
	if err := a.Revoke(ctx, bi.NodeID); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(ctx, bi.NodeID); err != nil {
		t.Fatal(err)
	}
	members, err := a.Members(ctx)
	if err != nil || len(members) != 0 {
		t.Fatalf("standalone members=%v err=%v", members, err)
	}
	local, err := a.LocalSummary(ctx)
	if err != nil || local.NodeID != ai.NodeID {
		t.Fatalf("standalone summary=%+v err=%v", local, err)
	}
}

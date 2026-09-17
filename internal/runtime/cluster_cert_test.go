package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	corerepl "github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	clusterapi "github.com/webfleet-cv/webfleet/internal/cluster"
	"github.com/webfleet-cv/webfleet/internal/replicated"
	"github.com/webfleet-cv/webfleet/internal/store"
)

type wfCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newWFCA(t *testing.T) *wfCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "webfleet-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &wfCA{cert: cert, key: key}
}

func (ca *wfCA) nodeCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (ca *wfCA) nodeTLS(t *testing.T, name string) *tls.Config {
	t.Helper()
	cert := ca.nodeCert(t, name)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

func (ca *wfCA) serverTLS(t *testing.T, name string) *tls.Config {
	t.Helper()
	return &tls.Config{Certificates: []tls.Certificate{ca.nodeCert(t, name)}, MinVersion: tls.VersionTLS12}
}

type wfNode struct {
	rt    *Replicated
	srv   *httptest.Server
	store *store.Store
	id    string
}

func wfHash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func buildWFNode(t *testing.T, ctx context.Context, ca *wfCA, dataDir, nodeID string, peers map[string][2]string, bootstrap bool, httpClient *http.Client) *wfNode {
	t.Helper()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Seed the identity deterministically with the raft node id so the
	// Authenticator's local id matches the raft server id (production derives
	// both from the same cluster_identity row).
	if _, err := st.DB.Exec(`INSERT INTO cluster_identity(singleton,node_id,installation_id,display_name,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,?,?,?,?,?,?,?,?,?)`,
		nodeID, nodeID+"-inst", nodeID, []byte("k"), []byte("k"), `["cluster.health","replication"]`, 1, "0.1.0", now); err != nil {
		t.Fatal(err)
	}
	for peer, cred := range peers {
		if _, err := st.DB.Exec(`INSERT INTO cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,credential_version,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?)`,
			peer, peer+"-inst", peer, "https://"+peer+".example", []byte("k"), `["cluster.health","replication"]`, 1, "0.1.0", "active", cred[0], wfHash(cred[1]), now, now); err != nil {
			t.Fatal(err)
		}
	}
	ct := clusterapi.NewTransport(st.DB, clusterapi.New(st.DB), httpClient)
	tlsConf := ca.nodeTLS(t, nodeID)
	addr := freeWFPort(t)
	rt, err := NewReplication(ctx, ReplicationOptions{DB: st.DB.DB, DataDir: dataDir, NodeID: nodeID, Address: addr, Bootstrap: bootstrap, TLS: tlsConf, Transport: ct, Timing: corerepl.ProductionTiming()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	us := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/v1/replication/propose" {
			http.NotFound(w, r)
			return
		}
		body, _, e := ct.Authenticate(r, "replication")
		if e != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		var fr corerepl.ForwardRequest
		if json.Unmarshal(body, &fr) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		mode, ready := rt.Controller.State()
		if mode != corerepl.ModeReplicated || ready != corerepl.ReadinessReadyLeader {
			http.Error(w, "leader not ready", 503)
			return
		}
		cctx := corerepl.WithRequestID(r.Context(), fr.OpID)
		res, e := rt.Controller.Propose(cctx, fr.Kind, fr.ObjectID, json.RawMessage(fr.Payload))
		if e != nil {
			http.Error(w, e.Error(), 503)
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	us.TLS = ca.serverTLS(t, nodeID)
	us.StartTLS()
	t.Cleanup(us.Close)
	return &wfNode{rt: rt, srv: us, store: st, id: nodeID}
}

func freeWFPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func wfMesh(t *testing.T, ctx context.Context, ca *wfCA, httpClient *http.Client, ids ...string) map[string]*wfNode {
	t.Helper()
	secrets := map[string]map[string][2]string{}
	for _, id := range ids {
		secrets[id] = map[string][2]string{}
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			ij := ids[i] + "_to_" + ids[j]
			ji := ids[j] + "_to_" + ids[i]
			secrets[ids[i]][ids[j]] = [2]string{ij, ji}
			secrets[ids[j]][ids[i]] = [2]string{ji, ij}
		}
	}
	nodes := map[string]*wfNode{}
	for i, id := range ids {
		nodes[id] = buildWFNode(t, ctx, ca, filepath.Join(t.TempDir(), "data"), id, secrets[id], i == 0, httpClient)
	}
	return nodes
}

func wfRepairEndpoints(t *testing.T, nodes ...*wfNode) {
	t.Helper()
	for _, n := range nodes {
		for _, m := range nodes {
			if n.id == m.id {
				continue
			}
			if _, e := n.store.DB.Exec(`UPDATE cluster_members SET public_endpoint=? WHERE node_id=?`, m.srv.URL, m.id); e != nil {
				t.Fatal(e)
			}
		}
	}
}

func wfWaitReady(t *testing.T, n *wfNode, want corerepl.Readiness) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, rd := n.rt.Controller.State()
	t.Fatalf("node %s readiness=%s want %s", n.id, rd, want)
}

func wfCount(t *testing.T, n *wfNode, q string, args ...any) int {
	t.Helper()
	var c int
	if e := n.store.DB.QueryRow(q, args...).Scan(&c); e != nil {
		t.Fatal(e)
	}
	return c
}

func wfWaitCount(t *testing.T, n *wfNode, q string, args ...any) {
	t.Helper()
	want := args[len(args)-1]
	args = args[:len(args)-1]
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var got any
		switch want.(type) {
		case int:
			var c int
			if e := n.store.DB.QueryRow(q, args...).Scan(&c); e == nil && c == want {
				return
			}
		case string:
			var s string
			if e := n.store.DB.QueryRow(q, args...).Scan(&s); e == nil && s == want {
				return
			}
		}
		_ = got
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("node %s never converged", n.id)
}

// TestThreeNodeProductionCertification certifies the Webfleet replicated
// topology path with real Gantry Core machinery: three independent runtimes,
// a full Gantry trust mesh, explicit Raft voter membership, leader + follower
// topology mutations converging to semantic equality, and the Raft quorum wall
// at 3/3, 2/3 and 1/3 with no local SQLite fallback.
func TestThreeNodeProductionCertification(t *testing.T) {
	ca := newWFCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}}
	ctx := context.Background()

	nodes := wfMesh(t, ctx, ca, httpClient, "A", "B", "C")
	a, b, c := nodes["A"], nodes["B"], nodes["C"]
	all := []*wfNode{a, b, c}
	wfRepairEndpoints(t, all...)

	wfWaitReady(t, a, corerepl.ReadinessReadyLeader)
	for _, n := range []*wfNode{b, c} {
		if e := a.rt.Node.AddVoter(raft.ServerID(n.id), n.rt.Node.Address()); e != nil {
			t.Fatalf("join %s: %v", n.id, e)
		}
	}
	wfWaitReady(t, b, corerepl.ReadinessReadyFollower)
	wfWaitReady(t, c, corerepl.ReadinessReadyFollower)
	if cfg, e := a.rt.Node.Configuration(); e != nil {
		t.Fatal(e)
	} else if len(cfg) != 3 {
		t.Fatalf("expected 3 voters, got %d", len(cfg))
	}

	// Topology mutations through the leader: group, site, tags.
	g1 := replicated.GroupPayload{ClusterID: "wfg_prod", OrgID: 1, Name: "Production", CreatedAt: "2026-09-18T00:00:00Z"}
	if _, e := a.rt.Controller.Propose(ctx, replicated.KindGroupPut, g1.ClusterID, g1); e != nil {
		t.Fatalf("leader group put: %v", e)
	}
	s1 := replicated.SitePayload{ClusterID: "wfs_example", OrgID: 1, Name: "Example", PrimaryURL: "https://example.com", GroupClusterID: "wfg_prod", Enabled: true, CreatedAt: "2026-09-18T00:00:00Z", UpdatedAt: "2026-09-18T00:00:00Z"}
	if _, e := a.rt.Controller.Propose(ctx, replicated.KindSitePut, s1.ClusterID, s1); e != nil {
		t.Fatalf("leader site put: %v", e)
	}
	tags := replicated.TagsPayload{SiteClusterID: s1.ClusterID, Tags: []string{"prod", "public"}}
	if _, e := a.rt.Controller.Propose(ctx, replicated.KindTagsSet, s1.ClusterID, tags); e != nil {
		t.Fatalf("leader tags set: %v", e)
	}
	for _, n := range all {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_prod'`, 1)
		wfWaitCount(t, n, `SELECT COUNT(*) FROM sites WHERE cluster_id='wfs_example'`, 1)
		wfWaitCount(t, n, `SELECT COUNT(*) FROM site_tags st JOIN sites s ON s.id=st.site_id WHERE s.cluster_id='wfs_example'`, 2)
	}

	// Follower-forwarded mutations: site update through B, second group through C.
	wfWaitReady(t, b, corerepl.ReadinessReadyFollower)
	wfWaitReady(t, c, corerepl.ReadinessReadyFollower)
	s1b := replicated.SitePayload{ClusterID: s1.ClusterID, OrgID: 1, Name: "Example", PrimaryURL: "https://example.org", GroupClusterID: "wfg_prod", Enabled: true, CreatedAt: "2026-09-18T00:00:00Z", UpdatedAt: "2026-09-18T00:00:01Z"}
	idem := corerepl.WithRequestID(ctx, "webfleet-caller-1")
	wfFollowerPropose(t, b, idem, replicated.KindSitePut, s1b.ClusterID, s1b)
	g2 := replicated.GroupPayload{ClusterID: "wfg_staging", OrgID: 1, Name: "Staging", CreatedAt: "2026-09-18T00:00:00Z"}
	wfFollowerPropose(t, c, ctx, replicated.KindGroupPut, g2.ClusterID, g2)
	for _, n := range all {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM sites WHERE cluster_id='wfs_example' AND primary_url='https://example.org'`, 1)
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_staging'`, 1)
	}

	// Node-local divergence: monitoring observation state must remain node-local
	// while consensus-owned fleet topology stays equal across all three.
	if _, e := b.store.DB.Exec(`INSERT INTO check_results(site_id,monitor_id,ok,status_code,checked_at) SELECT s.id,m.id,1,200,'2026-09-18T00:00:00Z' FROM sites s JOIN monitors m ON m.site_id=s.id WHERE s.cluster_id='wfs_example'`); e != nil {
		t.Fatal(e)
	}
	if _, e := c.store.DB.Exec(`INSERT INTO check_results(site_id,monitor_id,ok,status_code,checked_at) SELECT s.id,m.id,0,503,'2026-09-18T00:00:00Z' FROM sites s JOIN monitors m ON m.site_id=s.id WHERE s.cluster_id='wfs_example'`); e != nil {
		t.Fatal(e)
	}
	if _, e := c.store.DB.Exec(`INSERT INTO check_results(site_id,monitor_id,ok,status_code,checked_at) SELECT s.id,m.id,0,504,'2026-09-18T00:00:00Z' FROM sites s JOIN monitors m ON m.site_id=s.id WHERE s.cluster_id='wfs_example'`); e != nil {
		t.Fatal(e)
	}
	diverged := wfCount(t, b, `SELECT COUNT(*) FROM check_results`) != wfCount(t, c, `SELECT COUNT(*) FROM check_results`)
	if !diverged {
		t.Fatal("node-local monitoring observations unexpectedly identical")
	}
	// A node-local monitoring write must NOT advance the replicated applied index.
	idxBefore, _ := b.rt.FSM.AppliedIndex()
	if _, e := b.store.DB.Exec(`INSERT INTO check_results(site_id,monitor_id,ok,status_code,checked_at) SELECT s.id,m.id,1,200,'2026-09-18T00:00:00Z' FROM sites s JOIN monitors m ON m.site_id=s.id WHERE s.cluster_id='wfs_example'`); e != nil {
		t.Fatal(e)
	}
	time.Sleep(500 * time.Millisecond)
	idxAfter, _ := b.rt.FSM.AppliedIndex()
	if idxAfter != idxBefore {
		t.Fatalf("node-local monitoring advanced the applied index: before=%d after=%d", idxBefore, idxAfter)
	}
	for _, n := range all {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM sites WHERE cluster_id='wfs_example'`, 1)
	}

	// Snapshot + trailing-log recovery: force a snapshot, commit trailing
	// topology mutations, restart one follower over its durable state.
	if e := b.rt.Node.Snapshot(); e != nil {
		t.Fatalf("force snapshot: %v", e)
	}
	g3 := replicated.GroupPayload{ClusterID: "wfg_trail", OrgID: 1, Name: "Trail", CreatedAt: "2026-09-18T00:00:00Z"}
	if _, e := a.rt.Controller.Propose(ctx, replicated.KindGroupPut, g3.ClusterID, g3); e != nil {
		t.Fatalf("trailing group put: %v", e)
	}
	b2 := wfRestartNode(t, ctx, ca, b, httpClient)
	all[1] = b2
	wfRepairEndpoints(t, all...)
	wfWaitReadyAny(t, b2)
	wfWaitCount(t, b2, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_trail'`, 1)
	wfWaitCount(t, b2, `SELECT COUNT(*) FROM sites WHERE cluster_id='wfs_example'`, 1)

	// Whole-cluster restart: close all three, restart each over durable state.
	for _, n := range all {
		n.rt.Close()
	}
	restarted := []*wfNode{}
	for _, n := range all {
		restarted = append(restarted, wfRestartNode(t, ctx, ca, n, httpClient))
	}
	wfRepairEndpoints(t, restarted...)
	var leader *wfNode
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range restarted {
			if n.rt.Node.State() == raft.Leader {
				leader = n
				break
			}
		}
		if leader != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("no leader after whole-cluster restart")
	}
	for _, n := range restarted {
		wfWaitReadyAny(t, n)
	}
	g4 := replicated.GroupPayload{ClusterID: "wfg_afterrestart", OrgID: 1, Name: "AfterRestart", CreatedAt: "2026-09-18T00:00:00Z"}
	wfLeaderPropose(t, leader, ctx, replicated.KindGroupPut, g4.ClusterID, g4)
	for _, n := range restarted {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_afterrestart'`, 1)
	}
	all = restarted
	a, b, c = restarted[0], restarted[1], restarted[2]

	// Peer revoke/re-enable: disable one voter on the healthy majority; the
	// majority continues, the isolated peer fails closed once revalidation drops
	// it, and re-enabling restores catch-up.
	for _, n := range all {
		if n.id != c.id {
			if _, e := n.store.DB.Exec(`UPDATE cluster_members SET state='disabled' WHERE node_id=?`, c.id); e != nil {
				t.Fatal(e)
			}
		}
	}
	var isLeader *wfNode
	for _, n := range []*wfNode{a, b} {
		if n.rt.Node.State() == raft.Leader {
			isLeader = n
			break
		}
	}
	if isLeader == nil {
		deadline = time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			if a.rt.Node.State() == raft.Leader || b.rt.Node.State() == raft.Leader {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		for _, n := range []*wfNode{a, b} {
			if n.rt.Node.State() == raft.Leader {
				isLeader = n
			}
		}
	}
	if isLeader == nil {
		t.Fatal("no healthy leader after peer disable")
	}
	q0 := replicated.GroupPayload{ClusterID: "wfg_revoke", OrgID: 1, Name: "Revoke", CreatedAt: "2026-09-18T00:00:00Z"}
	wfAnyLeaderPropose(t, []*wfNode{a, b}, ctx, replicated.KindGroupPut, q0.ClusterID, q0)
	for _, n := range []*wfNode{a, b} {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_revoke'`, 1)
	}
	// Isolated peer fails closed after the revalidation window.
	isolatedDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(isolatedDeadline) {
		_, rd := c.rt.Controller.State()
		if rd == corerepl.ReadinessNoLeader {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	before := wfCount(t, c, `SELECT COUNT(*) FROM groups`)
	if _, e := c.rt.Controller.Propose(ctx, replicated.KindGroupPut, "wfg_isolated", replicated.GroupPayload{ClusterID: "wfg_isolated", OrgID: 1, Name: "Isolated", CreatedAt: "2026-09-18T00:00:00Z"}); e == nil {
		t.Fatal("isolated peer must fail closed")
	}
	if after := wfCount(t, c, `SELECT COUNT(*) FROM groups`); after != before {
		t.Fatalf("isolated peer fell through to local SQL: before=%d after=%d", before, after)
	}
	// Re-enable + catch-up.
	for _, n := range []*wfNode{a, b} {
		if _, e := n.store.DB.Exec(`UPDATE cluster_members SET state='active' WHERE node_id=?`, c.id); e != nil {
			t.Fatal(e)
		}
	}
	wfWaitReadyAny(t, c)
	wfWaitCount(t, c, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_revoke'`, 1)

	// Quorum wall: 3/3 proven; close C -> 2/3 writable.
	c.rt.Close()
	q1 := replicated.GroupPayload{ClusterID: "wfg_q23", OrgID: 1, Name: "Quorum23", CreatedAt: "2026-09-18T00:00:00Z"}
	wfAnyLeaderPropose(t, []*wfNode{a, b}, ctx, replicated.KindGroupPut, q1.ClusterID, q1)
	for _, n := range []*wfNode{a, b} {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_q23'`, 1)
	}

	// Close B -> 1/3: authoritative topology mutation must fail closed with no
	// local SQLite fallback.
	b.rt.Close()
	before = wfCount(t, a, `SELECT COUNT(*) FROM groups`)
	_, nqErr := a.rt.Controller.Propose(ctx, replicated.KindGroupPut, "wfg_noquorum", replicated.GroupPayload{ClusterID: "wfg_noquorum", OrgID: 1, Name: "NoQuorum", CreatedAt: "2026-09-18T00:00:00Z"})
	if nqErr == nil {
		t.Fatal("expected 1/3 topology mutation to fail closed")
	}
	if after := wfCount(t, a, `SELECT COUNT(*) FROM groups`); after != before {
		t.Fatalf("rejected 1/3 mutation fell through to local SQL: before=%d after=%d", before, after)
	}
}

func wfRetriable(e error) bool {
	if e == nil {
		return false
	}
	for _, s := range []string{"learner", "no leader", "unavailable", "not leader"} {
		if len(e.Error()) >= len(s) {
			matches := true
			for i := 0; i+len(s) <= len(e.Error()); i++ {
				if e.Error()[i:i+len(s)] == s {
					matches = false
					break
				}
			}
			if !matches {
				return true
			}
		}
	}
	return false
}

func wfFollowerPropose(t *testing.T, n *wfNode, ctx context.Context, kind, obj string, payload any) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd != corerepl.ReadinessReadyFollower && rd != corerepl.ReadinessReadyLeader {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if _, e := n.rt.Controller.Propose(ctx, kind, obj, payload); e == nil {
			return
		} else if wfRetriable(e) {
			time.Sleep(150 * time.Millisecond)
			continue
		} else {
			t.Fatalf("follower propose %s: %v", obj, e)
		}
	}
	t.Fatal("follower propose timed out")
}

// wfRestartNode reopens a node's durable state (SQLite, raft.db, snapshots) as a
// fresh process, exercising restart and snapshot+trailing-log recovery. The
// identity and membership rows persist, so they are not re-seeded.
func wfRestartNode(t *testing.T, ctx context.Context, ca *wfCA, n *wfNode, httpClient *http.Client) *wfNode {
	t.Helper()
	oldAddr := string(n.rt.Node.Address())
	n.rt.Close()
	dir := filepath.Dir(n.store.Path())
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ct := clusterapi.NewTransport(st.DB, clusterapi.New(st.DB), httpClient)
	rt, err := NewReplication(ctx, ReplicationOptions{DB: st.DB.DB, DataDir: dir, NodeID: n.id, Address: oldAddr, Bootstrap: false, TLS: ca.nodeTLS(t, n.id), Transport: ct, Timing: corerepl.ProductionTiming()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	us := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/v1/replication/propose" {
			http.NotFound(w, r)
			return
		}
		body, _, e := ct.Authenticate(r, "replication")
		if e != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		var fr corerepl.ForwardRequest
		if json.Unmarshal(body, &fr) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		mode, ready := rt.Controller.State()
		if mode != corerepl.ModeReplicated || ready != corerepl.ReadinessReadyLeader {
			http.Error(w, "leader not ready", 503)
			return
		}
		cctx := corerepl.WithRequestID(r.Context(), fr.OpID)
		res, e := rt.Controller.Propose(cctx, fr.Kind, fr.ObjectID, json.RawMessage(fr.Payload))
		if e != nil {
			http.Error(w, e.Error(), 503)
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	us.TLS = ca.serverTLS(t, n.id)
	us.StartTLS()
	t.Cleanup(us.Close)
	return &wfNode{rt: rt, srv: us, store: st, id: n.id}
}

// wfLeaderPropose retries an authoritative topology write until the node is a
// ready leader and the proposal succeeds, tolerating transient no-leader and
// catch-up states during leader changes.
func wfLeaderPropose(t *testing.T, n *wfNode, ctx context.Context, kind, obj string, payload any) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd != corerepl.ReadinessReadyLeader {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if _, e := n.rt.Controller.Propose(ctx, kind, obj, payload); e == nil {
			return
		} else if wfRetriable(e) {
			time.Sleep(150 * time.Millisecond)
			continue
		} else {
			t.Fatalf("leader propose %s: %v", obj, e)
		}
	}
	t.Fatal("leader propose timed out")
}

func wfWaitReadyAny(t *testing.T, n *wfNode) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd == corerepl.ReadinessReadyLeader || rd == corerepl.ReadinessReadyFollower {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, rd := n.rt.Controller.State()
	t.Fatalf("node %s never became ready: %s", n.id, rd)
}

// wfAnyLeaderPropose proposes through whichever of the surviving nodes becomes
// ready leader, tolerating leader changes and transient catch-up states.
func wfAnyLeaderPropose(t *testing.T, nodes []*wfNode, ctx context.Context, kind, obj string, payload any) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			_, rd := n.rt.Controller.State()
			if rd != corerepl.ReadinessReadyLeader {
				continue
			}
			if _, e := n.rt.Controller.Propose(ctx, kind, obj, payload); e == nil {
				return
			} else if wfRetriable(e) {
				continue
			} else {
				t.Fatalf("any-leader propose %s: %v", obj, e)
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("any-leader propose timed out")
}

// TestFiveNodeSmokeCertification proves Webfleet topology replication beyond
// three voters through the identical generic AddVoter path: five voters form,
// a topology mutation converges on all five, 3/5 remains writable, and 2/5
// fails closed with no local SQLite fallback.
func TestFiveNodeSmokeCertification(t *testing.T) {
	ca := newWFCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}}
	ctx := context.Background()

	nodes := wfMesh(t, ctx, ca, httpClient, "A", "B", "C", "D", "E")
	all := []*wfNode{nodes["A"], nodes["B"], nodes["C"], nodes["D"], nodes["E"]}
	wfRepairEndpoints(t, all...)

	wfWaitReady(t, all[0], corerepl.ReadinessReadyLeader)
	for _, n := range all[1:] {
		if e := all[0].rt.Node.AddVoter(raft.ServerID(n.id), n.rt.Node.Address()); e != nil {
			t.Fatalf("join %s: %v", n.id, e)
		}
	}
	for _, n := range all[1:] {
		wfWaitReady(t, n, corerepl.ReadinessReadyFollower)
	}
	if cfg, e := all[0].rt.Node.Configuration(); e != nil {
		t.Fatal(e)
	} else if len(cfg) != 5 {
		t.Fatalf("expected 5 voters, got %d", len(cfg))
	}

	g := replicated.GroupPayload{ClusterID: "wfg_five", OrgID: 1, Name: "Five", CreatedAt: "2026-09-18T00:00:00Z"}
	wfAnyLeaderPropose(t, all, ctx, replicated.KindGroupPut, g.ClusterID, g)
	for _, n := range all {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_five'`, 1)
	}

	// 3/5: stop two followers; a write still commits across the remaining three.
	all[4].rt.Close()
	all[3].rt.Close()
	alive := all[:3]
	q1 := replicated.GroupPayload{ClusterID: "wfg_q35", OrgID: 1, Name: "Q35", CreatedAt: "2026-09-18T00:00:00Z"}
	wfAnyLeaderPropose(t, alive, ctx, replicated.KindGroupPut, q1.ClusterID, q1)
	for _, n := range alive {
		wfWaitCount(t, n, `SELECT COUNT(*) FROM groups WHERE cluster_id='wfg_q35'`, 1)
	}

	// 2/5: stop a third; authoritative mutation fails closed, no local fallback.
	all[2].rt.Close()
	before := wfCount(t, alive[0], `SELECT COUNT(*) FROM groups`)
	_, e := alive[0].rt.Controller.Propose(ctx, replicated.KindGroupPut, "wfg_noquorum", replicated.GroupPayload{ClusterID: "wfg_noquorum", OrgID: 1, Name: "NoQuorum", CreatedAt: "2026-09-18T00:00:00Z"})
	if e == nil {
		t.Fatal("expected 2/5 mutation to fail closed")
	}
	if after := wfCount(t, alive[0], `SELECT COUNT(*) FROM groups`); after != before {
		t.Fatalf("rejected 2/5 mutation fell through to local SQL: before=%d after=%d", before, after)
	}
}

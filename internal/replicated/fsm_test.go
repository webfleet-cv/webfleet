package replicated

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/webfleet-cv/webfleet/internal/store"
)

func testFSM(t *testing.T) (*FSM, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f, err := NewFSM(st.DB.DB)
	if err != nil {
		t.Fatal(err)
	}
	return f, st
}
func op(t *testing.T, id, kind, obj string, payload any) replication.Operation {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return replication.Operation{Version: replication.Version, Product: "webfleet", ID: id, Kind: kind, ObjectID: obj, Payload: b}
}
func apply(t *testing.T, f *FSM, idx uint64, o replication.Operation) error {
	t.Helper()
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	v := f.Apply(&raft.Log{Index: idx, Term: 1, Type: raft.LogCommand, Data: b})
	if e, ok := v.(error); ok {
		return e
	}
	return nil
}

type memSink struct {
	bytes.Buffer
	id string
}

func (m *memSink) ID() string    { return m.id }
func (m *memSink) Cancel() error { return nil }
func (m *memSink) Close() error  { return nil }

func TestFSMFleetConfigurationAndDurableIdempotency(t *testing.T) {
	f, st := testFSM(t)
	g := GroupPayload{ClusterID: "wfg_a", OrgID: 1, Name: "Production", CreatedAt: "2026-09-18T00:00:00Z"}
	if err := apply(t, f, 1, op(t, "op-g", KindGroupPut, g.ClusterID, g)); err != nil {
		t.Fatal(err)
	}
	s := SitePayload{ClusterID: "wfs_a", OrgID: 1, Name: "Example", PrimaryURL: "https://example.com", GroupClusterID: g.ClusterID, Enabled: true, CreatedAt: "2026-09-18T00:00:00Z", UpdatedAt: "2026-09-18T00:00:00Z"}
	if err := apply(t, f, 2, op(t, "op-s", KindSitePut, s.ClusterID, s)); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, f, 3, op(t, "op-t", KindTagsSet, s.ClusterID, TagsPayload{SiteClusterID: s.ClusterID, Tags: []string{"prod", "public"}})); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM sites WHERE cluster_id=?`, s.ClusterID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("site materialization count=%d err=%v", count, err)
	}
	if err := apply(t, f, 4, op(t, "op-s", KindSitePut, s.ClusterID, s)); err != nil {
		t.Fatalf("durable duplicate should replay safely: %v", err)
	}
	if idx, _ := f.AppliedIndex(); idx != 4 {
		t.Fatalf("durable duplicate did not advance applied position: %d", idx)
	}
}

func TestFSMGroupConflictDoesNotFenceReplica(t *testing.T) {
	f, _ := testFSM(t)
	g1 := GroupPayload{ClusterID: "wfg_a", OrgID: 1, Name: "Production", CreatedAt: "2026-09-18T00:00:00Z"}
	g2 := GroupPayload{ClusterID: "wfg_b", OrgID: 1, Name: "Production", CreatedAt: "2026-09-18T00:00:00Z"}
	if err := apply(t, f, 1, op(t, "op1", KindGroupPut, g1.ClusterID, g1)); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, f, 2, op(t, "op2", KindGroupPut, g2.ClusterID, g2)); err == nil {
		t.Fatal("expected deterministic group conflict")
	}
	if f.ApplyFailure() != nil {
		t.Fatalf("caller conflict fenced replica: %v", f.ApplyFailure())
	}
	g3 := GroupPayload{ClusterID: "wfg_c", OrgID: 1, Name: "Staging", CreatedAt: "2026-09-18T00:00:00Z"}
	if err := apply(t, f, 3, op(t, "op3", KindGroupPut, g3.ClusterID, g3)); err != nil {
		t.Fatalf("valid operation after conflict: %v", err)
	}
}

func TestSnapshotRestorePreservesNodeLocalSiteConfiguration(t *testing.T) {
	f, st := testFSM(t)
	g := GroupPayload{ClusterID: "wfg_a", OrgID: 1, Name: "Production", CreatedAt: "2026-09-18T00:00:00Z"}
	s := SitePayload{ClusterID: "wfs_a", OrgID: 1, Name: "Example", PrimaryURL: "https://example.com", GroupClusterID: g.ClusterID, Enabled: true, CreatedAt: "2026-09-18T00:00:00Z", UpdatedAt: "2026-09-18T00:00:00Z"}
	if err := apply(t, f, 1, op(t, "g", KindGroupPut, g.ClusterID, g)); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, f, 2, op(t, "s", KindSitePut, s.ClusterID, s)); err != nil {
		t.Fatal(err)
	}
	var sid int64
	if err := st.DB.QueryRow(`SELECT id FROM sites WHERE cluster_id=?`, s.ClusterID).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE header_expectations SET required=0 WHERE site_id=? AND name='Content-Security-Policy'`, sid); err != nil {
		t.Fatal(err)
	}
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{id: "x"}
	if err = snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`UPDATE sites SET name='drift' WHERE id=?`, sid); err != nil {
		t.Fatal(err)
	}
	if err = f.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	var sid2 int64
	var name string
	if err = st.DB.QueryRow(`SELECT id,name FROM sites WHERE cluster_id=?`, s.ClusterID).Scan(&sid2, &name); err != nil {
		t.Fatal(err)
	}
	if sid2 != sid || name != "Example" {
		t.Fatalf("restore identity/state got id=%d name=%q want id=%d name=Example", sid2, name, sid)
	}
	var required bool
	if err = st.DB.QueryRow(`SELECT required FROM header_expectations WHERE site_id=? AND name='Content-Security-Policy'`, sid).Scan(&required); err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("snapshot restore destroyed node-local header expectation state")
	}
}

func TestFSMRejectsUnsupportedKindAndVersion(t *testing.T) {
	f, _ := testFSM(t)
	if err := apply(t, f, 1, op(t, "op-unk", "webfleet.bogus", "x", map[string]any{})); err == nil {
		t.Fatal("unsupported operation kind must fail closed")
	} else if f.ApplyFailure() == nil {
		t.Fatalf("unknown committed kind should be a corruption fence: %v", err)
	}
	f2, _ := testFSM(t)
	if err := apply(t, f2, 1, op(t, "op-ver", KindGroupPut, "g", map[string]any{})); err == nil {
		t.Fatal("malformed group payload must fail closed")
	}
}

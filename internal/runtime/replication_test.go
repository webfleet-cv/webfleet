package runtime

import (
	"context"
	"path/filepath"
	"testing"

	corerepl "github.com/gantry-tools/gantry-core/replication"
	"github.com/webfleet-cv/webfleet/internal/store"
)

// TestReplicationRequiresCleanFleetConfig proves the existing-database bootstrap
// contract: clustering refuses to start on a database with pre-existing
// sites/groups (no automatic adoption or merge), so an independently populated
// node can never silently merge or overwrite authoritative topology.
func TestReplicationRequiresCleanFleetConfig(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "data")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.DB.Exec(`INSERT INTO sites(organization_id,name,primary_url,enabled,created_at,updated_at) VALUES(1,'x','https://x.example',1,'2026-09-18T00:00:00Z','2026-09-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_, err = NewReplication(ctx, ReplicationOptions{DB: st.DB.DB, DataDir: dir, NodeID: "A", Address: "127.0.0.1:0", Bootstrap: true, TLS: nil, Insecure: true, Transport: nil, Timing: corerepl.Timing{}})
	if err == nil {
		t.Fatal("expected clustering to refuse a non-empty standalone database")
	}
}

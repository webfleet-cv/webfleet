package runtime

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	clusterapi "github.com/webfleet-cv/webfleet/internal/cluster"
	"github.com/webfleet-cv/webfleet/internal/replicated"
)

type Replicated struct {
	Controller *replicated.Controller
	Node       *replication.Node
	FSM        *replicated.FSM
	Net        *replication.NetTransport
	rs         *replication.BoltStore
	stop       context.CancelFunc
	done       chan struct{}
	once       sync.Once
}
type ReplicationOptions struct {
	DB                       *sql.DB
	DataDir, NodeID, Address string
	Bootstrap                bool
	TLS                      *tls.Config
	Insecure                 bool
	Transport                *clusterapi.Transport
	Timing                   replication.Timing
}

func NewReplication(ctx context.Context, o ReplicationOptions) (*Replicated, error) {
	if o.DB == nil {
		return nil, errors.New("replication database required")
	}
	if o.DataDir == "" || o.Address == "" {
		return nil, errors.New("replication data dir and address required")
	}
	if o.TLS == nil && !o.Insecure {
		return nil, errors.New("replication TLS required")
	}
	// Clustering deliberately starts from a clean fleet-configuration surface.
	// Existing untracked numeric site/group identities cannot be made deterministic
	// after the fact without an explicit migration/import campaign.
	var legacy int
	if e := o.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM sites WHERE cluster_id IS NULL)+(SELECT COUNT(*) FROM groups WHERE cluster_id IS NULL)`).Scan(&legacy); e != nil {
		return nil, e
	}
	if legacy != 0 {
		return nil, fmt.Errorf("Webfleet clustering requires a clean fleet configuration; found %d pre-cluster site/group rows", legacy)
	}
	if o.NodeID == "" {
		if e := o.DB.QueryRow(`SELECT node_id FROM cluster_identity WHERE singleton=1`).Scan(&o.NodeID); e != nil {
			return nil, e
		}
	}
	if o.Timing.HeartbeatTimeout == 0 {
		o.Timing = replication.ProductionTiming()
	}
	dir := filepath.Join(o.DataDir, "replication")
	if e := os.MkdirAll(dir, 0750); e != nil {
		return nil, e
	}
	fsm, e := replicated.NewFSM(o.DB)
	if e != nil {
		return nil, e
	}
	auth := replicated.NewAuthenticator(o.DB, replication.Version)
	nt, e := replication.NewNetTransport(replication.NetTransportOptions{ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Authenticator: auth, Membership: auth, PeerCredentials: auth, TLSConfig: o.TLS, Protocol: replication.Version, Capabilities: replication.Capabilities{ID: raft.ServerID(o.NodeID), OperationSchemaVersions: []int{replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}}, RevalidateEvery: o.Timing.RevalidateEvery, InsecureAllowPlaintext: o.Insecure})
	if e != nil {
		return nil, e
	}
	bs, e := replication.NewBoltStore(filepath.Join(dir, "raft.db"))
	if e != nil {
		_ = nt.Close()
		return nil, e
	}
	sn, e := raft.NewFileSnapshotStore(filepath.Join(dir, "snapshots"), 3, nil)
	if e != nil {
		return nil, e
	}
	node, e := replication.NewNode(replication.NodeOptions{ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Transport: nt, LogStore: bs, StableStore: bs, SnapshotStore: sn, FSM: fsm, Bootstrap: o.Bootstrap, CapabilitySource: auth, HeartbeatTimeout: o.Timing.HeartbeatTimeout, ElectionTimeout: o.Timing.ElectionTimeout, CommitTimeout: o.Timing.CommitTimeout, LeaderLeaseTimeout: o.Timing.LeaderLeaseTimeout, ProposeTimeout: o.Timing.ProposeTimeout})
	if e != nil {
		return nil, e
	}
	c := replicated.NewController(node)
	c.SetMode(replication.ModeReplicated)
	c.SetReadiness(replication.ReadinessStarting)
	c.SetForwardClient(forward(o.Transport, node))
	ctx, cancel := context.WithCancel(ctx)
	r := &Replicated{Controller: c, Node: node, FSM: fsm, Net: nt, rs: bs, stop: cancel, done: make(chan struct{})}
	go func() {
		replication.NewReadinessDriver(node, c.SetReadiness, fsm.ApplyFailure, 150*time.Millisecond).Run(ctx)
		close(r.done)
	}()
	return r, nil
}
func forward(t *clusterapi.Transport, n *replication.Node) replication.ForwardClient {
	return func(ctx context.Context, fr replication.ForwardRequest) (*replication.ApplyResult, error) {
		if t == nil {
			return nil, errors.New("forward transport unavailable")
		}
		_, id := n.Leader()
		if id == "" {
			return nil, errors.New("no leader")
		}
		b, _ := json.Marshal(fr)
		resp, e := t.Do(ctx, string(id), http.MethodPost, "/api/cluster/v1/replication/propose", "replication", b)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			x, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("forward rejected: %s", x)
		}
		var ar replication.ApplyResult
		e = json.NewDecoder(resp.Body).Decode(&ar)
		return &ar, e
	}
}
func (r *Replicated) Close() {
	r.once.Do(func() {
		r.Controller.SetReadiness(replication.ReadinessShuttingDown)
		r.stop()
		<-r.done
		_ = r.Node.Shutdown()
		_ = r.rs.Close()
		_ = r.Net.Close()
	})
}

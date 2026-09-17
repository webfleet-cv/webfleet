package replicated

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
)

type Controller struct {
	auth  *replication.Authority
	node  *replication.Node
	seq   atomic.Uint64
	epoch int64
}

func NewController(n *replication.Node) *Controller {
	return &Controller{auth: replication.NewAuthority(), node: n, epoch: time.Now().UnixNano()}
}
func (c *Controller) SetMode(m replication.Mode)                       { c.auth.SetMode(m) }
func (c *Controller) SetReadiness(r replication.Readiness)             { c.auth.SetReadiness(r) }
func (c *Controller) State() (replication.Mode, replication.Readiness) { return c.auth.State() }
func (c *Controller) SetForwardClient(f replication.ForwardClient)     { c.auth.SetForwardClient(f) }
func (c *Controller) Node() *replication.Node                          { return c.node }
func (c *Controller) Propose(ctx context.Context, kind, obj string, payload any) (*replication.ApplyResult, error) {
	b, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	id := replication.RequestID(ctx)
	if id == "" {
		id = fmt.Sprintf("webfleet-%s-%d-%d", c.node.ID(), c.epoch, c.seq.Add(1))
	}
	fr := replication.ForwardRequest{Kind: kind, ObjectID: obj, OpID: id, Payload: b}
	local := func(context.Context) (*replication.ApplyResult, error) {
		return c.node.Propose(ctx, replication.Operation{Version: replication.Version, Product: "webfleet", Kind: kind, ID: id, ObjectKind: "fleet-config", ObjectID: obj, Payload: b})
	}
	forward := func(ctx context.Context) (*replication.ApplyResult, error) {
		f := c.auth.ForwardClient()
		if f == nil {
			return nil, fmt.Errorf("replication forward unavailable")
		}
		r, e := f(ctx, fr)
		if e == nil && r != nil {
			e = c.node.WaitApplied(ctx, r.Index)
		}
		return r, e
	}
	return c.auth.Route(ctx, local, forward)
}

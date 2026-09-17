package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	clusterapi "github.com/webfleet-cv/webfleet/internal/cluster"
	"github.com/webfleet-cv/webfleet/internal/replicated"
)

func clusterObjectID(prefix string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}
func (s *Server) SetReplication(c *replicated.Controller, n *replication.Node, f *replicated.FSM) {
	s.replication = c
	s.replicationNode = n
	s.replicationFSM = f
}
func (s *Server) ClusterService() *clusterapi.Service     { return s.cluster }
func (s *Server) ClusterTransport() *clusterapi.Transport { return s.clusterTransport }
func (s *Server) SetClusterHTTPClient(c *http.Client)     { s.clusterTransport.SetHTTPClient(c) }
func (s *Server) handleReplicationPropose(w http.ResponseWriter, r *http.Request) {
	if s.replication == nil {
		writeError(w, 503, "replication disabled")
		return
	}
	body, rid, e := s.clusterTransport.Authenticate(r, "replication")
	if e != nil {
		writeError(w, 401, e.Error())
		return
	}
	var fr replication.ForwardRequest
	if e = json.Unmarshal(body, &fr); e != nil {
		writeError(w, 400, "invalid replication proposal")
		return
	}
	_ = rid // transport request identity authenticates this hop; caller identity is fr.OpID.
	mode, ready := s.replication.State()
	if mode != replication.ModeReplicated || ready != replication.ReadinessReadyLeader {
		writeError(w, 503, "leader not ready")
		return
	}
	ctx := replication.WithRequestID(r.Context(), fr.OpID)
	ar, e := s.replication.Propose(ctx, fr.Kind, fr.ObjectID, json.RawMessage(fr.Payload))
	if e != nil {
		writeError(w, 503, e.Error())
		return
	}
	writeJSON(w, 200, ar)
}
func (s *Server) handleReplicationStatus(w http.ResponseWriter, r *http.Request, _ principal) {
	if s.replication == nil {
		writeError(w, 503, "replication disabled")
		return
	}
	mode, ready := s.replication.State()
	leaderAddr, leaderID := s.replicationNode.Leader()
	idx, term := s.replicationFSM.AppliedIndex()
	cfg, e := s.replicationNode.Configuration()
	if e != nil {
		writeError(w, 503, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"mode": mode, "readiness": ready, "leader_id": leaderID, "leader_address": leaderAddr, "applied_index": idx, "applied_term": term, "members": cfg})
}
func (s *Server) handleReplicationJoin(w http.ResponseWriter, r *http.Request, _ principal) {
	if s.replicationNode == nil {
		writeError(w, 503, "replication disabled")
		return
	}
	var in struct {
		NodeID  string `json:"node_id"`
		Address string `json:"address"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.NodeID) == "" || strings.TrimSpace(in.Address) == "" {
		writeError(w, 400, "node_id and address required")
		return
	}
	if e := s.cluster.EligibleVoter(r.Context(), in.NodeID); e != nil {
		writeError(w, 409, e.Error())
		return
	}
	if e := s.replicationNode.AddVoter(raft.ServerID(in.NodeID), raft.ServerAddress(in.Address)); e != nil {
		writeError(w, 409, e.Error())
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleReplicationSnapshot(w http.ResponseWriter, r *http.Request, _ principal) {
	if s.replicationNode == nil {
		writeError(w, 503, "replication disabled")
		return
	}
	if e := s.replicationNode.Snapshot(); e != nil {
		writeError(w, 503, e.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func replicationRequestContext(r *http.Request) context.Context {
	id := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if id == "" {
		return r.Context()
	}
	if len(id) > 200 {
		return r.Context()
	}
	return replication.WithRequestID(r.Context(), id)
}

func replicationHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "operation id reused") || strings.Contains(msg, "group conflict") {
		return http.StatusConflict
	}
	if replicationUnavailable(err) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

func replicationUnavailable(err error) bool {
	return err != nil && (errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "replication") || strings.Contains(err.Error(), "leader") || strings.Contains(err.Error(), "readiness"))
}

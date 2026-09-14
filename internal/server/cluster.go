package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
	clusterapi "github.com/webfleet-cv/webfleet/internal/cluster"
)

func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	var in clusterapi.JoinSubmission
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, core.MaxRequestBytes)).Decode(&in); err != nil {
		writeError(w, 400, "invalid cluster join request")
		return
	}
	v, err := s.cluster.SubmitJoin(r.Context(), in)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, v)
}
func (s *Server) handleClusterPollJoin(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	v, err := s.cluster.PollJoin(r.Context(), r.PathValue("id"), secret)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterPendingJoins(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.PendingJoins(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterJoinAction(w http.ResponseWriter, r *http.Request, p principal) {
	action := r.PathValue("action")
	if action != "approve" && action != "reject" {
		writeError(w, 404, "unknown cluster join action")
		return
	}
	if err := s.cluster.DecideJoin(r.Context(), r.PathValue("id"), action == "approve"); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	auditAction := core.AuditJoinReject
	if action == "approve" {
		auditAction = core.AuditJoinApprove
	}
	if err := s.cluster.Audit(r.Context(), p.UserID, p.OrgID, auditAction, r.PathValue("id"), r.Header.Get("X-Request-ID")); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleClusterBeginOutbound(w http.ResponseWriter, r *http.Request, p principal) {
	var in struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, core.MaxRequestBytes)).Decode(&in); err != nil {
		writeError(w, 400, "invalid outbound join")
		return
	}
	v, err := s.cluster.BeginOutbound(r.Context(), in.URL, in.Token, nil)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := s.cluster.Audit(r.Context(), p.UserID, p.OrgID, "cluster.join.begin", v.ID, r.Header.Get("X-Request-ID")); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 202, v)
}

func (s *Server) handleClusterOutbound(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.ListOutbound(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterCollectOutbound(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.CollectOutbound(r.Context(), r.PathValue("id"), nil)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handleClusterIdentity(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.EnsureIdentity(r.Context(), "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"identity": v, "fingerprint": v.Fingerprint()})
}
func (s *Server) handleClusterMembers(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.Members(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterInvite(w http.ResponseWriter, r *http.Request, p principal) {
	inv, token, err := s.cluster.Invite(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := s.cluster.Audit(r.Context(), p.UserID, p.OrgID, core.AuditInviteCreate, inv.ID, r.Header.Get("X-Request-ID")); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	inv.Token = token
	writeJSON(w, 201, inv)
}
func (s *Server) handleClusterMemberAction(w http.ResponseWriter, r *http.Request, p principal) {
	id := r.PathValue("id")
	var err error
	var value any = map[string]bool{"ok": true}
	switch r.PathValue("action") {
	case "enable":
		err = s.cluster.SetEnabled(r.Context(), id, true)
	case "disable":
		err = s.cluster.SetEnabled(r.Context(), id, false)
	case "revoke":
		err = s.cluster.Revoke(r.Context(), id)
	case "remove":
		err = s.cluster.Remove(r.Context(), id)
	case "rotate":
		var secret string
		secret, err = s.cluster.Rotate(r.Context(), id, s.clusterTransport)
		value = map[string]string{"credential": secret}
	default:
		writeError(w, 404, "unknown cluster action")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	auditAction := map[string]string{"enable": core.AuditMemberEnable, "disable": core.AuditMemberDisable, "rotate": core.AuditMemberRotate, "revoke": core.AuditMemberRevoke, "remove": core.AuditMemberRemove}[r.PathValue("action")]
	if err := s.cluster.Audit(r.Context(), p.UserID, p.OrgID, auditAction, id, r.Header.Get("X-Request-ID")); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, value)
}

func (s *Server) handleClusterAudit(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.RecentAudit(r.Context(), 25)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request, _ principal) {
	local, err := s.cluster.LocalSummary(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	members, err := s.cluster.Members(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	remote := clusterapi.RemoteReader{Transport: s.clusterTransport}
	v, err := clusterapi.Aggregate(r.Context(), local.NodeID, local, members, r.URL.Query().Get("target"), remote.Summary)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterCompare(w http.ResponseWriter, r *http.Request, _ principal) {
	local, err := s.cluster.LocalComparison(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	members, err := s.cluster.Members(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	remote := clusterapi.RemoteReader{Transport: s.clusterTransport}
	v, err := clusterapi.Aggregate(r.Context(), local.NodeID, local, members, r.URL.Query().Get("target"), remote.Comparison)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterRPCSummary(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.clusterTransport.Authenticate(r, "cluster.webfleet.summary"); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	v, err := s.cluster.LocalSummary(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterRPCCompare(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.clusterTransport.Authenticate(r, "cluster.webfleet.compare"); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	v, err := s.cluster.LocalComparison(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

// handleClusterRPCRotateInbound installs a pending inbound credential for the
// calling member during a peer-initiated rotation. The request is
// authenticated with the current credential, so an unauthenticated caller
// cannot overwrite a member's rotation state.
func (s *Server) handleClusterRPCRotateInbound(w http.ResponseWriter, r *http.Request) {
	body, _, err := s.clusterTransport.Authenticate(r, "cluster.health")
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}
	nodeID := r.Header.Get(core.HeaderNode)
	var in struct {
		SecretHash string `json:"secret_hash"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&in); err != nil {
		writeError(w, 400, "invalid rotation payload")
		return
	}
	hash, err := base64.RawURLEncoding.DecodeString(in.SecretHash)
	if err != nil || len(hash) != sha256.Size {
		writeError(w, 400, "invalid credential digest")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
	if err != nil {
		writeError(w, 400, "invalid rotation expiry")
		return
	}
	if err := s.cluster.RotateInbound(r.Context(), nodeID, hash, expiresAt); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	w.WriteHeader(200)
}

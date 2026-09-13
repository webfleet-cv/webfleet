package server

import (
	"encoding/json"
	"net/http"

	core "github.com/gantry-tools/gantry-core/cluster"
	clusterapi "github.com/webfleet-cv/webfleet/internal/cluster"
)

type clusterPairInput struct {
	Token    string        `json:"token"`
	Identity core.Identity `json:"identity"`
}

func (s *Server) handleClusterIdentity(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.EnsureIdentity(r.Context(), "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterMembers(w http.ResponseWriter, r *http.Request, _ principal) {
	v, err := s.cluster.Members(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterInvite(w http.ResponseWriter, r *http.Request, _ principal) {
	inv, token, err := s.cluster.Invite(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"invitation": inv, "token": token})
}
func (s *Server) handleClusterPair(w http.ResponseWriter, r *http.Request, _ principal) {
	var in clusterPairInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, core.MaxRequestBytes)).Decode(&in); err != nil {
		writeError(w, 400, "invalid cluster pairing request")
		return
	}
	v, err := s.cluster.Pair(r.Context(), in.Token, in.Identity)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, v)
}
func (s *Server) handleClusterMemberAction(w http.ResponseWriter, r *http.Request, _ principal) {
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
		secret, err = s.cluster.Rotate(r.Context(), id)
		value = map[string]string{"credential": secret}
	default:
		writeError(w, 404, "unknown cluster action")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, value)
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

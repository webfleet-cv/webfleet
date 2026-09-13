package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
)

type propagationWire struct {
	Kinds     []string        `json:"kinds,omitempty"`
	Target    string          `json:"target,omitempty"`
	Envelopes []core.Envelope `json:"envelopes,omitempty"`
	PlanID    string          `json:"plan_id,omitempty"`
	Selector  core.Selector   `json:"selector,omitempty"`
	DryRun    bool            `json:"dry_run,omitempty"`
}

func webActor(p principal) core.Actor {
	return core.Actor{Kind: "user", ID: strconv.FormatInt(p.UserID, 10)}
}
func (s *Server) handlePropagationKinds(w http.ResponseWriter, r *http.Request, _ principal) {
	writeJSON(w, 200, s.propagation.Adapter.Kinds())
}
func (s *Server) handlePropagationExport(w http.ResponseWriter, r *http.Request, p principal) {
	var q propagationWire
	if !decodeJSON(w, r, &q) {
		return
	}
	v, e := s.propagation.Export(r.Context(), q.Kinds, webActor(p), q.Target)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationPreview(w http.ResponseWriter, r *http.Request, p principal) {
	var q propagationWire
	if !decodeJSON(w, r, &q) {
		return
	}
	v, e := s.propagation.Preview(r.Context(), q.Envelopes, webActor(p))
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationApply(w http.ResponseWriter, r *http.Request, p principal) {
	var q propagationWire
	if !decodeJSON(w, r, &q) {
		return
	}
	if q.PlanID == "" {
		q.PlanID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	v, e := s.propagation.Apply(r.Context(), q.PlanID, q.Envelopes, webActor(p), q.Target)
	if e != nil {
		writeJSON(w, 409, map[string]any{"error": e.Error(), "result": v})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationHistory(w http.ResponseWriter, r *http.Request, _ principal) {
	v, e := s.propagation.History(r.Context(), 50)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationProfiles(w http.ResponseWriter, r *http.Request, _ principal) {
	v, e := s.propagation.Profiles(r.Context())
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationProfilePut(w http.ResponseWriter, r *http.Request, _ principal) {
	var p core.Profile
	if !decodeJSON(w, r, &p) {
		return
	}
	p.ID = r.PathValue("id")
	if e := s.propagation.SaveProfile(r.Context(), p); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handlePropagationRPCPreview(w http.ResponseWriter, r *http.Request) {
	body, _, e := s.clusterTransport.Authenticate(r, "cluster.propagation")
	if e != nil {
		writeError(w, 401, e.Error())
		return
	}
	var q propagationWire
	if e = json.Unmarshal(body, &q); e != nil {
		writeError(w, 400, "invalid propagation payload")
		return
	}
	v, e := s.propagation.Preview(r.Context(), q.Envelopes, core.Actor{Kind: "node"})
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationRPCApply(w http.ResponseWriter, r *http.Request) {
	body, _, e := s.clusterTransport.Authenticate(r, "cluster.propagation")
	if e != nil {
		writeError(w, 401, e.Error())
		return
	}
	var q propagationWire
	if e = json.Unmarshal(body, &q); e != nil {
		writeError(w, 400, "invalid propagation payload")
		return
	}
	v, e := s.propagation.Apply(r.Context(), q.PlanID, q.Envelopes, core.Actor{Kind: "node"}, "remote")
	if e != nil {
		writeJSON(w, 409, map[string]any{"error": e.Error(), "result": v})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) remotePropagationPreview(ctx context.Context, node string, env []core.Envelope, actor core.Actor) (core.Preview, error) {
	b, _ := json.Marshal(propagationWire{Envelopes: env})
	resp, e := s.clusterTransport.Do(ctx, node, http.MethodPost, "/api/cluster/v1/rpc/propagation/preview", "cluster.propagation", b)
	if e != nil {
		return core.Preview{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return core.Preview{}, fmt.Errorf("remote status %d", resp.StatusCode)
	}
	var v core.Preview
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v)
	return v, e
}
func (s *Server) remotePropagationApply(ctx context.Context, node, plan string, env []core.Envelope, actor core.Actor) (core.ApplyBundleResult, error) {
	b, _ := json.Marshal(propagationWire{PlanID: plan, Envelopes: env})
	resp, e := s.clusterTransport.Do(ctx, node, http.MethodPost, "/api/cluster/v1/rpc/propagation/apply", "cluster.propagation", b)
	if e != nil {
		return core.ApplyBundleResult{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return core.ApplyBundleResult{}, fmt.Errorf("remote status %d", resp.StatusCode)
	}
	var v core.ApplyBundleResult
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v)
	return v, e
}
func (s *Server) handlePropagationPropagate(w http.ResponseWriter, r *http.Request, p principal) {
	var q propagationWire
	if !decodeJSON(w, r, &q) {
		return
	}
	actor := webActor(p)
	env, e := s.propagation.Export(r.Context(), q.Kinds, actor, "members")
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	members, e := s.cluster.Members(r.Context())
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	ms := make([]core.Member, 0, len(members))
	for _, m := range members {
		ms = append(ms, core.Member{ID: m.NodeID, Capabilities: m.Capabilities, Enabled: m.State == "active"})
	}
	nodes, e := core.Select(q.Selector, ms)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	pre := core.PreviewNodes(r.Context(), nodes, env, actor, 4, s.remotePropagationPreview)
	blocked := false
	for _, x := range pre {
		if x.Error != "" || !x.Preview.Applicable {
			blocked = true
		}
	}
	if q.DryRun || blocked {
		writeJSON(w, 200, map[string]any{"preview": pre, "applicable": !blocked})
		return
	}
	if q.PlanID == "" {
		q.PlanID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	results := core.ApplyNodes(r.Context(), nodes, q.PlanID, env, actor, 4, s.remotePropagationApply)
	writeJSON(w, 200, map[string]any{"plan_id": q.PlanID, "preview": pre, "results": results})
}

func (s *Server) propagationProfileExecutor(ctx context.Context) (core.ProfileExecutor, error) {
	members, err := s.cluster.Members(ctx)
	if err != nil {
		return core.ProfileExecutor{}, err
	}
	ms := make([]core.Member, 0, len(members))
	for _, m := range members {
		ms = append(ms, core.Member{ID: m.NodeID, Capabilities: m.Capabilities, Enabled: m.State == "active"})
	}
	return core.ProfileExecutor{Members: ms, Export: s.propagation.Export, Preview: s.remotePropagationPreview, Apply: s.remotePropagationApply}, nil
}

func (s *Server) runPropagationProfile(ctx context.Context, p core.Profile) (core.ProfileRunResult, error) {
	exec, err := s.propagationProfileExecutor(ctx)
	if err != nil {
		return core.ProfileRunResult{ProfileID: p.ID}, err
	}
	return core.ExecuteProfile(ctx, p, core.Actor{Kind: "system", ID: "scheduler"}, exec)
}

func (s *Server) runDuePropagationProfiles(ctx context.Context) ([]core.ProfileRunResult, error) {
	return s.propagation.RunDueProfiles(ctx, s.runPropagationProfile)
}

func (s *Server) propagationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			results, err := s.runDuePropagationProfiles(ctx)
			if err != nil {
				s.log.Warn("propagation reconciliation failed", "error", err)
				continue
			}
			for _, result := range results {
				if result.Error != "" || result.Failed > 0 {
					s.log.Warn("propagation profile run incomplete", "profile", result.ProfileID, "action", result.Action, "drift", result.Drift, "failed", result.Failed, "error", result.Error)
				}
			}
		}
	}
}

func (s *Server) handlePropagationProfileDelete(w http.ResponseWriter, r *http.Request, _ principal) {
	if err := s.propagation.DeleteProfile(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePropagationRunDue(w http.ResponseWriter, r *http.Request, _ principal) {
	results, err := s.runDuePropagationProfiles(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, results)
}

package propagation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/webfleet-cv/webfleet/internal/store"
)

type Adapter struct {
	db  *store.Store
	now func() time.Time
}

func New(st *store.Store) *Adapter { return &Adapter{db: st, now: time.Now} }
func (a *Adapter) Kinds() []core.KindDescriptor {
	return []core.KindDescriptor{{Kind: "monitor-definition", Label: "Monitor definitions", SchemaVersion: 1, Reversible: true}, {Kind: "request-definition", Label: "Site/request definitions", SchemaVersion: 1, Reversible: true}}
}
func want(kinds []string, k string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, v := range kinds {
		if v == k {
			return true
		}
	}
	return false
}
func rev(v string) int64 {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", v)
	}
	if err != nil || t.UnixNano() < 1 {
		return 1
	}
	return t.UnixNano()
}
func max1(v int64) int64 {
	if v < 1 {
		return 1
	}
	return v
}
func mk(kind, id string, revision int64, target string, actor core.Actor, payload any, deps []string) (core.Envelope, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return core.Envelope{}, err
	}
	e := core.Envelope{Kind: kind, ID: id, SchemaVersion: 1, Revision: max1(revision), SourceNode: "webfleet-local", CreatedAt: time.Now().UTC(), Target: target, Conflict: core.ConflictSourceWins, Actor: actor, Payload: b, Dependencies: deps}
	if err = e.Validate(); err != nil {
		return core.Envelope{}, err
	}
	return e, nil
}

type requestPayload struct {
	OrganizationID int64  `json:"organization_id"`
	Name           string `json:"name"`
	PrimaryURL     string `json:"primary_url"`
	Enabled        bool   `json:"enabled"`
	GroupName      string `json:"group_name,omitempty"`
}
type monitorPayload struct {
	SiteID      int64  `json:"site_id"`
	Kind        string `json:"kind"`
	TimeoutMS   int64  `json:"timeout_ms"`
	ExpectedMin int64  `json:"expected_min"`
	ExpectedMax int64  `json:"expected_max"`
}

func (a *Adapter) Export(ctx context.Context, kinds []string, actor core.Actor, target string) ([]core.Envelope, error) {
	out := []core.Envelope{}
	if want(kinds, "request-definition") {
		rows, err := a.db.DB.QueryContext(ctx, `SELECT s.id,s.organization_id,s.name,s.primary_url,s.enabled,COALESCE(g.name,''),s.updated_at FROM sites s LEFT JOIN groups g ON g.id=s.group_id WHERE s.archived_at IS NULL ORDER BY s.id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var p requestPayload
			var enabled int
			var updated string
			if err := rows.Scan(&id, &p.OrganizationID, &p.Name, &p.PrimaryURL, &enabled, &p.GroupName, &updated); err != nil {
				rows.Close()
				return nil, err
			}
			p.Enabled = enabled != 0
			e, err := mk("request-definition", strconv.FormatInt(id, 10), rev(updated), target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "sites.update"}, p, nil)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	if want(kinds, "monitor-definition") {
		rows, err := a.db.DB.QueryContext(ctx, `SELECT id,site_id,kind,timeout_ms,expected_min,expected_max,created_at FROM monitors ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var p monitorPayload
			var created string
			if err := rows.Scan(&id, &p.SiteID, &p.Kind, &p.TimeoutMS, &p.ExpectedMin, &p.ExpectedMax, &created); err != nil {
				rows.Close()
				return nil, err
			}
			e, err := mk("monitor-definition", strconv.FormatInt(id, 10), rev(created), target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "monitors.update"}, p, []string{"site:" + strconv.FormatInt(p.SiteID, 10)})
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].ID < out[j].ID
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}
func (a *Adapter) Snapshot(ctx context.Context, kinds []string) (map[string]core.ObjectState, error) {
	envs, err := a.Export(ctx, kinds, core.Actor{}, "local")
	if err != nil {
		return nil, err
	}
	out := map[string]core.ObjectState{}
	for _, e := range envs {
		out[e.Kind+"/"+e.ID] = core.ObjectState{Existing: core.Existing{Kind: e.Kind, ID: e.ID, Digest: e.Digest, Revision: e.Revision}, Payload: e.Payload, Reversible: true}
	}
	return out, nil
}
func (a *Adapter) TargetState(ctx context.Context, src []core.Envelope, actor core.Actor) (core.TargetState, error) {
	snap, err := a.Snapshot(ctx, nil)
	if err != nil {
		return core.TargetState{}, err
	}
	existing := map[string]core.Existing{}
	deps := map[string]bool{}
	for k, v := range snap {
		existing[k] = v.Existing
		if v.Existing.Kind == "request-definition" {
			deps["site:"+v.Existing.ID] = true
		}
	}
	perms := map[string]bool{}
	for _, e := range src {
		if e.Actor.Permission != "" {
			perms[e.Actor.Permission] = true
		}
	}
	return core.TargetState{Existing: existing, SupportedSchemas: map[string]int{"request-definition": 1, "monitor-definition": 1}, Dependencies: deps, Secrets: core.MapSecrets{}, Permissions: perms}, nil
}
func (a *Adapter) Apply(ctx context.Context, e core.Envelope) (core.AppliedRevision, error) {
	if err := ValidateEnvelope(e); err != nil {
		return core.AppliedRevision{}, err
	}
	id, err := strconv.ParseInt(e.ID, 10, 64)
	if err != nil {
		return core.AppliedRevision{}, fmt.Errorf("invalid numeric id %q", e.ID)
	}
	switch e.Kind {
	case "request-definition":
		var p requestPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		var group any = nil
		if p.GroupName != "" {
			var gid int64
			err := a.db.DB.QueryRowContext(ctx, `SELECT id FROM groups WHERE organization_id=? AND name=?`, p.OrganizationID, p.GroupName).Scan(&gid)
			if errors.Is(err, sql.ErrNoRows) {
				r, er := a.db.DB.ExecContext(ctx, `INSERT INTO groups(organization_id,name,created_at) VALUES(?,?,?)`, p.OrganizationID, p.GroupName, a.now().UTC().Format(time.RFC3339Nano))
				if er != nil {
					return core.AppliedRevision{}, er
				}
				gid, er = r.LastInsertId()
				if er != nil {
					return core.AppliedRevision{}, er
				}
			} else if err != nil {
				return core.AppliedRevision{}, err
			}
			group = gid
		}
		now := a.now().UTC().Format(time.RFC3339Nano)
		var before string
		_ = a.db.DB.QueryRowContext(ctx, `SELECT updated_at FROM sites WHERE id=?`, id).Scan(&before)
		_, err = a.db.DB.ExecContext(ctx, `INSERT INTO sites(id,organization_id,name,primary_url,enabled,group_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET organization_id=excluded.organization_id,name=excluded.name,primary_url=excluded.primary_url,enabled=excluded.enabled,group_id=excluded.group_id,updated_at=excluded.updated_at`, id, p.OrganizationID, p.Name, p.PrimaryURL, p.Enabled, group, now, now)
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, Before: rev(before), After: e.Revision, Reversible: true}, nil
	case "monitor-definition":
		var p monitorPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		var exists int
		_ = a.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM monitors WHERE id=?`, id).Scan(&exists)
		_, err = a.db.DB.ExecContext(ctx, `INSERT INTO monitors(id,site_id,kind,timeout_ms,expected_min,expected_max,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET site_id=excluded.site_id,kind=excluded.kind,timeout_ms=excluded.timeout_ms,expected_min=excluded.expected_min,expected_max=excluded.expected_max`, id, p.SiteID, p.Kind, p.TimeoutMS, p.ExpectedMin, p.ExpectedMax, a.now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, Before: int64(exists), After: e.Revision, Reversible: true}, nil
	}
	return core.AppliedRevision{}, fmt.Errorf("unsupported kind %q", e.Kind)
}
func (a *Adapter) Restore(ctx context.Context, s core.ObjectState) error {
	id, err := strconv.ParseInt(s.Existing.ID, 10, 64)
	if err != nil {
		return err
	}
	if s.Existing.Revision == 0 && len(s.Payload) == 0 {
		switch s.Existing.Kind {
		case "monitor-definition":
			_, err = a.db.DB.ExecContext(ctx, `DELETE FROM monitors WHERE id=?`, id)
			return err
		case "request-definition":
			_, err = a.db.DB.ExecContext(ctx, `DELETE FROM sites WHERE id=?`, id)
			return err
		}
	}
	e := core.Envelope{Kind: s.Existing.Kind, ID: s.Existing.ID, SchemaVersion: 1, Revision: max1(s.Existing.Revision), SourceNode: "rollback", Target: "local", Conflict: core.ConflictSourceWins, Payload: s.Payload}
	if e.Kind == "request-definition" {
		e.Actor.Permission = "sites.update"
	} else {
		e.Actor.Permission = "monitors.update"
	}
	_, err = a.Apply(ctx, e)
	return err
}

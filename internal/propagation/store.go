package propagation

import (
	"context"
	"encoding/json"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/webfleet-cv/webfleet/internal/store"
)

type StateStore struct {
	st  *store.Store
	now func() time.Time
}

func NewStateStore(st *store.Store) *StateStore { return &StateStore{st: st, now: time.Now} }
func (s *StateStore) SaveProfile(ctx context.Context, p core.Profile) error {
	sel, e := json.Marshal(p.Selector)
	if e != nil {
		return e
	}
	ks, e := json.Marshal(p.Kinds)
	if e != nil {
		return e
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, e = s.st.DB.ExecContext(ctx, `INSERT INTO propagation_profiles(id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,selector_json=excluded.selector_json,kinds_json=excluded.kinds_json,mode=excluded.mode,schedule=excluded.schedule,maintenance_window=excluded.maintenance_window,enabled=excluded.enabled,updated_at=excluded.updated_at`, p.ID, p.Name, string(sel), string(ks), string(p.Mode), p.Schedule, p.MaintenanceWindow, enabled, now, now)
	return e
}
func (s *StateStore) DeleteProfile(ctx context.Context, id string) error {
	_, e := s.st.DB.ExecContext(ctx, "DELETE FROM propagation_profiles WHERE id=?", id)
	return e
}
func (s *StateStore) ListProfiles(ctx context.Context) ([]core.Profile, error) {
	rows, e := s.st.DB.QueryContext(ctx, "SELECT id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled FROM propagation_profiles ORDER BY name,id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []core.Profile
	for rows.Next() {
		var p core.Profile
		var sel, ks string
		var en int
		if e := rows.Scan(&p.ID, &p.Name, &sel, &ks, &p.Mode, &p.Schedule, &p.MaintenanceWindow, &en); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(sel), &p.Selector); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(ks), &p.Kinds); e != nil {
			return nil, e
		}
		p.Enabled = en != 0
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *StateStore) RecordHistory(ctx context.Context, h core.HistoryRecord) error {
	_, e := s.st.DB.ExecContext(ctx, `INSERT INTO propagation_history(id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,applied=excluded.applied,failed=excluded.failed,rolled_back=excluded.rolled_back,detail=excluded.detail`, h.ID, h.PlanID, h.Actor, h.Target, h.Status, h.Applied, h.Failed, h.RolledBack, h.Detail, h.CreatedAt.UTC().Format(time.RFC3339Nano))
	return e
}
func (s *StateStore) ListHistory(ctx context.Context, limit int) ([]core.HistoryRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, e := s.st.DB.QueryContext(ctx, "SELECT id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at FROM propagation_history ORDER BY created_at DESC LIMIT ?", limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []core.HistoryRecord
	for rows.Next() {
		var h core.HistoryRecord
		var at string
		if e := rows.Scan(&h.ID, &h.PlanID, &h.Actor, &h.Target, &h.Status, &h.Applied, &h.Failed, &h.RolledBack, &h.Detail, &at); e != nil {
			return nil, e
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, h)
	}
	return out, rows.Err()
}

var _ core.StateStore = (*StateStore)(nil)

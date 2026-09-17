package replicated

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

const (
	KindGroupPut    = "webfleet.group.put"
	KindSitePut     = "webfleet.site.put"
	KindSiteArchive = "webfleet.site.archive"
	KindSiteDelete  = "webfleet.site.delete"
	KindTagsSet     = "webfleet.site.tags.set"
	metaTable       = "webfleet_replicated_meta"
)

var ErrGroupConflict = errors.New("group conflict")

type GroupPayload struct {
	ClusterID string `json:"cluster_id"`
	OrgID     int64  `json:"organization_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}
type SitePayload struct {
	ClusterID      string `json:"cluster_id"`
	OrgID          int64  `json:"organization_id"`
	Name           string `json:"name"`
	PrimaryURL     string `json:"primary_url"`
	GroupClusterID string `json:"group_cluster_id,omitempty"`
	Enabled        bool   `json:"enabled"`
	Archived       bool   `json:"archived"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}
type TagsPayload struct {
	SiteClusterID string   `json:"site_cluster_id"`
	Tags          []string `json:"tags"`
}
type snapshot struct {
	Groups  []GroupPayload      `json:"groups"`
	Sites   []SitePayload       `json:"sites"`
	Tags    map[string][]string `json:"tags"`
	Applied map[string]string   `json:"applied"`
	Index   uint64              `json:"index"`
	Term    uint64              `json:"term"`
}
type FSM struct {
	mu          sync.Mutex
	db          *sql.DB
	applied     map[string]string
	index, term uint64
	failure     error
}

func NewFSM(db *sql.DB) (*FSM, error) {
	f := &FSM{db: db, applied: map[string]string{}}
	if _, e := db.Exec(`CREATE TABLE IF NOT EXISTS ` + metaTable + `(k TEXT PRIMARY KEY,v TEXT NOT NULL)`); e != nil {
		return nil, e
	}
	rows, e := db.Query(`SELECT k,v FROM ` + metaTable)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if e = rows.Scan(&k, &v); e != nil {
			return nil, e
		}
		switch k {
		case "index":
			f.index, _ = strconv.ParseUint(v, 10, 64)
		case "term":
			f.term, _ = strconv.ParseUint(v, 10, 64)
		default:
			if len(k) > 3 && k[:3] == "op:" {
				f.applied[k[3:]] = v
			}
		}
	}
	return f, rows.Err()
}
func (f *FSM) OpKnown(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.applied[id]
	return v, ok
}
func (f *FSM) AppliedIndex() (uint64, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.index, f.term
}
func (f *FSM) ApplyFailure() error { f.mu.Lock(); defer f.mu.Unlock(); return f.failure }
func (f *FSM) Apply(l *raft.Log) interface{} {
	op, e := replication.DecodeOperation(l.Data)
	if e != nil {
		f.fail(e)
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	d, e := op.Digest()
	if e != nil {
		return e
	}
	if old, ok := f.applied[op.ID]; ok {
		if old != d {
			return errors.New("operation id reused with different payload")
		}
		f.index, f.term = l.Index, l.Term
		return &replication.ApplyResult{Index: l.Index, Term: l.Term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version}
	}
	tx, e := f.db.BeginTx(context.Background(), nil)
	if e == nil {
		e = f.materialize(tx, op)
	}
	if e == nil {
		_, e = tx.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, "op:"+op.ID, d)
	}
	if e == nil {
		_, e = tx.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES('index',?),('term',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprint(l.Index), fmt.Sprint(l.Term))
	}
	if e == nil {
		e = tx.Commit()
	} else if tx != nil {
		_ = tx.Rollback()
	}
	if e != nil {
		if errors.Is(e, ErrGroupConflict) {
			return e
		}
		f.failure = e
		return e
	}
	f.applied[op.ID] = d
	f.index, f.term = l.Index, l.Term
	return &replication.ApplyResult{Index: l.Index, Term: l.Term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version}
}
func (f *FSM) fail(e error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure == nil {
		f.failure = e
	}
}
func (f *FSM) materialize(tx *sql.Tx, op replication.Operation) error {
	switch op.Kind {
	case KindGroupPut:
		var p GroupPayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return e
		}
		var existing string
		e := tx.QueryRow(`SELECT COALESCE(cluster_id,'') FROM groups WHERE organization_id=? AND name=?`, p.OrgID, p.Name).Scan(&existing)
		if e == nil && existing != p.ClusterID {
			return ErrGroupConflict
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		_, e = tx.Exec(`INSERT INTO groups(organization_id,name,created_at,cluster_id) VALUES(?,?,?,?) ON CONFLICT(cluster_id) DO UPDATE SET name=excluded.name`, p.OrgID, p.Name, p.CreatedAt, p.ClusterID)
		return e
	case KindSitePut:
		var p SitePayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return e
		}
		var gid any = nil
		if p.GroupClusterID != "" {
			var x int64
			if e := tx.QueryRow(`SELECT id FROM groups WHERE cluster_id=?`, p.GroupClusterID).Scan(&x); e != nil {
				return e
			}
			gid = x
		}
		var id int64
		e := tx.QueryRow(`SELECT id FROM sites WHERE cluster_id=?`, p.ClusterID).Scan(&id)
		if errors.Is(e, sql.ErrNoRows) {
			var arch any = nil
			if p.Archived {
				arch = p.UpdatedAt
			}
			r, e := tx.Exec(`INSERT INTO sites(organization_id,name,primary_url,enabled,group_id,archived_at,created_at,updated_at,cluster_id) VALUES(?,?,?,?,?,?,?,?,?)`, p.OrgID, p.Name, p.PrimaryURL, p.Enabled, gid, arch, p.CreatedAt, p.UpdatedAt, p.ClusterID)
			if e != nil {
				return e
			}
			id, _ = r.LastInsertId()
			if _, e = tx.Exec(`INSERT INTO monitors(site_id,kind,timeout_ms,expected_min,expected_max,created_at) VALUES(?,'http',10000,200,399,?)`, id, p.CreatedAt); e != nil {
				return e
			}
			if _, e = tx.Exec(`INSERT INTO site_health(site_id,state,last_change_at) VALUES(?,'unknown',?)`, id, p.CreatedAt); e != nil {
				return e
			}
			for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"} {
				if _, e = tx.Exec(`INSERT INTO header_expectations(site_id,name,required) VALUES(?,?,1)`, id, h); e != nil {
					return e
				}
			}
			return nil
		}
		if e != nil {
			return e
		}
		var arch any = nil
		if p.Archived {
			arch = p.UpdatedAt
		}
		_, e = tx.Exec(`UPDATE sites SET name=?,primary_url=?,enabled=?,group_id=?,archived_at=?,updated_at=? WHERE id=?`, p.Name, p.PrimaryURL, p.Enabled, gid, arch, p.UpdatedAt, id)
		return e
	case KindSiteArchive:
		var p SitePayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return e
		}
		var at any = nil
		if p.Archived {
			at = p.UpdatedAt
		}
		_, e := tx.Exec(`UPDATE sites SET archived_at=?,updated_at=? WHERE cluster_id=?`, at, p.UpdatedAt, p.ClusterID)
		return e
	case KindSiteDelete:
		_, e := tx.Exec(`DELETE FROM sites WHERE cluster_id=?`, op.ObjectID)
		return e
	case KindTagsSet:
		var p TagsPayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return e
		}
		var id int64
		if e := tx.QueryRow(`SELECT id FROM sites WHERE cluster_id=?`, p.SiteClusterID).Scan(&id); e != nil {
			return e
		}
		if _, e := tx.Exec(`DELETE FROM site_tags WHERE site_id=?`, id); e != nil {
			return e
		}
		for _, tag := range p.Tags {
			if _, e := tx.Exec(`INSERT INTO site_tags(site_id,tag) VALUES(?,?)`, id, tag); e != nil {
				return e
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported Webfleet replication operation %q", op.Kind)
	}
}
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := snapshot{Applied: map[string]string{}, Tags: map[string][]string{}, Index: f.index, Term: f.term}
	for k, v := range f.applied {
		s.Applied[k] = v
	}
	rows, e := f.db.Query(`SELECT cluster_id,organization_id,name,created_at FROM groups WHERE cluster_id IS NOT NULL ORDER BY cluster_id`)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var p GroupPayload
		if e = rows.Scan(&p.ClusterID, &p.OrgID, &p.Name, &p.CreatedAt); e != nil {
			rows.Close()
			return nil, e
		}
		s.Groups = append(s.Groups, p)
	}
	rows.Close()
	rows, e = f.db.Query(`SELECT s.cluster_id,s.organization_id,s.name,s.primary_url,COALESCE(g.cluster_id,''),s.enabled,s.archived_at IS NOT NULL,s.created_at,s.updated_at FROM sites s LEFT JOIN groups g ON g.id=s.group_id WHERE s.cluster_id IS NOT NULL ORDER BY s.cluster_id`)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var p SitePayload
		if e = rows.Scan(&p.ClusterID, &p.OrgID, &p.Name, &p.PrimaryURL, &p.GroupClusterID, &p.Enabled, &p.Archived, &p.CreatedAt, &p.UpdatedAt); e != nil {
			rows.Close()
			return nil, e
		}
		s.Sites = append(s.Sites, p)
	}
	rows.Close()
	for _, p := range s.Sites {
		tr, e := f.db.Query(`SELECT tag FROM site_tags st JOIN sites s ON s.id=st.site_id WHERE s.cluster_id=? ORDER BY tag`, p.ClusterID)
		if e != nil {
			return nil, e
		}
		for tr.Next() {
			var t string
			_ = tr.Scan(&t)
			s.Tags[p.ClusterID] = append(s.Tags[p.ClusterID], t)
		}
		tr.Close()
	}
	b, e := json.Marshal(s)
	return &snapBytes{b: b}, e
}

type snapBytes struct{ b []byte }

func (s *snapBytes) Persist(sink raft.SnapshotSink) error {
	if _, e := sink.Write(s.b); e != nil {
		_ = sink.Cancel()
		return e
	}
	return sink.Close()
}
func (s *snapBytes) Release() {}
func (f *FSM) Restore(r io.ReadCloser) error {
	defer r.Close()
	b, e := io.ReadAll(r)
	if e != nil {
		return e
	}
	var s snapshot
	if e = json.NewDecoder(bytes.NewReader(b)).Decode(&s); e != nil {
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tx, e := f.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()

	// Reconcile clustered rows in place. Updating existing cluster_id rows keeps
	// their local numeric IDs stable, which deliberately preserves node-local
	// observations/history attached by foreign keys. Snapshot restore must not
	// turn consensus recovery into deletion of Webfleet's local monitoring data.
	groupSet := map[string]bool{}
	for _, p := range s.Groups {
		groupSet[p.ClusterID] = true
		if e = f.materialize(tx, replication.Operation{Kind: KindGroupPut, Payload: mustJSON(p)}); e != nil {
			return e
		}
	}
	siteSet := map[string]bool{}
	for _, p := range s.Sites {
		siteSet[p.ClusterID] = true
		if e = f.materialize(tx, replication.Operation{Kind: KindSitePut, Payload: mustJSON(p)}); e != nil {
			return e
		}
	}
	rows, e := tx.Query(`SELECT cluster_id FROM sites WHERE cluster_id IS NOT NULL`)
	if e != nil {
		return e
	}
	var staleSites []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		if !siteSet[id] {
			staleSites = append(staleSites, id)
		}
	}
	rows.Close()
	for _, id := range staleSites {
		if _, e = tx.Exec(`DELETE FROM sites WHERE cluster_id=?`, id); e != nil {
			return e
		}
	}
	rows, e = tx.Query(`SELECT cluster_id FROM groups WHERE cluster_id IS NOT NULL`)
	if e != nil {
		return e
	}
	var staleGroups []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		if !groupSet[id] {
			staleGroups = append(staleGroups, id)
		}
	}
	rows.Close()
	for _, id := range staleGroups {
		if _, e = tx.Exec(`DELETE FROM groups WHERE cluster_id=?`, id); e != nil {
			return e
		}
	}
	for _, p := range s.Sites {
		if e = f.materialize(tx, replication.Operation{Kind: KindTagsSet, Payload: mustJSON(TagsPayload{SiteClusterID: p.ClusterID, Tags: s.Tags[p.ClusterID]})}); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(`DELETE FROM ` + metaTable); e != nil {
		return e
	}
	for id, d := range s.Applied {
		if _, e = tx.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES(?,?)`, "op:"+id, d); e != nil {
			return e
		}
	}
	_, e = tx.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES('index',?),('term',?)`, fmt.Sprint(s.Index), fmt.Sprint(s.Term))
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	f.applied = s.Applied
	f.index, f.term = s.Index, s.Term
	f.failure = nil
	return nil
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

package sites

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

type Service struct{ store *store.Store }
type Group struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	SiteCount int64  `json:"site_count"`
}
type Site struct {
	ID                  int64  `json:"id"`
	Name                string `json:"name"`
	PrimaryURL          string `json:"primary_url"`
	Enabled             bool   `json:"enabled"`
	GroupID             int64  `json:"group_id"`
	GroupName           string `json:"group_name"`
	Archived            bool   `json:"archived"`
	Health              string `json:"health"`
	ConsecutiveFailures int64  `json:"consecutive_failures"`
	LastCheckedAt       string `json:"last_checked_at"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}
type List struct {
	Sites    []Site `json:"sites"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Total    int    `json:"total"`
	Pages    int    `json:"pages"`
}

func New(s *store.Store) *Service { return &Service{store: s} }
func CanonicalURL(raw string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return "", errors.New("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("URL must use http or https")
	}
	if u.Hostname() == "" || u.User != nil {
		return "", errors.New("URL must contain a hostname and no credentials")
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}
func (s *Service) CreateGroup(orgID int64, name string) (Group, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return Group{}, errors.New("group name must be 1..80 characters")
	}
	r, e := sqlite.Query(s.store.DB, `INSERT INTO groups(organization_id,name,created_at) VALUES(?,?,?) RETURNING id`, orgID, name, store.Now())
	if e != nil {
		return Group{}, e
	}
	return Group{ID: r[0]["id"].Int64, Name: name}, nil
}
func (s *Service) Groups(orgID int64) ([]Group, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT g.id,g.name,COUNT(s.id) site_count FROM groups g LEFT JOIN sites s ON s.group_id=g.id AND s.archived_at IS NULL WHERE g.organization_id=? GROUP BY g.id ORDER BY lower(g.name)`, orgID)
	if e != nil {
		return nil, e
	}
	out := make([]Group, 0, len(r))
	for _, x := range r {
		out = append(out, Group{ID: x["id"].Int64, Name: x["name"].Text, SiteCount: x["site_count"].Int64})
	}
	return out, nil
}
func (s *Service) Create(orgID int64, name, rawURL string, groupID int64) (Site, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 {
		return Site{}, errors.New("site name must be 1..120 characters")
	}
	u, e := CanonicalURL(rawURL)
	if e != nil {
		return Site{}, e
	}
	if groupID > 0 {
		r, e := sqlite.Query(s.store.DB, `SELECT id FROM groups WHERE id=? AND organization_id=?`, groupID, orgID)
		if e != nil || len(r) == 0 {
			return Site{}, errors.New("group not found")
		}
	}
	now := store.Now()
	r, e := sqlite.Query(s.store.DB, `INSERT INTO sites(organization_id,name,primary_url,enabled,group_id,created_at,updated_at) VALUES(?,?,?,1,NULLIF(?,0),?,?) RETURNING id`, orgID, name, u, groupID, now, now)
	if e != nil {
		return Site{}, e
	}
	id := r[0]["id"].Int64
	if e = sqlite.Exec(s.store.DB, `INSERT INTO monitors(site_id,kind,timeout_ms,expected_min,expected_max,created_at) VALUES(?,'http',10000,200,399,?)`, id, now); e != nil {
		return Site{}, e
	}
	if e = sqlite.Exec(s.store.DB, `INSERT INTO site_health(site_id,state,last_change_at) VALUES(?,'unknown',?)`, id, now); e != nil {
		return Site{}, e
	}
	for _, header := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"} {
		if e = sqlite.Exec(s.store.DB, `INSERT INTO header_expectations(site_id,name,required) VALUES(?,?,1)`, id, header); e != nil {
			return Site{}, e
		}
	}
	return s.GetForOrg(orgID, id)
}
func (s *Service) GetForOrg(orgID, id int64) (Site, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT s.id,s.name,s.primary_url,s.enabled,COALESCE(s.group_id,0) group_id,COALESCE(g.name,'') group_name,s.archived_at,s.created_at,s.updated_at,COALESCE(h.state,'unknown') health,COALESCE(h.consecutive_failures,0) consecutive_failures,COALESCE((SELECT checked_at FROM check_results cr WHERE cr.site_id=s.id ORDER BY cr.id DESC LIMIT 1),'') last_checked_at FROM sites s LEFT JOIN groups g ON g.id=s.group_id LEFT JOIN site_health h ON h.site_id=s.id WHERE s.id=? AND s.organization_id=?`, id, orgID)
	if e != nil || len(r) == 0 {
		return Site{}, errors.New("site not found")
	}
	return rowSite(r[0]), nil
}
func (s *Service) Update(orgID, id int64, name, rawURL string, groupID int64, enabled bool) (Site, error) {
	if _, e := s.GetForOrg(orgID, id); e != nil {
		return Site{}, e
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 {
		return Site{}, errors.New("site name must be 1..120 characters")
	}
	u, e := CanonicalURL(rawURL)
	if e != nil {
		return Site{}, e
	}
	if groupID > 0 {
		r, e := sqlite.Query(s.store.DB, `SELECT id FROM groups WHERE id=? AND organization_id=?`, groupID, orgID)
		if e != nil || len(r) == 0 {
			return Site{}, errors.New("group not found")
		}
	}
	if e = sqlite.Exec(s.store.DB, `UPDATE sites SET name=?,primary_url=?,group_id=NULLIF(?,0),enabled=?,updated_at=? WHERE id=? AND organization_id=?`, name, u, groupID, enabled, store.Now(), id, orgID); e != nil {
		return Site{}, e
	}
	return s.GetForOrg(orgID, id)
}
func (s *Service) Archive(orgID, id int64, archived bool) error {
	if _, e := s.GetForOrg(orgID, id); e != nil {
		return e
	}
	var at any = nil
	if archived {
		at = store.Now()
	}
	return sqlite.Exec(s.store.DB, `UPDATE sites SET archived_at=?,updated_at=? WHERE id=? AND organization_id=?`, at, store.Now(), id, orgID)
}
func (s *Service) Delete(orgID, id int64) error {
	site, e := s.GetForOrg(orgID, id)
	if e != nil {
		return e
	}
	if !site.Archived {
		return errors.New("archive site before deleting it")
	}
	return sqlite.Exec(s.store.DB, `DELETE FROM sites WHERE id=? AND organization_id=?`, id, orgID)
}
func (s *Service) List(orgID int64, q string, groupID int64, page, pageSize int, includeArchived bool) (List, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where := ` WHERE s.organization_id=?`
	args := []any{orgID}
	if !includeArchived {
		where += ` AND s.archived_at IS NULL`
	}
	if strings.TrimSpace(q) != "" {
		where += ` AND (lower(s.name) LIKE ? OR lower(s.primary_url) LIKE ?)`
		term := "%" + strings.ToLower(strings.TrimSpace(q)) + "%"
		args = append(args, term, term)
	}
	if groupID > 0 {
		where += ` AND s.group_id=?`
		args = append(args, groupID)
	}
	cr, e := sqlite.Query(s.store.DB, `SELECT COUNT(*) n FROM sites s`+where, args...)
	if e != nil {
		return List{}, e
	}
	total := int(cr[0]["n"].Int64)
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, e := sqlite.Query(s.store.DB, `SELECT s.id,s.name,s.primary_url,s.enabled,COALESCE(s.group_id,0) group_id,COALESCE(g.name,'') group_name,s.archived_at,s.created_at,s.updated_at,COALESCE(h.state,'unknown') health,COALESCE(h.consecutive_failures,0) consecutive_failures,COALESCE((SELECT checked_at FROM check_results cr WHERE cr.site_id=s.id ORDER BY cr.id DESC LIMIT 1),'') last_checked_at FROM sites s LEFT JOIN groups g ON g.id=s.group_id LEFT JOIN site_health h ON h.site_id=s.id`+where+` ORDER BY lower(s.name) LIMIT ? OFFSET ?`, args...)
	if e != nil {
		return List{}, e
	}
	out := List{Sites: make([]Site, 0, len(rows)), Page: page, PageSize: pageSize, Total: total, Pages: pages}
	for _, r := range rows {
		out.Sites = append(out.Sites, rowSite(r))
	}
	return out, nil
}
func rowSite(r sqlite.Row) Site {
	return Site{ID: r["id"].Int64, Name: r["name"].Text, PrimaryURL: r["primary_url"].Text, Enabled: r["enabled"].Int64 != 0, GroupID: r["group_id"].Int64, GroupName: r["group_name"].Text, Archived: !r["archived_at"].Null, Health: r["health"].Text, ConsecutiveFailures: r["consecutive_failures"].Int64, LastCheckedAt: r["last_checked_at"].Text, CreatedAt: r["created_at"].Text, UpdatedAt: r["updated_at"].Text}
}
func ParseID(raw string) (int64, error) {
	id, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || id < 1 {
		return 0, fmt.Errorf("invalid id")
	}
	return id, nil
}

func (s *Service) Tags(orgID, siteID int64) ([]string, error) {
	if _, e := s.GetForOrg(orgID, siteID); e != nil {
		return nil, e
	}
	r, e := sqlite.Query(s.store.DB, `SELECT tag FROM site_tags WHERE site_id=? ORDER BY lower(tag)`, siteID)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, x := range r {
		out = append(out, x["tag"].Text)
	}
	return out, nil
}
func (s *Service) SetTags(orgID, siteID int64, tags []string) error {
	if _, e := s.GetForOrg(orgID, siteID); e != nil {
		return e
	}
	if e := sqlite.Exec(s.store.DB, `DELETE FROM site_tags WHERE site_id=?`, siteID); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || seen[tag] {
			continue
		}
		if len(tag) > 40 {
			return errors.New("tag too long")
		}
		seen[tag] = true
		if e := sqlite.Exec(s.store.DB, `INSERT INTO site_tags(site_id,tag) VALUES(?,?)`, siteID, tag); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) ListByTag(orgID int64, q string, groupID int64, tag string, page, pageSize int) (List, error) {
	if strings.TrimSpace(tag) == "" {
		return s.List(orgID, q, groupID, page, pageSize, false)
	}
	tag = strings.ToLower(strings.TrimSpace(tag))
	where := ` WHERE s.organization_id=? AND s.archived_at IS NULL AND EXISTS(SELECT 1 FROM site_tags st WHERE st.site_id=s.id AND st.tag=?)`
	args := []any{orgID, tag}
	if strings.TrimSpace(q) != "" {
		where += ` AND (lower(s.name) LIKE ? OR lower(s.primary_url) LIKE ?)`
		term := "%" + strings.ToLower(strings.TrimSpace(q)) + "%"
		args = append(args, term, term)
	}
	if groupID > 0 {
		where += ` AND s.group_id=?`
		args = append(args, groupID)
	}
	cr, e := sqlite.Query(s.store.DB, `SELECT COUNT(*) n FROM sites s`+where, args...)
	if e != nil {
		return List{}, e
	}
	total := int(cr[0]["n"].Int64)
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > pages {
		page = pages
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, e := sqlite.Query(s.store.DB, `SELECT s.id,s.name,s.primary_url,s.enabled,COALESCE(s.group_id,0) group_id,COALESCE(g.name,'') group_name,s.archived_at,s.created_at,s.updated_at,COALESCE(h.state,'unknown') health,COALESCE(h.consecutive_failures,0) consecutive_failures,COALESCE((SELECT checked_at FROM check_results cr WHERE cr.site_id=s.id ORDER BY cr.id DESC LIMIT 1),'') last_checked_at FROM sites s LEFT JOIN groups g ON g.id=s.group_id LEFT JOIN site_health h ON h.site_id=s.id`+where+` ORDER BY lower(s.name) LIMIT ? OFFSET ?`, args...)
	if e != nil {
		return List{}, e
	}
	out := List{Sites: make([]Site, 0, len(rows)), Page: page, PageSize: pageSize, Total: total, Pages: pages}
	for _, r := range rows {
		out.Sites = append(out.Sites, rowSite(r))
	}
	return out, nil
}

// ClusterIDForSite returns the stable consensus identity for a clustered site.
func (s *Service) ClusterIDForSite(orgID, id int64) (string, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT cluster_id FROM sites WHERE id=? AND organization_id=?`, id, orgID)
	if e != nil || len(r) == 0 || r[0]["cluster_id"].Null {
		return "", errors.New("site is not cluster-managed")
	}
	return r[0]["cluster_id"].Text, nil
}
func (s *Service) ClusterIDForGroup(orgID, id int64) (string, error) {
	if id == 0 {
		return "", nil
	}
	r, e := sqlite.Query(s.store.DB, `SELECT cluster_id FROM groups WHERE id=? AND organization_id=?`, id, orgID)
	if e != nil || len(r) == 0 || r[0]["cluster_id"].Null {
		return "", errors.New("group is not cluster-managed")
	}
	return r[0]["cluster_id"].Text, nil
}
func (s *Service) GetByClusterID(orgID int64, cid string) (Site, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT id FROM sites WHERE cluster_id=? AND organization_id=?`, cid, orgID)
	if e != nil || len(r) == 0 {
		return Site{}, errors.New("site not found")
	}
	return s.GetForOrg(orgID, r[0]["id"].Int64)
}
func (s *Service) GroupByClusterID(orgID int64, cid string) (Group, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT id,name FROM groups WHERE cluster_id=? AND organization_id=?`, cid, orgID)
	if e != nil || len(r) == 0 {
		return Group{}, errors.New("group not found")
	}
	return Group{ID: r[0]["id"].Int64, Name: r[0]["name"].Text}, nil
}

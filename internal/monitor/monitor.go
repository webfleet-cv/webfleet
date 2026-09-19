package monitor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/webfleet-cv/webfleet/internal/incidents"
	"github.com/webfleet-cv/webfleet/internal/netguard"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

type Service struct {
	store *store.Store
	guard netguard.Guard
}
type Result struct {
	ID            int64  `json:"id"`
	SiteID        int64  `json:"site_id"`
	MonitorID     int64  `json:"monitor_id"`
	OK            bool   `json:"ok"`
	StatusCode    int    `json:"status_code"`
	LatencyMS     int64  `json:"latency_ms"`
	ResponseBytes int64  `json:"response_bytes"`
	FinalURL      string `json:"final_url"`
	ErrorClass    string `json:"error_class"`
	Error         string `json:"error"`
	CheckedAt     string `json:"checked_at"`
}

type HTTPObservation struct {
	ID             int64             `json:"id"`
	SiteID         int64             `json:"site_id"`
	CheckID        int64             `json:"check_id"`
	RedirectChain  []string          `json:"redirect_chain"`
	Headers        map[string]string `json:"headers"`
	MissingHeaders []string          `json:"missing_headers"`
	Changed        bool              `json:"changed"`
	ObservedAt     string            `json:"observed_at"`
}

func New(st *store.Store) *Service { return &Service{store: st, guard: netguard.New()} }
func NewForTests(st *store.Store, r netguard.Resolver, allowPrivate bool) *Service {
	return &Service{store: st, guard: netguard.Guard{Resolver: r, AllowPrivate: allowPrivate}}
}

func (s *Service) CheckSite(ctx context.Context, siteID int64) (Result, error) {
	rows, e := sqlite.Query(s.store.DB, `SELECT m.id monitor_id,s.primary_url,m.timeout_ms,m.expected_min,m.expected_max FROM monitors m JOIN sites s ON s.id=m.site_id WHERE s.id=? AND s.enabled=1 AND s.archived_at IS NULL LIMIT 1`, siteID)
	if e != nil {
		return Result{}, e
	}
	if len(rows) == 0 {
		return Result{}, errors.New("enabled site monitor not found")
	}
	r := rows[0]
	return s.check(ctx, siteID, r["monitor_id"].Int64, r["primary_url"].Text, time.Duration(r["timeout_ms"].Int64)*time.Millisecond, int(r["expected_min"].Int64), int(r["expected_max"].Int64))
}
func (s *Service) check(ctx context.Context, siteID, monitorID int64, raw string, timeout time.Duration, minStatus, maxStatus int) (Result, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: s.guard.DialContext}
	redirects := []string{raw}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if err := s.guard.ValidateURL(req.Context(), req.URL); err != nil {
			return err
		}
		redirects = append(redirects, req.URL.String())
		return nil
	}}
	u, e := url.Parse(raw)
	if e != nil {
		return Result{}, e
	}
	if e = s.guard.ValidateURL(ctx, u); e != nil {
		return s.persist(siteID, monitorID, Result{SiteID: siteID, MonitorID: monitorID, OK: false, FinalURL: raw, ErrorClass: "blocked", Error: e.Error(), CheckedAt: store.Now()})
	}
	start := time.Now()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return Result{}, e
	}
	req.Header.Set("User-Agent", "WebFleet/0.1 monitor")
	resp, e := client.Do(req)
	lat := time.Since(start).Milliseconds()
	res := Result{SiteID: siteID, MonitorID: monitorID, LatencyMS: lat, FinalURL: raw, CheckedAt: store.Now()}
	if e != nil {
		res.ErrorClass = classifyError(e)
		res.Error = e.Error()
		return s.persist(siteID, monitorID, res)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20))
	res.ResponseBytes = n
	res.StatusCode = resp.StatusCode
	res.FinalURL = resp.Request.URL.String()
	res.OK = resp.StatusCode >= minStatus && resp.StatusCode <= maxStatus
	if !res.OK {
		res.ErrorClass = "http_status"
		res.Error = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
	}
	res, e = s.persist(siteID, monitorID, res)
	if e != nil {
		return Result{}, e
	}
	if _, e = s.persistHTTPObservation(res, redirects, resp.Header); e != nil {
		return Result{}, e
	}
	return res, nil
}
func (s *Service) persist(siteID, monitorID int64, res Result) (Result, error) {
	rows, e := sqlite.Query(s.store.DB, `INSERT INTO check_results(site_id,monitor_id,ok,status_code,latency_ms,response_bytes,final_url,error_class,error,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id`, siteID, monitorID, res.OK, res.StatusCode, res.LatencyMS, res.ResponseBytes, res.FinalURL, res.ErrorClass, res.Error, res.CheckedAt)
	if e != nil {
		return Result{}, e
	}
	res.ID = rows[0]["id"].Int64
	if err := s.updateHealth(res); err != nil {
		return Result{}, err
	}
	return res, nil
}
func (s *Service) persistHTTPObservation(res Result, redirects []string, h http.Header) (HTTPObservation, error) {
	selected := map[string]string{}
	for _, name := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-Frame-Options", "Server", "Content-Type"} {
		if v := h.Get(name); v != "" {
			selected[name] = v
		}
	}
	exp, err := sqlite.Query(s.store.DB, `SELECT name FROM header_expectations WHERE site_id=? AND required=1 ORDER BY lower(name)`, res.SiteID)
	if err != nil {
		return HTTPObservation{}, err
	}
	missing := []string{}
	final, _ := url.Parse(res.FinalURL)
	for _, r := range exp {
		name := r["name"].Text
		if strings.EqualFold(name, "Strict-Transport-Security") && final != nil && final.Scheme != "https" {
			continue
		}
		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	chainJSON, _ := json.Marshal(redirects)
	headersJSON, _ := json.Marshal(selected)
	missingText := strings.Join(missing, "\n")
	changed := false
	prev, _ := sqlite.Query(s.store.DB, `SELECT redirect_chain,headers_json,missing_headers FROM http_observations WHERE site_id=? ORDER BY id DESC LIMIT 1`, res.SiteID)
	if len(prev) > 0 {
		changed = prev[0]["redirect_chain"].Text != string(chainJSON) || prev[0]["headers_json"].Text != string(headersJSON) || prev[0]["missing_headers"].Text != missingText
	}
	rows, err := sqlite.Query(s.store.DB, `INSERT INTO http_observations(site_id,check_id,redirect_chain,headers_json,missing_headers,changed,observed_at) VALUES(?,?,?,?,?,?,?) RETURNING id`, res.SiteID, res.ID, string(chainJSON), string(headersJSON), missingText, changed, res.CheckedAt)
	if err != nil {
		return HTTPObservation{}, err
	}
	return HTTPObservation{ID: rows[0]["id"].Int64, SiteID: res.SiteID, CheckID: res.ID, RedirectChain: redirects, Headers: selected, MissingHeaders: missing, Changed: changed, ObservedAt: res.CheckedAt}, nil
}
func (s *Service) HTTPHistory(siteID int64) ([]HTTPObservation, error) {
	rows, err := sqlite.Query(s.store.DB, `SELECT id,site_id,check_id,redirect_chain,headers_json,missing_headers,changed,observed_at FROM http_observations WHERE site_id=? ORDER BY id DESC LIMIT 50`, siteID)
	if err != nil {
		return nil, err
	}
	out := make([]HTTPObservation, 0, len(rows))
	for _, r := range rows {
		o := HTTPObservation{ID: r["id"].Int64, SiteID: r["site_id"].Int64, CheckID: r["check_id"].Int64, Changed: r["changed"].Int64 != 0, ObservedAt: r["observed_at"].Text, Headers: map[string]string{}}
		_ = json.Unmarshal([]byte(r["redirect_chain"].Text), &o.RedirectChain)
		_ = json.Unmarshal([]byte(r["headers_json"].Text), &o.Headers)
		if r["missing_headers"].Text != "" {
			o.MissingHeaders = strings.Split(r["missing_headers"].Text, "\n")
		}
		out = append(out, o)
	}
	return out, nil
}
func (s *Service) HeaderExpectations(siteID int64) (map[string]bool, error) {
	rows, err := sqlite.Query(s.store.DB, `SELECT name,required FROM header_expectations WHERE site_id=? ORDER BY lower(name)`, siteID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r["name"].Text] = r["required"].Int64 != 0
	}
	return out, nil
}
func (s *Service) SetHeaderExpectation(siteID int64, name string, required bool) error {
	name = http.CanonicalHeaderKey(strings.TrimSpace(name))
	allowed := map[string]bool{"Content-Security-Policy": true, "Strict-Transport-Security": true, "X-Content-Type-Options": true, "Referrer-Policy": true, "Permissions-Policy": true, "X-Frame-Options": true}
	if !allowed[name] {
		return errors.New("unsupported header expectation")
	}
	return sqlite.Exec(s.store.DB, `INSERT INTO header_expectations(site_id,name,required) VALUES(?,?,?) ON CONFLICT(site_id,name) DO UPDATE SET required=excluded.required`, siteID, name, required)
}

func (s *Service) updateHealth(res Result) error {
	rows, err := sqlite.Query(s.store.DB, `SELECT state,consecutive_failures FROM site_health WHERE site_id=?`, res.SiteID)
	if err != nil {
		return err
	}
	state := "unknown"
	fails := int64(0)
	if len(rows) > 0 {
		state = rows[0]["state"].Text
		fails = rows[0]["consecutive_failures"].Int64
	}
	next := state
	now := res.CheckedAt
	var success any = nil
	var failure any = nil
	if res.OK {
		fails = 0
		next = "healthy"
		success = now
	} else {
		fails++
		failure = now
		if fails == 1 {
			next = "warning"
		} else {
			next = "down"
		}
		if res.ErrorClass == "http_status" && fails == 1 {
			next = "degraded"
		}
	}
	changed := next != state
	if len(rows) == 0 {
		err = sqlite.Exec(s.store.DB, `INSERT INTO site_health(site_id,state,consecutive_failures,last_check_id,last_change_at,last_success_at,last_failure_at) VALUES(?,?,?,?,?,?,?)`, res.SiteID, next, fails, res.ID, now, success, failure)
	} else if changed {
		err = sqlite.Exec(s.store.DB, `UPDATE site_health SET state=?,consecutive_failures=?,last_check_id=?,last_change_at=?,last_success_at=COALESCE(?,last_success_at),last_failure_at=COALESCE(?,last_failure_at) WHERE site_id=?`, next, fails, res.ID, now, success, failure, res.SiteID)
	} else {
		err = sqlite.Exec(s.store.DB, `UPDATE site_health SET consecutive_failures=?,last_check_id=?,last_success_at=COALESCE(?,last_success_at),last_failure_at=COALESCE(?,last_failure_at) WHERE site_id=?`, fails, res.ID, success, failure, res.SiteID)
	}
	if err != nil {
		return err
	}
	if changed {
		return incidents.New(s.store).Transition(res.SiteID, state, next, now)
	}
	return nil
}

func (s *Service) Recent(siteID int64, limit int) ([]Result, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	rows, e := sqlite.Query(s.store.DB, `SELECT id,site_id,monitor_id,ok,status_code,latency_ms,response_bytes,final_url,error_class,error,checked_at FROM check_results WHERE site_id=? ORDER BY id DESC LIMIT ?`, siteID, limit)
	if e != nil {
		return nil, e
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		out = append(out, resultRow(r))
	}
	return out, nil
}
func resultRow(r sqlite.Row) Result {
	return Result{ID: r["id"].Int64, SiteID: r["site_id"].Int64, MonitorID: r["monitor_id"].Int64, OK: r["ok"].Int64 != 0, StatusCode: int(r["status_code"].Int64), LatencyMS: r["latency_ms"].Int64, ResponseBytes: r["response_bytes"].Int64, FinalURL: r["final_url"].Text, ErrorClass: r["error_class"].Text, Error: r["error"].Text, CheckedAt: r["checked_at"].Text}
}
func classifyError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "blocked target"):
		return "blocked"
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "lookup") || strings.Contains(msg, "resolve"):
		return "dns"
	case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") || strings.Contains(msg, "x509"):
		return "tls"
	case strings.Contains(msg, "redirect"):
		return "redirect"
	default:
		return "connection"
	}
}

package crawler

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/webfleet-cv/webfleet/internal/netguard"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

const (
	MaxPages          = 500
	MaxDepth          = 8
	MaxLinksPerPage   = 1000
	MaxExternalChecks = 20
	MaxBodyBytes      = 2 << 20
)

type Service struct {
	store    *store.Store
	guard    netguard.Guard
	mu       sync.Mutex
	inflight map[int64]bool
}
type Run struct {
	ID                    int64  `json:"id"`
	SiteID                int64  `json:"site_id"`
	Status                string `json:"status"`
	PagesCrawled          int    `json:"pages_crawled"`
	PagesDiscovered       int    `json:"pages_discovered"`
	PageLimit             int    `json:"page_limit"`
	LimitReached          bool   `json:"limit_reached"`
	SitemapURLsDiscovered int    `json:"sitemap_urls"`
	CurrentURL            string `json:"current_url"`
	PagesFailed           int    `json:"pages_failed"`
	CSSFiles              int    `json:"css_files"`
	JavaScriptFiles       int    `json:"javascript_files"`
	ImageFiles            int    `json:"image_files"`
	FontFiles             int    `json:"font_files"`
	MediaFiles            int    `json:"media_files"`
	DocumentFiles         int    `json:"document_files"`
	DataFeedFiles         int    `json:"data_feed_files"`
	OtherAssetFiles       int    `json:"other_asset_files"`
	InternalLinks         int    `json:"internal_links"`
	ExternalLinks         int    `json:"external_links"`
	BrokenInternal        int    `json:"broken_internal"`
	BrokenExternal        int    `json:"broken_external"`
	NewBroken             int    `json:"new_broken"`
	RobotsFound           bool   `json:"robots_found"`
	SitemapFound          bool   `json:"sitemap_found"`
	Error                 string `json:"error"`
	StartedAt             string `json:"started_at"`
	FinishedAt            string `json:"finished_at"`
}
type Page struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Depth      int    `json:"depth"`
	Error      string `json:"error"`
	Kind       string `json:"kind"`
	AssetClass string `json:"asset_class"`
	Origin     string `json:"origin"`
	OK         bool   `json:"ok"`
}
type Link struct {
	FromURL    string `json:"from_url"`
	ToURL      string `json:"to_url"`
	Kind       string `json:"kind"`
	StatusCode int    `json:"status_code"`
	Broken     bool   `json:"broken"`
	Error      string `json:"error"`
}
type Detail struct {
	Run    Run    `json:"run"`
	Pages  []Page `json:"pages"`
	Assets []Page `json:"assets"`
	Links  []Link `json:"links"`
}

type fetchResult struct {
	status int
	body   []byte
	final  string
	header http.Header
	err    error
}
type queued struct {
	u     string
	depth int
}

func New(st *store.Store) *Service {
	return &Service{store: st, guard: netguard.New(), inflight: map[int64]bool{}}
}
func NewForTests(st *store.Store, g netguard.Guard) *Service {
	return &Service{store: st, guard: g, inflight: map[int64]bool{}}
}

// aHrefRE matches navigation links only (<a href>), keeping the page/link
// metric distinct from asset/resource references.
var aHrefRE = regexp.MustCompile(`(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']`)
var linkTagRE = regexp.MustCompile(`(?is)<link\b([^>]*)>`)
var linkRelRE = regexp.MustCompile(`(?i)\brel\s*=\s*["']([^"']+)["']`)
var linkHrefRE = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"'#]+)["']`)
var srcRE = regexp.MustCompile(`(?i)\b(src|poster)\s*=\s*["']([^"']+)["']`)
var srcsetRE = regexp.MustCompile(`(?i)\bsrcset\s*=\s*["']([^"']+)["']`)
var locRE = regexp.MustCompile(`(?is)<loc>\s*([^<]+?)\s*</loc>`)

func (s *Service) CrawlSite(ctx context.Context, siteID int64) (Detail, error) {
	rows, e := sqlite.Query(s.store.DB, `SELECT primary_url FROM sites WHERE id=? AND archived_at IS NULL`, siteID)
	if e != nil || len(rows) == 0 {
		return Detail{}, errors.New("site not found")
	}
	root, e := url.Parse(rows[0]["primary_url"].Text)
	if e != nil {
		return Detail{}, e
	}
	root.Fragment = ""
	prevID := int64(0)
	if p, _ := sqlite.Query(s.store.DB, `SELECT id FROM crawl_runs WHERE site_id=? AND status='complete' ORDER BY id DESC LIMIT 1`, siteID); len(p) > 0 {
		prevID = p[0]["id"].Int64
	}
	started := store.Now()
	ridRows, e := sqlite.Query(s.store.DB, `INSERT INTO crawl_runs(site_id,status,started_at) VALUES(?,'running',?) RETURNING id`, siteID, started)
	if e != nil {
		return Detail{}, e
	}
	runID := ridRows[0]["id"].Int64
	detail := Detail{Run: Run{ID: runID, SiteID: siteID, Status: "running", StartedAt: started}}
	defer func() {
		if detail.Run.Status == "running" {
			detail.Run.Status = "error"
		}
	}()
	robots, robotsFound, sitemaps := s.loadRobots(ctx, root)
	detail.Run.RobotsFound = robotsFound
	if len(sitemaps) == 0 {
		sitemapURL := *root
		sitemapURL.Path = "/sitemap.xml"
		sitemapURL.RawQuery = ""
		sitemaps = append(sitemaps, sitemapURL.String())
	}
	queue := []queued{{u: root.String(), depth: 0}}
	seen := map[string]bool{}
	known := map[string]bool{root.String(): true}
	discovered := 1
	sitemapPages := map[string]bool{}
	internalPages := map[string]bool{root.String(): true}
	assets := map[string]string{}
	for _, sm := range sitemaps {
		if urls := s.loadSitemap(ctx, sm, root); len(urls) > 0 {
			detail.Run.SitemapFound = true
			for _, u := range urls {
				if pu, perr := url.Parse(u); perr == nil && isAsset(pu) {
					continue
				}
				// Every unique HTML URL actually obtained from sitemap data is
				// recorded regardless of whether it was already known from
				// another source, so the sitemap count is exact.
				if !sitemapPages[u] {
					sitemapPages[u] = true
					detail.Run.SitemapURLsDiscovered++
				}
				if !known[u] {
					known[u] = true
					discovered++
					queue = append(queue, queued{u: u, depth: 0})
				}
			}
		}
	}
	external := map[string]Link{}
	brokenNow := map[string]bool{}
	for len(queue) > 0 && len(detail.Pages) < MaxPages {
		q := queue[0]
		queue = queue[1:]
		if seen[q.u] || q.depth > MaxDepth {
			continue
		}
		seen[q.u] = true
		detail.Run.CurrentURL = q.u
		u, _ := url.Parse(q.u)
		if disallowed(robots, u.Path) {
			continue
		}
		fr := s.fetch(ctx, http.MethodGet, q.u, MaxBodyBytes)
		page := Page{URL: q.u, Depth: q.depth, StatusCode: fr.status}
		if fr.err != nil {
			page.Error = fr.err.Error()
		}
		isHTML := true
		if ct := strings.ToLower(fr.header.Get("Content-Type")); ct != "" && !strings.Contains(ct, "text/html") {
			isHTML = false
		}
		// A fetched resource that is neither HTML nor an error is an asset
		// (extensionless target); classify it by its authoritative Content-Type.
		if !isHTML && fr.err == nil && fr.status < 400 {
			cls := assetClassByContentType(fr.header.Get("Content-Type"))
			if _, ok := assets[q.u]; !ok {
				assets[q.u] = cls
				_, _ = sqlite.Query(s.store.DB, `INSERT INTO crawl_pages(run_id,site_id,url,status_code,depth,error,kind,asset_class,origin,ok) VALUES(?,?,?,0,0,'','asset',?,'internal',0) RETURNING id`, runID, siteID, q.u, cls)
			}
			// It was counted as a discovered page when enqueued, but it is a
			// resource, not an HTML page.
			if discovered > 0 {
				discovered--
			}
			_ = s.persistProgress(runID, detail, discovered)
			continue
		}
		// A real page: record its discovery origin and whether it was fetched OK.
		page.Kind = "page"
		page.Origin = "internal"
		if sitemapPages[q.u] {
			page.Origin = "sitemap"
		}
		if page.Origin == "sitemap" && internalPages[q.u] {
			page.Origin = "both"
		}
		page.OK = fr.err == nil && fr.status < 400
		detail.Pages = append(detail.Pages, page)
		_, _ = sqlite.Query(s.store.DB, `INSERT INTO crawl_pages(run_id,site_id,url,status_code,depth,error,kind,asset_class,origin,ok) VALUES(?,?,?,?,?,?,'page','',?,?) RETURNING id`, runID, siteID, q.u, page.StatusCode, q.depth, page.Error, page.Origin, page.OK)
		if !page.OK {
			brokenNow[q.u] = true
			_ = s.persistProgress(runID, detail, discovered)
			continue
		}
		links := extractNavigationLinks(fr.body, fr.final)
		if len(links) > MaxLinksPerPage {
			links = links[:MaxLinksPerPage]
		}
		for _, target := range links {
			tu, e := url.Parse(target)
			if e != nil || tu.Hostname() == "" {
				continue
			}
			kind := "external"
			if strings.EqualFold(tu.Hostname(), root.Hostname()) {
				kind = "internal"
				detail.Run.InternalLinks++
				if isAsset(tu) {
					if _, ok := assets[target]; !ok {
						assets[target] = assetClass(tu)
						_, _ = sqlite.Query(s.store.DB, `INSERT INTO crawl_pages(run_id,site_id,url,status_code,depth,error,kind,asset_class,origin,ok) VALUES(?,?,?,0,0,'','asset',?,'internal',0) RETURNING id`, runID, siteID, target, assetClass(tu))
					}
				} else {
					internalPages[target] = true
					if !known[target] && q.depth < MaxDepth {
						known[target] = true
						discovered++
						queue = append(queue, queued{u: target, depth: q.depth + 1})
					}
				}
			} else {
				detail.Run.ExternalLinks++
				if len(external) < MaxExternalChecks {
					external[target] = Link{FromURL: q.u, ToURL: target, Kind: "external"}
				}
			}
			_, _ = sqlite.Query(s.store.DB, `INSERT INTO crawl_links(run_id,site_id,from_url,to_url,kind,status_code,broken,error) VALUES(?,?,?,?,?,0,0,'') RETURNING id`, runID, siteID, q.u, target, kind)
		}
		// Resource references (<link href>, src, srcset, poster) are
		// inventoried as assets; they are not navigation links and never pages.
		for _, res := range extractResources(fr.body, fr.final) {
			ru, rerr := url.Parse(res)
			if rerr != nil || !strings.EqualFold(ru.Hostname(), root.Hostname()) {
				continue
			}
			if _, ok := assets[res]; !ok {
				cls := assetClass(ru)
				if cls == "" {
					cls = "other"
				}
				assets[res] = cls
				_, _ = sqlite.Query(s.store.DB, `INSERT INTO crawl_pages(run_id,site_id,url,status_code,depth,error,kind,asset_class,origin,ok) VALUES(?,?,?,0,0,'','asset',?,'internal',0) RETURNING id`, runID, siteID, res, cls)
			}
		}
		_ = s.persistProgress(runID, detail, discovered)
	}
	// Internal broken links are pages that were linked and returned an error/status >=400.
	for _, p := range detail.Pages {
		if p.Error != "" || p.StatusCode >= 400 {
			detail.Run.BrokenInternal++
			brokenNow[p.URL] = true
		}
	}
	// External checks are capped and HEAD-only to remain conservative.
	keys := make([]string, 0, len(external))
	for k := range external {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, target := range keys {
		l := external[target]
		fr := s.fetch(ctx, http.MethodHead, target, 64<<10)
		if fr.err == nil && (fr.status == http.StatusMethodNotAllowed || fr.status == http.StatusNotImplemented) {
			fr = s.fetch(ctx, http.MethodGet, target, 64<<10)
		}
		l.StatusCode = fr.status
		if fr.err != nil {
			l.Broken = true
			l.Error = fr.err.Error()
		} else if fr.status >= 400 {
			l.Broken = true
		}
		if l.Broken {
			detail.Run.BrokenExternal++
			brokenNow[target] = true
		}
		external[target] = l
		time.Sleep(20 * time.Millisecond)
	}
	// Update persisted link rows with verified statuses/broken state. Internal targets use page results.
	statusByURL := map[string]Page{}
	for _, p := range detail.Pages {
		statusByURL[p.URL] = p
	}
	for _, target := range keys {
		l := external[target]
		_ = sqlite.Exec(s.store.DB, `UPDATE crawl_links SET status_code=?,broken=?,error=? WHERE run_id=? AND kind='external' AND to_url=?`, l.StatusCode, l.Broken, l.Error, runID, target)
	}
	for target, p := range statusByURL {
		broken := p.Error != "" || p.StatusCode >= 400
		_ = sqlite.Exec(s.store.DB, `UPDATE crawl_links SET status_code=?,broken=?,error=? WHERE run_id=? AND kind='internal' AND to_url=?`, p.StatusCode, broken, p.Error, runID, target)
	}
	if prevID > 0 {
		prev, _ := sqlite.Query(s.store.DB, `SELECT DISTINCT to_url FROM crawl_links WHERE run_id=? AND broken=1`, prevID)
		old := map[string]bool{}
		for _, r := range prev {
			old[r["to_url"].Text] = true
		}
		for u := range brokenNow {
			if !old[u] {
				detail.Run.NewBroken++
			}
		}
	} else {
		detail.Run.NewBroken = len(brokenNow)
	}
	detail.Run.PagesCrawled = len(detail.Pages)
	detail.Run.PagesDiscovered = discovered
	detail.Run.SitemapURLsDiscovered = len(sitemapPages)
	detail.Run.PageLimit = MaxPages
	// The crawl is truncated only when it stopped at the page ceiling while
	// undiscovered work still remained in the queue.
	detail.Run.LimitReached = len(detail.Pages) >= MaxPages && len(queue) > 0
	for _, p := range detail.Pages {
		if !p.OK {
			detail.Run.PagesFailed++
		}
	}
	for _, cls := range assets {
		switch cls {
		case "css":
			detail.Run.CSSFiles++
		case "javascript":
			detail.Run.JavaScriptFiles++
		case "image":
			detail.Run.ImageFiles++
		case "font":
			detail.Run.FontFiles++
		case "media":
			detail.Run.MediaFiles++
		case "document":
			detail.Run.DocumentFiles++
		case "data":
			detail.Run.DataFeedFiles++
		default:
			detail.Run.OtherAssetFiles++
		}
	}
	detail.Run.CurrentURL = ""
	detail.Run.Status = "complete"
	detail.Run.FinishedAt = store.Now()
	_ = sqlite.Exec(s.store.DB, `UPDATE crawl_runs SET status='complete',pages_crawled=?,pages_discovered=?,page_limit=?,limit_reached=?,sitemap_urls_discovered=?,current_url='',pages_failed=?,css_files=?,javascript_files=?,image_files=?,font_files=?,media_files=?,document_files=?,data_feed_files=?,other_asset_files=?,internal_links=?,external_links=?,broken_internal=?,broken_external=?,new_broken=?,robots_found=?,sitemap_found=?,finished_at=? WHERE id=?`, detail.Run.PagesCrawled, detail.Run.PagesDiscovered, detail.Run.PageLimit, detail.Run.LimitReached, detail.Run.SitemapURLsDiscovered, detail.Run.PagesFailed, detail.Run.CSSFiles, detail.Run.JavaScriptFiles, detail.Run.ImageFiles, detail.Run.FontFiles, detail.Run.MediaFiles, detail.Run.DocumentFiles, detail.Run.DataFeedFiles, detail.Run.OtherAssetFiles, detail.Run.InternalLinks, detail.Run.ExternalLinks, detail.Run.BrokenInternal, detail.Run.BrokenExternal, detail.Run.NewBroken, detail.Run.RobotsFound, detail.Run.SitemapFound, detail.Run.FinishedAt, runID)
	full, e := s.Detail(runID)
	if e == nil {
		return full, nil
	}
	return detail, nil
}
func (s *Service) loadRobots(ctx context.Context, root *url.URL) ([]string, bool, []string) {
	u := *root
	u.Path = "/robots.txt"
	u.RawQuery = ""
	fr := s.fetch(ctx, http.MethodGet, u.String(), 256<<10)
	if fr.err != nil || fr.status != 200 {
		return nil, false, nil
	}
	var dis []string
	var maps []string
	active := false
	for _, line := range strings.Split(string(fr.body), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.TrimSpace(parts[1])
		switch k {
		case "user-agent":
			active = v == "*"
		case "disallow":
			if active && v != "" {
				dis = append(dis, v)
			}
		case "sitemap":
			if v != "" {
				maps = append(maps, v)
			}
		}
	}
	return dis, true, maps
}
func (s *Service) loadSitemap(ctx context.Context, raw string, root *url.URL) []string {
	u, e := url.Parse(raw)
	if e != nil || !strings.EqualFold(u.Hostname(), root.Hostname()) {
		return nil
	}
	fr := s.fetch(ctx, http.MethodGet, u.String(), MaxBodyBytes)
	if fr.err != nil || fr.status != 200 {
		return nil
	}
	out := []string{}
	for _, m := range locRE.FindAllSubmatch(fr.body, MaxPages) {
		x := strings.TrimSpace(string(m[1]))
		v, e := url.Parse(x)
		if e == nil && strings.EqualFold(v.Hostname(), root.Hostname()) {
			v.Fragment = ""
			out = append(out, v.String())
		}
	}
	return out
}

// assetClassByExt classifies a resource by its URL path extension. Assets are
// inventoried (unique URL per class) but never enqueued as crawl pages.
var assetClassByExt = map[string]string{
	"css": "css", "scss": "css", "sass": "css",
	"js": "javascript", "mjs": "javascript", "cjs": "javascript",
	"png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "webp": "image", "svg": "image", "ico": "image", "avif": "image", "bmp": "image",
	"woff": "font", "woff2": "font", "ttf": "font", "otf": "font", "eot": "font",
	"mp4": "media", "mp3": "media", "webm": "media", "ogg": "media", "mov": "media", "m4a": "media", "wav": "media",
	"pdf": "document", "zip": "document", "tar": "document", "gz": "document", "7z": "document", "rar": "document", "doc": "document", "docx": "document", "xls": "document", "xlsx": "document", "ppt": "document", "pptx": "document", "epub": "document",
	"json": "data", "xml": "data", "atom": "data", "rss": "data", "txt": "data", "yaml": "data", "yml": "data", "toml": "data", "webmanifest": "data",
}

func assetClass(u *url.URL) string {
	if c, ok := assetClassByExt[strings.ToLower(strings.TrimPrefix(path.Ext(u.Path), "."))]; ok {
		return c
	}
	return ""
}

func isAsset(u *url.URL) bool { return assetClass(u) != "" }

// isAssetLinkRel reports whether a <link rel> references a resource asset
// (stylesheet/icon/manifest/preload/prefetch) rather than a page or feed
// reference such as rel="canonical" or rel="alternate".
func isAssetLinkRel(rel string) bool {
	rel = strings.ToLower(rel)
	return strings.Contains(rel, "stylesheet") || strings.Contains(rel, "icon") || strings.Contains(rel, "manifest") ||
		strings.Contains(rel, "preload") || strings.Contains(rel, "prefetch") || rel == "mask-icon"
}

// assetClassByContentType classifies a fetched resource that carried no
// classifiable path extension, using the authoritative response Content-Type.
func assetClassByContentType(ct string) string {
	ct = strings.ToLower(ct)
	switch {
	case strings.Contains(ct, "text/css"):
		return "css"
	case strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript"):
		return "javascript"
	case strings.HasPrefix(ct, "image/"):
		return "image"
	case strings.Contains(ct, "font"):
		return "font"
	case strings.HasPrefix(ct, "audio/") || strings.HasPrefix(ct, "video/"):
		return "media"
	case strings.Contains(ct, "pdf") || strings.Contains(ct, "zip") || strings.Contains(ct, "octet-stream"):
		return "document"
	case strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "rss") || strings.Contains(ct, "atom") || strings.Contains(ct, "text/plain") || strings.Contains(ct, "text/csv"):
		return "data"
	default:
		return "other"
	}
}

// isTemplateLiteral detects documentation code-sample hrefs such as
// href="$[item.url]" or @path(...) that resolve to real path strings but are
// not actual links on the site.
func isTemplateLiteral(raw string) bool {
	return strings.ContainsAny(raw, " \t") || strings.Contains(raw, "$[") || strings.Contains(raw, "@path(") || strings.Contains(raw, "{{") || strings.Contains(raw, "{%")
}

func disallowed(rules []string, path string) bool {
	for _, r := range rules {
		if r != "/" && strings.HasPrefix(path, r) {
			return true
		}
		if r == "/" {
			return true
		}
	}
	return false
}

// resolveURL resolves raw against base, keeping only http(s) absolute URLs
// with fragments stripped.
func resolveURL(raw, base string) (string, bool) {
	u, e := url.Parse(raw)
	if e != nil {
		return "", false
	}
	b, e := url.Parse(base)
	if e != nil {
		return "", false
	}
	u = b.ResolveReference(u)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	u.Fragment = ""
	return u.String(), true
}

// extractNavigationLinks returns deduplicated <a href> links: the page
// navigation/download link set that drives crawl pages and internal/external
// link counts.
func extractNavigationLinks(body []byte, base string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range aHrefRE.FindAllSubmatch(body, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if isTemplateLiteral(raw) {
			continue
		}
		x, ok := resolveURL(raw, base)
		if !ok || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// extractResources returns deduplicated resource references from real browser
// markup: <link href> (stylesheets/manifests/icons), src/poster attributes
// (script/img/source/video/audio) and srcset candidates. These are inventoried
// as assets; they are never crawl pages.
func extractResources(body []byte, base string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		x, ok := resolveURL(strings.TrimSpace(raw), base)
		if !ok || seen[x] {
			return
		}
		seen[x] = true
		out = append(out, x)
	}
	for _, m := range linkTagRE.FindAllSubmatch(body, -1) {
		tag := string(m[1])
		rel := ""
		if rm := linkRelRE.FindStringSubmatch(tag); rm != nil {
			rel = rm[1]
		}
		if !isAssetLinkRel(rel) {
			continue
		}
		if hm := linkHrefRE.FindStringSubmatch(tag); hm != nil {
			add(hm[1])
		}
	}
	for _, m := range srcRE.FindAllSubmatch(body, -1) {
		add(string(m[2]))
	}
	for _, m := range srcsetRE.FindAllSubmatch(body, -1) {
		for _, cand := range strings.Split(string(m[1]), ",") {
			parts := strings.Fields(cand)
			if len(parts) > 0 {
				add(parts[0])
			}
		}
	}
	return out
}

func (s *Service) fetch(ctx context.Context, method, raw string, max int64) fetchResult {
	u, e := url.Parse(raw)
	if e != nil {
		return fetchResult{err: e}
	}
	if e = s.guard.ValidateURL(ctx, u); e != nil {
		return fetchResult{err: e}
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: s.guard.DialContext}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return errors.New("too many redirects")
		}
		return s.guard.ValidateURL(req.Context(), req.URL)
	}}
	req, e := http.NewRequestWithContext(ctx, method, raw, nil)
	if e != nil {
		return fetchResult{err: e}
	}
	req.Header.Set("User-Agent", "WebFleet/0.1 crawler")
	resp, e := client.Do(req)
	if e != nil {
		return fetchResult{err: e}
	}
	defer resp.Body.Close()
	var body []byte
	if method != http.MethodHead {
		body, e = io.ReadAll(io.LimitReader(resp.Body, max))
		if e != nil {
			return fetchResult{status: resp.StatusCode, err: e}
		}
	}
	return fetchResult{status: resp.StatusCode, body: body, final: resp.Request.URL.String(), header: resp.Header.Clone()}
}
func (s *Service) Latest(siteID int64) (Run, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT id,site_id,status,pages_crawled,pages_discovered,page_limit,limit_reached,sitemap_urls_discovered,current_url,pages_failed,css_files,javascript_files,image_files,font_files,media_files,document_files,data_feed_files,other_asset_files,internal_links,external_links,broken_internal,broken_external,new_broken,robots_found,sitemap_found,error,started_at,COALESCE(finished_at,'') finished_at FROM crawl_runs WHERE site_id=? ORDER BY id DESC LIMIT 1`, siteID)
	if e != nil || len(r) == 0 {
		return Run{}, errors.New("no crawl run")
	}
	return runRow(r[0]), nil
}
func (s *Service) Detail(runID int64) (Detail, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT id,site_id,status,pages_crawled,pages_discovered,page_limit,limit_reached,sitemap_urls_discovered,current_url,pages_failed,css_files,javascript_files,image_files,font_files,media_files,document_files,data_feed_files,other_asset_files,internal_links,external_links,broken_internal,broken_external,new_broken,robots_found,sitemap_found,error,started_at,COALESCE(finished_at,'') finished_at FROM crawl_runs WHERE id=?`, runID)
	if e != nil || len(r) == 0 {
		return Detail{}, errors.New("crawl run not found")
	}
	d := Detail{Run: runRow(r[0])}
	pr, e := sqlite.Query(s.store.DB, `SELECT url,status_code,depth,error,kind,asset_class,origin,ok FROM crawl_pages WHERE run_id=? AND kind='page' ORDER BY id`, runID)
	if e != nil {
		return Detail{}, e
	}
	for _, x := range pr {
		d.Pages = append(d.Pages, Page{URL: x["url"].Text, StatusCode: int(x["status_code"].Int64), Depth: int(x["depth"].Int64), Error: x["error"].Text, Kind: x["kind"].Text, AssetClass: x["asset_class"].Text, Origin: x["origin"].Text, OK: x["ok"].Int64 != 0})
	}
	ar, e := sqlite.Query(s.store.DB, `SELECT url,status_code,depth,error,kind,asset_class,origin,ok FROM crawl_pages WHERE run_id=? AND kind='asset' ORDER BY id`, runID)
	if e != nil {
		return Detail{}, e
	}
	for _, x := range ar {
		d.Assets = append(d.Assets, Page{URL: x["url"].Text, StatusCode: int(x["status_code"].Int64), Depth: int(x["depth"].Int64), Error: x["error"].Text, Kind: x["kind"].Text, AssetClass: x["asset_class"].Text, Origin: x["origin"].Text, OK: x["ok"].Int64 != 0})
	}
	lr, e := sqlite.Query(s.store.DB, `SELECT from_url,to_url,kind,status_code,broken,error FROM crawl_links WHERE run_id=? ORDER BY id LIMIT 1000`, runID)
	if e != nil {
		return Detail{}, e
	}
	for _, x := range lr {
		d.Links = append(d.Links, Link{FromURL: x["from_url"].Text, ToURL: x["to_url"].Text, Kind: x["kind"].Text, StatusCode: int(x["status_code"].Int64), Broken: x["broken"].Int64 != 0, Error: x["error"].Text})
	}
	return d, nil
}
func (s *Service) LatestDetail(siteID int64) (Detail, error) {
	r, e := s.Latest(siteID)
	if e != nil {
		return Detail{}, e
	}
	return s.Detail(r.ID)
}
func (s *Service) FleetRegressions(orgID int64) ([]Run, error) {
	r, e := sqlite.Query(s.store.DB, `SELECT c.id,c.site_id,c.status,c.pages_crawled,c.pages_discovered,c.page_limit,c.limit_reached,c.sitemap_urls_discovered,c.current_url,c.pages_failed,c.css_files,c.javascript_files,c.image_files,c.font_files,c.media_files,c.document_files,c.data_feed_files,c.other_asset_files,c.internal_links,c.external_links,c.broken_internal,c.broken_external,c.new_broken,c.robots_found,c.sitemap_found,c.error,c.started_at,COALESCE(c.finished_at,'') finished_at FROM crawl_runs c JOIN (SELECT site_id,MAX(id) id FROM crawl_runs WHERE status='complete' GROUP BY site_id) x ON x.id=c.id JOIN sites s ON s.id=c.site_id WHERE s.organization_id=? AND (c.new_broken>0 OR c.broken_internal>0 OR c.broken_external>0) ORDER BY c.new_broken DESC,c.id DESC LIMIT 50`, orgID)
	if e != nil {
		return nil, e
	}
	out := make([]Run, 0, len(r))
	for _, x := range r {
		out = append(out, runRow(x))
	}
	return out, nil
}
func runRow(r sqlite.Row) Run {
	return Run{ID: r["id"].Int64, SiteID: r["site_id"].Int64, Status: r["status"].Text, PagesCrawled: int(r["pages_crawled"].Int64), PagesDiscovered: int(r["pages_discovered"].Int64), PageLimit: int(r["page_limit"].Int64), LimitReached: r["limit_reached"].Int64 != 0, SitemapURLsDiscovered: int(r["sitemap_urls_discovered"].Int64), CurrentURL: r["current_url"].Text, PagesFailed: int(r["pages_failed"].Int64), CSSFiles: int(r["css_files"].Int64), JavaScriptFiles: int(r["javascript_files"].Int64), ImageFiles: int(r["image_files"].Int64), FontFiles: int(r["font_files"].Int64), MediaFiles: int(r["media_files"].Int64), DocumentFiles: int(r["document_files"].Int64), DataFeedFiles: int(r["data_feed_files"].Int64), OtherAssetFiles: int(r["other_asset_files"].Int64), InternalLinks: int(r["internal_links"].Int64), ExternalLinks: int(r["external_links"].Int64), BrokenInternal: int(r["broken_internal"].Int64), BrokenExternal: int(r["broken_external"].Int64), NewBroken: int(r["new_broken"].Int64), RobotsFound: r["robots_found"].Int64 != 0, SitemapFound: r["sitemap_found"].Int64 != 0, Error: r["error"].Text, StartedAt: r["started_at"].Text, FinishedAt: r["finished_at"].Text}
}

// persistProgress writes the live crawl state so a polling client can observe
// real crawled/discovered counts and the current URL while the crawl runs.
func (s *Service) persistProgress(runID int64, detail Detail, discovered int) error {
	return sqlite.Exec(s.store.DB, `UPDATE crawl_runs SET pages_crawled=?,pages_discovered=?,current_url=? WHERE id=?`, len(detail.Pages), discovered, detail.Run.CurrentURL, runID)
}

// Claim synchronously reserves a site for crawling and returns false if a
// crawl is already in flight, so a second concurrent start is rejected
// deterministically (independent of when the background run writes its row).
func (s *Service) Claim(siteID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[siteID] {
		return false
	}
	s.inflight[siteID] = true
	return true
}

// Release clears the in-flight reservation for a site.
func (s *Service) Release(siteID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, siteID)
}

var _ = fmt.Sprintf

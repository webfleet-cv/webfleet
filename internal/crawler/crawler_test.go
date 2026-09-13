package crawler

import (
	"context"
	"fmt"
	"github.com/webfleet-cv/webfleet/internal/netguard"
	"github.com/webfleet-cv/webfleet/internal/sites"
	"github.com/webfleet-cv/webfleet/internal/store"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type resolver struct{ ip netip.Addr }

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}
func TestCrawlRespectsRobotsAndFindsBrokenLinks(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /private\nSitemap: "+base+"/sitemap.xml\n")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, "<urlset><url><loc>"+base+"/extra</loc></url></urlset>")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/ok">ok</a><a href="/missing">missing</a><a href="/private">private</a>`)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/extra", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "extra")
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) { t.Error("robots-disallowed page fetched") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	u, _ := url.Parse(base)
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	site, e := sites.New(st).Create(1, "x", base, 0)
	if e != nil {
		t.Fatal(e)
	}
	g := netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}
	d, e := NewForTests(st, g).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	if !d.Run.RobotsFound || !d.Run.SitemapFound || d.Run.BrokenInternal < 1 {
		t.Fatalf("run=%+v", d.Run)
	}
	for _, p := range d.Pages {
		if strings.Contains(p.URL, "/private") {
			t.Fatal("private page crawled")
		}
	}
}

// multiPageSite serves `n` linked pages on one host plus a sitemap listing a
// set of URLs (some reachable only via the sitemap) so tests can distinguish
// crawled, discovered, sitemap-discovered and internally-discovered counts.
func multiPageSite(n, sitemapExtra int) (*httptest.Server, func() int) {
	var base string
	crawled := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nSitemap: %s/sitemap.xml\n", base)
	})
	for i := 1; i <= n; i++ {
		cur := i
		mux.HandleFunc(fmt.Sprintf("/p%d", i), func(w http.ResponseWriter, r *http.Request) {
			crawled++
			w.Header().Set("Content-Type", "text/html")
			next := cur + 1
			if next <= n {
				fmt.Fprintf(w, `<a href="/p%d">next</a>`, next)
			}
		})
	}
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		var sb strings.Builder
		sb.WriteString("<urlset>")
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&sb, "<url><loc>%s/p%d</loc></url>", base, i)
		}
		for i := 1; i <= sitemapExtra; i++ {
			fmt.Fprintf(&sb, "<url><loc>%s/sm%d</loc></url>", base, i)
		}
		sb.WriteString("</urlset>")
		w.Write([]byte(sb.String()))
	})
	for i := 1; i <= sitemapExtra; i++ {
		cur := i
		mux.HandleFunc(fmt.Sprintf("/sm%d", i), func(w http.ResponseWriter, r *http.Request) {
			crawled++
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "sitemap page %d", cur)
		})
	}
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv, func() int { return crawled }
}

func crawlServiceFor(t *testing.T, base string) *Service {
	t.Helper()
	u, _ := url.Parse(base)
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	site, e := sites.New(st).Create(1, "x", base, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("CRAWL_TEST_SITE_ID", fmt.Sprintf("%d", site.ID))
	return NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true})
}

func TestCrawlExceedsFiftyPages(t *testing.T) {
	srv, _ := multiPageSite(80, 0)
	defer srv.Close()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(srv.URL)
	site, _ := sites.New(st).Create(1, "x", srv.URL, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	if d.Run.PagesCrawled < 60 {
		t.Fatalf("crawled %d pages, want >50 (old ceiling)", d.Run.PagesCrawled)
	}
}

func TestCrawlLimitsAndDiscoveredCounts(t *testing.T) {
	// 700 reachable pages exceeds the 500 ceiling; sitemap adds 150 more
	// discovered-but-maybe-uncrawled URLs -> pages_discovered > pages_crawled.
	srv, _ := multiPageSite(700, 150)
	defer srv.Close()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(srv.URL)
	site, _ := sites.New(st).Create(1, "x", srv.URL, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	r := d.Run
	if r.PagesCrawled > MaxPages {
		t.Fatalf("pages_crawled=%d exceeds MaxPages=%d", r.PagesCrawled, MaxPages)
	}
	if r.PagesDiscovered <= r.PagesCrawled {
		t.Fatalf("pages_discovered=%d should exceed pages_crawled=%d on a truncated crawl", r.PagesDiscovered, r.PagesCrawled)
	}
	if r.PageLimit != MaxPages {
		t.Fatalf("page_limit=%d want %d", r.PageLimit, MaxPages)
	}
	if !r.LimitReached {
		t.Fatal("limit_reached=false but the crawl hit the ceiling with work remaining")
	}
	if r.SitemapURLsDiscovered < 150 {
		t.Fatalf("sitemap_urls_discovered=%d want >=150", r.SitemapURLsDiscovered)
	}
}

func TestCrawlSmallSiteCompleteNoLimit(t *testing.T) {
	srv, _ := multiPageSite(30, 5)
	defer srv.Close()
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(srv.URL)
	site, _ := sites.New(st).Create(1, "x", srv.URL, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	r := d.Run
	if r.LimitReached {
		t.Fatal("small site reported limit_reached")
	}
	// root + 30 linked pages + 5 sitemap-only pages.
	if r.PagesCrawled != 36 {
		t.Fatalf("pages_crawled=%d want 36", r.PagesCrawled)
	}
	if r.PagesDiscovered != 36 {
		t.Fatalf("pages_discovered=%d want 36", r.PagesDiscovered)
	}
}

func TestCrawlLinksPerPageBeyond200(t *testing.T) {
	var base string
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html")
		var sb strings.Builder
		for i := 1; i <= 400; i++ {
			fmt.Fprintf(&sb, `<a href="/q%d">l</a>`, i)
		}
		w.Write([]byte(sb.String()))
	})
	for i := 1; i <= 400; i++ {
		cur := i
		mux.HandleFunc(fmt.Sprintf("/q%d", i), func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "p %d", cur)
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(base)
	site, _ := sites.New(st).Create(1, "x", base, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	if d.Run.InternalLinks < 300 {
		t.Fatalf("internal_links=%d, want >200 links discovered from one page", d.Run.InternalLinks)
	}
}

func TestCrawlExcludesAssetsAndTemplateLiterals(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="/style.css">css</a><a href="/asset.zip">zip</a><a href="/real">real</a><a href="$[item.url]">literal</a><a href="/docs/@path(">literal2</a>`)
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprint(w, "body{}")
	})
	mux.HandleFunc("/asset.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		fmt.Fprint(w, "zip")
	})
	mux.HandleFunc("/real", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "real")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(base)
	site, _ := sites.New(st).Create(1, "x", base, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range d.Pages {
		for _, bad := range []string{"/style.css", "/asset.zip", "$[", "@path("} {
			if strings.Contains(p.URL, bad) {
				t.Fatalf("asset/template-literal URL counted as a page: %s", p.URL)
			}
		}
	}
	// root + /real are the only pages; the asset and literal links are internal
	// links but never crawled pages.
	if d.Run.PagesCrawled != 2 {
		t.Fatalf("pages_crawled=%d want 2 (root + /real)", d.Run.PagesCrawled)
	}
	if d.Run.PagesDiscovered != 2 {
		t.Fatalf("pages_discovered=%d want 2", d.Run.PagesDiscovered)
	}
	if d.Run.InternalLinks < 3 {
		t.Fatalf("internal_links=%d want >=3 (asset links still count as internal links; template literals are filtered)", d.Run.InternalLinks)
	}
}

// TestCrawlAssetInventoryUnique proves assets are inventoried as unique
// normalized URLs per class, repeated references count once, extensionless
// resources are classified by Content-Type, and no asset ever becomes a page.
func TestCrawlAssetInventoryUnique(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="/style.css">c1</a><a href="/style.css">c2</a><a href="/app.js">j</a><a href="/img.png">i</a><a href="/img.png">i2</a><a href="/font.woff2">f</a><a href="/dl.zip">d</a><a href="/blob">b</a>`)
	})
	mux.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "png")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(base)
	site, _ := sites.New(st).Create(1, "x", base, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	r := d.Run
	// Only the root page is HTML; the extensionless /blob is an image asset.
	if r.PagesCrawled != 1 || r.PagesDiscovered != 1 {
		t.Fatalf("pages_crawled=%d discovered=%d want 1 (assets never become pages)", r.PagesCrawled, r.PagesDiscovered)
	}
	if r.CSSFiles != 1 || r.JavaScriptFiles != 1 || r.ImageFiles != 2 || r.FontFiles != 1 || r.DocumentFiles != 1 {
		t.Fatalf("asset counts css=%d js=%d img=%d font=%d doc=%d want 1/1/2/1/1 (unique, repeated refs counted once)",
			r.CSSFiles, r.JavaScriptFiles, r.ImageFiles, r.FontFiles, r.DocumentFiles)
	}
	if len(d.Assets) != 6 {
		t.Fatalf("assets rows=%d want 6 (5 extension + 1 content-type-classified)", len(d.Assets))
	}
	for _, a := range d.Assets {
		if a.Kind != "asset" {
			t.Fatalf("asset row kind=%q", a.Kind)
		}
		if a.URL == base+"/blob" && a.AssetClass != "image" {
			t.Fatalf("extensionless /blob class=%q want image (from Content-Type)", a.AssetClass)
		}
	}
}

// TestCrawlSitemapDiagnostics proves the sitemap/internal/crawled sets stay
// distinct so mismatch counts can be derived truthfully.
func TestCrawlSitemapDiagnostics(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="/linked">linked</a>`) // in sitemap AND internal -> both
	})
	mux.HandleFunc("/linked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="/only-internal">more</a>`)
	})
	mux.HandleFunc("/only-internal", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "internal only")
	})
	mux.HandleFunc("/only-sitemap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "sitemap only")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, "<urlset><url><loc>%s/linked</loc></url><url><loc>%s/only-sitemap</loc></url></urlset>", base, base)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(base)
	site, _ := sites.New(st).Create(1, "x", base, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	originOf := map[string]string{}
	for _, p := range d.Pages {
		originOf[p.URL] = p.Origin
	}
	if originOf[base+"/linked"] != "both" {
		t.Fatalf("/linked origin=%q want both", originOf[base+"/linked"])
	}
	if originOf[base+"/only-sitemap"] != "sitemap" {
		t.Fatalf("/only-sitemap origin=%q want sitemap", originOf[base+"/only-sitemap"])
	}
	if originOf[base+"/only-internal"] != "internal" {
		t.Fatalf("/only-internal origin=%q want internal", originOf[base+"/only-internal"])
	}
}

// TestCrawlResourceMarkupDiscovery proves the inventory sees real browser
// resource markup (link[href], script[src], img[src], img[srcset],
// source[src]) rather than only <a href>, and that resource references never
// inflate page counts or the navigation-link metric.
func TestCrawlResourceMarkupDiscovery(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<link rel="stylesheet" href="/style.css"><script src="/app.js"></script><img src="/one.webp"><img srcset="/one.webp 1x, /two.webp 2x"><source src="/clip.webm">`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	u, _ := url.Parse(base)
	site, _ := sites.New(st).Create(1, "x", base, 0)
	d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
	if e != nil {
		t.Fatal(e)
	}
	r := d.Run
	if r.PagesCrawled != 1 || r.PagesDiscovered != 1 {
		t.Fatalf("pages crawled=%d discovered=%d want 1 (resource refs are not pages)", r.PagesCrawled, r.PagesDiscovered)
	}
	if r.CSSFiles != 1 || r.JavaScriptFiles != 1 || r.ImageFiles != 2 || r.MediaFiles != 1 {
		t.Fatalf("asset counts css=%d js=%d img=%d media=%d want 1/1/2/1 (srcset dedups one.webp)", r.CSSFiles, r.JavaScriptFiles, r.ImageFiles, r.MediaFiles)
	}
	if r.InternalLinks != 0 {
		t.Fatalf("internal_links=%d want 0 (resource references must not inflate the navigation-link metric)", r.InternalLinks)
	}
}

// TestCrawlSitemapCountIsExact proves sitemap_urls equals the unique HTML URLs
// actually obtained from the sitemap, with and without the root present, and
// that the set-difference arithmetic reconciles.
func TestCrawlSitemapCountIsExact(t *testing.T) {
	for _, rootInSitemap := range []bool{true, false} {
		var base string
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<a href="/a">a</a><a href="/b">b</a>`)
		})
		mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "a")
		})
		mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "b")
		})
		mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			var sb strings.Builder
			sb.WriteString("<urlset>")
			if rootInSitemap {
				fmt.Fprintf(&sb, "<url><loc>%s/</loc></url>", base)
			}
			fmt.Fprintf(&sb, "<url><loc>%s/a</loc></url><url><loc>%s/sm-only</loc></url>", base, base)
			sb.WriteString("</urlset>")
			w.Write([]byte(sb.String()))
		})
		mux.HandleFunc("/sm-only", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "sm")
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		base = srv.URL
		st, e := store.Open(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(base)
		site, _ := sites.New(st).Create(1, "x", base, 0)
		d, e := NewForTests(st, netguard.Guard{Resolver: resolver{netip.MustParseAddr(u.Hostname())}, AllowPrivate: true}).CrawlSite(context.Background(), site.ID)
		st.Close()
		if e != nil {
			t.Fatal(e)
		}
		wantSitemap := 2
		if rootInSitemap {
			wantSitemap = 3
		}
		if d.Run.SitemapURLsDiscovered != wantSitemap {
			t.Fatalf("rootInSitemap=%v sitemap_urls=%d want %d", rootInSitemap, d.Run.SitemapURLsDiscovered, wantSitemap)
		}
		// Arithmetic invariant: internal-only + sitemap-only + both == discovered
		var internalOnly, sitemapOnly, both int
		for _, p := range d.Pages {
			switch p.Origin {
			case "internal":
				internalOnly++
			case "sitemap":
				sitemapOnly++
			case "both":
				both++
			}
		}
		if internalOnly+sitemapOnly+both != d.Run.PagesDiscovered {
			t.Fatalf("rootInSitemap=%v set partition %d+%d+%d != discovered %d", rootInSitemap, internalOnly, sitemapOnly, both, d.Run.PagesDiscovered)
		}
		if rootInSitemap && d.Run.SitemapURLsDiscovered != sitemapOnly+both {
			t.Fatalf("rootInSitemap=%v sitemap_urls=%d != sitemap-origin pages %d", rootInSitemap, d.Run.SitemapURLsDiscovered, sitemapOnly+both)
		}
	}
}

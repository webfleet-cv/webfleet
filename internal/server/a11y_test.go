package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/store"
)

// This suite drives the real embedded application in a headless browser and
// asserts deterministic keyboard/focus/announcement behavior for the primary
// workflows. The browser is pre-authenticated by injecting the session cookie
// (chromedp's fetch path is not relied upon for Set-Cookie), so the assertions
// exercise the actual dashboard and dialog code.

func a11yBrowser() string {
	for _, x := range []string{"chromium-browser", "chromium", "google-chrome", "google-chrome-stable"} {
		if p, e := exec.LookPath(x); e == nil {
			return p
		}
	}
	return ""
}

func a11yContext(t *testing.T) context.Context {
	t.Helper()
	// Browser integration tests are heavyweight and not race-relevant; they are
	// run explicitly with WEBFLEET_A11Y=1 (they time out under -race).
	if os.Getenv("WEBFLEET_A11Y") == "" || raceEnabled {
		t.Skip("set WEBFLEET_A11Y=1 to run browser accessibility tests")
	}
	bin := a11yBrowser()
	if bin == "" {
		t.Skip("no browser runtime installed")
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		chromedp.ExecPath(bin), chromedp.Headless, chromedp.DisableGPU, chromedp.NoFirstRun)
	ctx, cancelCtx := chromedp.NewContext(alloc)
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	t.Cleanup(func() { chromedp.Cancel(ctx); cancelTimeout(); cancelCtx(); cancelAlloc() })
	return ctx
}

func a11yServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	st, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := New(config.Config{DataDir: dir}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// a11ySetup performs setup over HTTP and injects the session cookie into the
// browser, then navigates so boot() shows the dashboard.
func a11ySetup(t *testing.T, ctx context.Context, srv *httptest.Server) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/api/setup", "application/json",
		bytes.NewBufferString(`{"username":"admin","email":"admin@example.com","password":"secret7"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("setup %d", resp.StatusCode)
	}
	var sessionCookie string
	for _, c := range resp.Cookies() {
		if c.Name == "webfleet_session" {
			sessionCookie = c.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("no session cookie from setup")
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, network.SetCookie("webfleet_session", sessionCookie).WithURL(srv.URL)); err != nil {
		t.Fatalf("inject cookie: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#dashboard`)); err != nil {
		t.Fatalf("dashboard did not appear with injected session: %v", err)
	}
}

func activeElementID(ctx context.Context) (string, error) {
	var id string
	err := chromedp.Run(ctx, chromedp.Evaluate(`document.activeElement && document.activeElement.id`, &id))
	return id, err
}

// TestA11yDialogInitialFocusAndReturn proves dialogs take initial focus on
// open, Escape closes them, and focus returns to the opening element.
func TestA11yDialogInitialFocusAndReturn(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	// The fleet view renders the add-site button.
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#site-dialog`)); err != nil {
		t.Fatal(err)
	}
	id, err := activeElementID(ctx)
	if err != nil || id != "site-name" {
		t.Fatalf("dialog initial focus = %q (want site-name), err=%v", id, err)
	}
	// Escape closes the dialog; native <dialog> returns focus to the opener.
	if err := chromedp.Run(ctx, chromedp.KeyEvent("\u001b")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	var open bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('site-dialog').open`, &open)); err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("dialog did not close on Escape")
	}
	id, err = activeElementID(ctx)
	if err != nil || id != "add-site-head" {
		t.Fatalf("focus after dialog close = %q (want add-site-head), err=%v", id, err)
	}
}

// TestA11yLoginErrorAnnounced proves failed login surfaces an announced error
// on the auth screen (role=alert).
// TestA11yFormErrorAnnounced proves the auth screen surfaces a validation
// error in a role=alert live region. Native HTML5 validation is stripped so
// the application's own error path is exercised deterministically.
func TestA11yFormErrorAnnounced(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	if err := chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		chromedp.WaitVisible(`#database-stage`),
		chromedp.Click(`#db-action`),
		chromedp.WaitVisible(`#auth-form`),
		chromedp.Evaluate(`document.getElementById('email').removeAttribute('required');document.getElementById('password').removeAttribute('required');document.getElementById('password').removeAttribute('minlength');true`, nil),
		chromedp.SetValue(`#email`, "admin@example.com"),
		chromedp.SetValue(`#password`, "x"),
		chromedp.Click(`#auth-submit`),
	); err != nil {
		t.Fatal(err)
	}
	var errText string
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := chromedp.Run(ctx, chromedp.Evaluate(`(document.getElementById('auth-error')||{}).textContent || ''`, &errText)); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(errText) != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("form error not announced within timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var role string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('auth-error').getAttribute('role')`, &role)); err != nil {
		t.Fatal(err)
	}
	if role != "alert" {
		t.Fatalf("auth-error role = %q, want alert", role)
	}
}
func TestA11yMobileNavToggle(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	if err := chromedp.Run(ctx, chromedp.EmulateViewport(375, 700)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#mobile-nav`)); err != nil {
		t.Fatal(err)
	}
	var expanded string
	var open bool
	var navLinks int
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`document.getElementById('mobile-nav').getAttribute('aria-expanded')`, &expanded),
		chromedp.Evaluate(`document.getElementById('primary-rail').classList.contains('mobile-open')`, &open),
		chromedp.Evaluate(`document.querySelectorAll('#primary-rail nav a').length`, &navLinks),
	); err != nil {
		t.Fatal(err)
	}
	if expanded != "true" || !open || navLinks == 0 {
		t.Fatalf("mobile nav expanded=%q open=%v links=%d", expanded, open, navLinks)
	}
}

// TestA11yKeyboardTabReachesControls proves the primary controls are reachable
// by keyboard traversal from the fleet view.
func TestA11yKeyboardTabReachesControls(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	// Tab forward several times; the add-site button must be reachable.
	reached := false
	for i := 0; i < 12; i++ {
		if err := chromedp.Run(ctx, chromedp.KeyEvent("\u0009")); err != nil { // TAB
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
		id, err := activeElementID(ctx)
		if err == nil && id == "add-site-head" {
			reached = true
			break
		}
	}
	if !reached {
		t.Fatal("add-site-head not reachable by keyboard tabbing")
	}
}

var _ = json.Marshal

// a11yAddSite creates a site over HTTP (admin cookie + CSRF) so the dashboard
// has a site to navigate to in the browser.
func a11yAddSite(t *testing.T, srv *httptest.Server) int64 {
	t.Helper()
	login := func() (cookie string, csrf string) {
		resp, err := http.Post(srv.URL+"/api/login", "application/json",
			bytes.NewBufferString(`{"email":"admin@example.com","password":"secret7"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		for _, c := range resp.Cookies() {
			if c.Name == "webfleet_session" {
				cookie = c.Value
			}
		}
		csrf, _ = body["csrf"].(string)
		return
	}
	cookie, csrf := login()
	req, _ := http.NewRequest("POST", srv.URL+"/api/sites", bytes.NewBufferString(`{"name":"S","primary_url":"https://example.com/"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "webfleet_session", Value: cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("create site %d", resp.StatusCode)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.ID
}

// TestA11yEditAndGroupDialogsFocus proves the edit-site and create-group
// dialogs take initial focus on the primary field.
func TestA11yEditAndGroupDialogsFocus(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	siteID := a11yAddSite(t, srv)
	if err := chromedp.Run(ctx, chromedp.Evaluate(fmt.Sprintf(`location.hash="#/sites/%d"`, siteID), nil)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#edit-site`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#edit-site`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#site-dialog`)); err != nil {
		t.Fatal(err)
	}
	id, err := activeElementID(ctx)
	if err != nil || id != "site-name" {
		t.Fatalf("edit dialog initial focus = %q (want site-name), err=%v", id, err)
	}
	if err := chromedp.Run(ctx, chromedp.KeyEvent("\u001b")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	// Create-group dialog from the fleet view (SPA hash navigation).
	if err := chromedp.Run(ctx, chromedp.Evaluate(`location.hash='#/sites'`, nil)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#site-dialog`)); err != nil {
		t.Fatal(err)
	}
	// Open the group dialog from within the site dialog.
	if err := chromedp.Run(ctx, chromedp.Click(`#new-group`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#group-dialog`)); err != nil {
		t.Fatal(err)
	}
	id, err = activeElementID(ctx)
	if err != nil || id != "group-name" {
		t.Fatalf("group dialog initial focus = %q (want group-name), err=%v", id, err)
	}
}

// TestA11yDialogFocusContainment proves Tab cycling keeps focus inside the
// open dialog (native <dialog> containment).
func TestA11yDialogFocusContainment(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#site-dialog`)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := chromedp.Run(ctx, chromedp.KeyEvent("\u0009")); err != nil { // TAB
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
		// The meaningful containment property: tabbing never reaches an
		// interactive control on the page behind the modal dialog.
		var behind bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(`(function(){var a=document.activeElement;return !document.getElementById('site-dialog').contains(a)&&(a.tagName==='A'||a.tagName==='BUTTON'||a.tagName==='INPUT'||a.tagName==='SELECT')})()`, &behind)); err != nil {
			t.Fatal(err)
		}
		if behind {
			t.Fatalf("tab %d reached a page-behind control", i)
		}
	}
	// A full cycle returns focus to the dialog's primary field.
	ok := false
	for i := 0; i < 10 && !ok; i++ {
		if err := chromedp.Run(ctx, chromedp.KeyEvent("\u0009")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
		id, _ := activeElementID(ctx)
		if id == "site-name" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("tabbing did not cycle back to the dialog primary field")
	}
}

// TestA11ySiteDetailLandmarksAndNav proves site-detail navigation, heading
// structure and the primary navigation are keyboard-reachable.
func TestA11ySiteDetailLandmarksAndNav(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	siteID := a11yAddSite(t, srv)
	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"#/sites/"+itoa(siteID))); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#view-title`)); err != nil {
		t.Fatal(err)
	}
	var h1, h2, navCount, mainCount int
	var viewTitle string
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`document.querySelectorAll('h1').length`, &h1),
		chromedp.Evaluate(`document.querySelectorAll('h2').length`, &h2),
		chromedp.Evaluate(`document.querySelectorAll('#primary-rail nav a').length`, &navCount),
		chromedp.Evaluate(`document.querySelectorAll('main').length`, &mainCount),
		chromedp.Evaluate(`document.getElementById('view-title').textContent`, &viewTitle),
	); err != nil {
		t.Fatal(err)
	}
	if h1 < 1 || h2 < 1 || navCount == 0 || mainCount < 1 {
		t.Fatalf("landmarks/headings h1=%d h2=%d nav=%d main=%d", h1, h2, navCount, mainCount)
	}
	// Primary navigation is keyboard-reachable from the site detail.
	reached := false
	for i := 0; i < 14; i++ {
		if err := chromedp.Run(ctx, chromedp.KeyEvent("\u0009")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
		var tag string
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.activeElement.tagName`, &tag))
		if tag == "A" {
			reached = true
			break
		}
	}
	if !reached {
		t.Fatal("no navigation link reachable by keyboard from site detail")
	}
	_ = viewTitle
}

// TestA11yMobileOverflowAndMenuKeyboard proves no horizontal overflow at a
// 320px viewport and the mobile menu toggles via keyboard and closes on Escape.
func TestA11yMobileOverflowAndMenuKeyboard(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	if err := chromedp.Run(ctx, chromedp.EmulateViewport(320, 700)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#dashboard`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	var scrollW, innerW int
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`document.documentElement.scrollWidth`, &scrollW),
		chromedp.Evaluate(`window.innerWidth`, &innerW),
	); err != nil {
		t.Fatal(err)
	}
	if scrollW > innerW {
		t.Fatalf("page-level horizontal overflow at 320px: scrollWidth=%d innerWidth=%d", scrollW, innerW)
	}
	// Open the mobile menu via keyboard (focus + Enter) and assert focus lands
	// on a navigation link.
	if err := chromedp.Run(ctx, chromedp.Focus(`#mobile-nav`)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.KeyEvent("\r")); err != nil { // Enter
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	var expanded string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('mobile-nav').getAttribute('aria-expanded')`, &expanded)); err != nil {
		t.Fatal(err)
	}
	if expanded != "true" {
		t.Fatalf("mobile nav not opened by keyboard: aria-expanded=%q", expanded)
	}
	// Escape closes it.
	if err := chromedp.Run(ctx, chromedp.KeyEvent("\u001b")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('mobile-nav').getAttribute('aria-expanded')`, &expanded)); err != nil {
		t.Fatal(err)
	}
	if expanded != "false" {
		t.Fatalf("mobile nav did not close on Escape: aria-expanded=%q", expanded)
	}
}

func itoa(n int64) string { return fmt.Sprintf("%d", n) }

// a11ySeedSites logs in once and creates n sites over HTTP so the fleet view
// reaches its populated large-fleet presentation (pagination at 20/page).
func a11ySeedSites(t *testing.T, srv *httptest.Server, n int) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/api/login", "application/json",
		bytes.NewBufferString(`{"email":"admin@example.com","password":"secret7"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == "webfleet_session" {
			cookie = c.Value
		}
	}
	csrf, _ := body["csrf"].(string)
	for i := 0; i < n; i++ {
		payload := fmt.Sprintf(`{"name":"Site %d","primary_url":"https://example.com/%d/"}`, i+1, i+1)
		req, _ := http.NewRequest("POST", srv.URL+"/api/sites", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: "webfleet_session", Value: cookie})
		r, err := http.DefaultClient.Do(req)
		if err != nil || r.StatusCode != 201 {
			t.Fatalf("seed site %d: %v %v", i+1, err, r)
		}
		r.Body.Close()
	}
}

// TestA11yLargeFleetOverflow proves the populated fleet table/pagination
// layout does not cause page-level horizontal overflow at desktop or narrow
// width, that the table container owns its own scrolling, that filter and
// pagination controls remain reachable/inside the viewport, and that
// pagination actually advances.
func TestA11yLargeFleetOverflow(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	a11ySetup(t, ctx, srv)
	a11ySeedSites(t, srv, 25)
	// Re-fetch the fleet view so the browser sees the seeded sites.
	if err := chromedp.Run(ctx, chromedp.Reload()); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`location.hash='#/sites'`, nil)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible(`#add-site-head`)); err != nil {
		t.Fatal(err)
	}
	var ready bool
	for i := 0; i < 20 && !ready; i++ {
		time.Sleep(50 * time.Millisecond)
		var r int
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.querySelectorAll('.site-table tbody tr').length`, &r))
		ready = r == 20
	}
	if !ready {
		var hash, view string
		_ = chromedp.Run(ctx, chromedp.Evaluate(`location.hash`, &hash))
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('view').textContent.slice(0,120)`, &view))
		t.Fatalf("fleet table did not render 20 populated rows after reload (hash=%q view=%q)", hash, view)
	}

	assertLayout := func(viewportW int) {
		var scrollW, innerW, addBtnRight, addBtnLeft float64
		var searchVisible, nextVisible, prevVisible bool
		var tableRows int
		var tableW, sectionClientW float64
		if err := chromedp.Run(ctx,
			chromedp.Evaluate(`document.documentElement.scrollWidth`, &scrollW),
			chromedp.Evaluate(`window.innerWidth`, &innerW),
			chromedp.Evaluate(`document.querySelector('#add-site-head').getBoundingClientRect().right`, &addBtnRight),
			chromedp.Evaluate(`document.querySelector('#add-site-head').getBoundingClientRect().left`, &addBtnLeft),
			chromedp.Evaluate(`!!document.querySelector('#site-search') && document.querySelector('#site-search').offsetParent!==null`, &searchVisible),
			chromedp.Evaluate(`!!document.querySelector('#next-page') && !document.querySelector('#next-page').disabled`, &nextVisible),
			chromedp.Evaluate(`document.querySelector('#prev-page')!==null && document.querySelector('#prev-page').disabled`, &prevVisible),
			chromedp.Evaluate(`document.querySelectorAll('.site-table tbody tr').length`, &tableRows),
			chromedp.Evaluate(`document.querySelector('.site-table').scrollWidth`, &tableW),
			chromedp.Evaluate(`document.querySelector('.site-table').closest('.section').clientWidth`, &sectionClientW),
		); err != nil {
			t.Fatal(err)
		}
		if scrollW > innerW {
			t.Fatalf("page-level horizontal overflow at %dpx: scrollWidth=%.0f innerWidth=%.0f", viewportW, scrollW, innerW)
		}
		if addBtnLeft < 0 || addBtnRight > innerW {
			t.Fatalf("primary add control outside viewport at %dpx: left=%.0f right=%.0f inner=%.0f", viewportW, addBtnLeft, addBtnRight, innerW)
		}
		if !searchVisible || !nextVisible || !prevVisible {
			t.Fatalf("filter/pagination controls not reachable at %dpx (search=%v next=%v prev=%v)", viewportW, searchVisible, nextVisible, prevVisible)
		}
		if tableRows != 20 {
			t.Fatalf("expected 20 rows per populated page at %dpx, got %d", viewportW, tableRows)
		}
		if tableW > sectionClientW {
			// The table container owns its own horizontal scrolling; the page
			// itself must still not overflow.
			t.Logf("table internally scrollable at %dpx: tableW=%.0f container=%.0f", viewportW, tableW, sectionClientW)
		}
	}

	assertLayout(1280)

	// Pagination advances to page 2.
	if err := chromedp.Run(ctx, chromedp.Click(`#next-page`)); err != nil {
		t.Fatal(err)
	}
	var pageNum, rows2 int
	ok := false
	for i := 0; i < 20 && !ok; i++ {
		time.Sleep(50 * time.Millisecond)
		_ = chromedp.Run(ctx, chromedp.Evaluate(`parseInt(document.getElementById("page-number").value)`, &pageNum))
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.querySelectorAll('.site-table tbody tr').length`, &rows2))
		ok = pageNum == 2 && rows2 == 5
	}
	if !ok {
		t.Fatalf("pagination did not advance correctly: page=%d rows=%d", pageNum, rows2)
	}

	// Narrow width: return to page 1 and assert the populated table does not
	// overflow the page.
	if err := chromedp.Run(ctx, chromedp.Click(`#prev-page`)); err != nil {
		t.Fatal(err)
	}
	back := false
	for i := 0; i < 20 && !back; i++ {
		time.Sleep(50 * time.Millisecond)
		_ = chromedp.Run(ctx, chromedp.Evaluate(`parseInt(document.getElementById("page-number").value)`, &pageNum))
		back = pageNum == 1
	}
	if err := chromedp.Run(ctx, chromedp.EmulateViewport(320, 700)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	rendered := false
	for i := 0; i < 20 && !rendered; i++ {
		time.Sleep(50 * time.Millisecond)
		var r int
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.querySelectorAll('.site-table tbody tr').length`, &r))
		rendered = r == 20
	}
	if !rendered {
		t.Fatal("fleet table did not render 20 populated rows at 320px")
	}
	assertLayout(320)
}

// TestA11yBrowserAuthFlow proves an ordinary browser can complete the
// first-admin setup form, reach the dashboard, log out, and log back in
// through the browser login form - no cookie injection involved.
func a11yPoll(t *testing.T, ctx context.Context, expr string) bool {
	t.Helper()
	for i := 0; i < 40; i++ {
		var v bool
		if chromedp.Run(ctx, chromedp.Evaluate(expr, &v)) == nil && v {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestA11yBrowserAuthFlow(t *testing.T) {
	ctx := a11yContext(t)
	srv := a11yServer(t)
	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL)); err != nil {
		t.Fatal(err)
	}
	// Fresh instance: the two-stage flow shows the database stage first, then
	// the administrator stage after the SQLite decision is committed.
	if !a11yPoll(t, ctx, `document.getElementById('auth-title').textContent === 'Choose your database'`) {
		t.Fatal("database stage did not render")
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#db-action`)); err != nil {
		t.Fatal(err)
	}
	if !a11yPoll(t, ctx, `document.getElementById('auth-form').dataset.mode === 'setup' && !document.getElementById('auth-form').hidden`) {
		var dberr, dbHidden, actionLabel string
		_ = chromedp.Run(ctx, chromedp.Evaluate(`(document.getElementById('db-error')||{}).textContent||''`, &dberr))
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('database-stage').hidden`, &dbHidden))
		_ = chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById('db-action').textContent`, &actionLabel))
		t.Fatalf("fresh instance did not reach the administrator form in setup mode (db-error=%q dbHidden=%v action=%q)", dberr, dbHidden, actionLabel)
	}
	// Complete first-admin setup through the browser.
	if err := chromedp.Run(ctx,
		chromedp.SendKeys(`#email`, "admin@example.com"),
		chromedp.SendKeys(`#password`, "secret7"),
	); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#auth-submit`)); err != nil {
		t.Fatal(err)
	}
	if !a11yPoll(t, ctx, `document.getElementById('auth-stage').hidden === true`) {
		t.Fatal("auth stage still visible after successful setup")
	}
	// Log out via the browser control; the login form appears.
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(function(){document.getElementById('logout').click();return true})()`, nil)); err != nil {
		t.Fatal(err)
	}
	if !a11yPoll(t, ctx, `document.getElementById('auth-stage').hidden === false`) {
		t.Fatal("auth stage did not reappear after logout")
	}
	if !a11yPoll(t, ctx, `document.getElementById('auth-form').dataset.mode === 'login' && !document.getElementById('auth-form').hidden`) {
		t.Fatal("post-logout auth form did not reach login mode")
	}
	// Log back in through the browser login form.
	if err := chromedp.Run(ctx,
		chromedp.SendKeys(`#email`, "admin@example.com"),
		chromedp.SendKeys(`#password`, "secret7"),
		chromedp.Click(`#auth-submit`),
	); err != nil {
		t.Fatal(err)
	}
	if !a11yPoll(t, ctx, `document.getElementById('auth-stage').hidden === true`) {
		t.Fatal("auth stage still visible after successful login")
	}
	if !a11yPoll(t, ctx, `!!document.getElementById('add-site-head')`) {
		t.Fatal("dashboard fleet view did not render after login")
	}
}

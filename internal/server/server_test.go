package server

import (
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthAndEmbeddedDashboard(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	s := New(config.Config{Listen: "127.0.0.1:0"}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("health: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/app/", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "WEB FLEET") {
		t.Fatalf("dashboard: %d", rr.Code)
	}
}

func TestLauncherConfigRequiresAuthenticationWithoutRenderingControls(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(config.Config{Listen: "127.0.0.1:0"}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/?config", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Authentication required") || strings.Contains(w.Body.String(), "Current instances") {
		t.Fatalf("config denial: %d %q", w.Code, w.Body.String())
	}
}

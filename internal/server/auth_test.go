package server

import (
	"bytes"
	"encoding/json"
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthAndCSRF(t *testing.T) {
	st, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	s := New(config.Config{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest("POST", "/api/setup", bytes.NewBufferString(`{"username":"a","email":"a@example.com","password":"secret7"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("setup %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	csrf, _ := body["csrf"].(string)
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "webfleet_session" {
			cookie = c
		}
	}
	if cookie == nil || csrf == "" {
		t.Fatal("missing session/csrf")
	}
	req = httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("missing csrf got %d", rr.Code)
	}
	req = httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("logout got %d %s", rr.Code, rr.Body.String())
	}
}

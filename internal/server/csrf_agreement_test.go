package server

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCSRFHeaderAgreementAcrossSurfaces is a regression test for a
// dogfooding-discovered defect: the CLI automation and the admin manage UI sent
// "X-Webfleet-CSRF" while the server only validated "X-CSRF-Token", so no CLI or
// admin mutation could ever pass CSRF. Every CSRF-sending surface must use the
// server's CSRFHeader.
func TestCSRFHeaderAgreementAcrossSurfaces(t *testing.T) {
	if CSRFHeader != "X-CSRF-Token" {
		t.Fatalf("server CSRFHeader changed to %q; update this test and all consumers", CSRFHeader)
	}
	// The embedded admin manage UI must send the server's header, not a stale one.
	embeddedFile, err := embedded.Open("web/manage.js")
	if err != nil {
		t.Fatalf("open embedded manage.js: %v", err)
	}
	embeddedBytes, err := io.ReadAll(embeddedFile)
	embeddedFile.Close()
	if err != nil {
		t.Fatalf("read embedded manage.js: %v", err)
	}
	for _, bad := range []string{"X-Webfleet-CSRF"} {
		if strings.Contains(string(embeddedBytes), bad) {
			t.Fatalf("embedded manage.js still sends %q; must send %q", bad, CSRFHeader)
		}
	}
	if !strings.Contains(string(embeddedBytes), CSRFHeader) {
		t.Fatalf("embedded manage.js does not send the server header %q", CSRFHeader)
	}
	// The non-embedded public copy must stay in sync with the embedded source.
	public, err := os.ReadFile(filepath.Join("..", "..", "public", "manage.js"))
	if err != nil {
		t.Fatalf("read public/manage.js: %v", err)
	}
	if string(public) != string(embeddedBytes) {
		t.Fatalf("public/manage.js is out of sync with the embedded web/manage.js")
	}
}

// TestApplicationNavigationHasNoCrossSiteLink is a regression test for a
// dogfooding-discovered defect: a request to add Gantry to the public-facing
// websites leaked a hard-coded https://gantry.cv link into the authenticated
// application navigation. The application menu must only carry application
// routes, never unsolicited cross-site branding.
func TestApplicationNavigationHasNoCrossSiteLink(t *testing.T) {
	f, err := embedded.Open("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "gantry.cv") {
		t.Fatal("application frontend contains a hard-coded gantry.cv cross-site link; remove it from the Nift source and regenerate")
	}
}

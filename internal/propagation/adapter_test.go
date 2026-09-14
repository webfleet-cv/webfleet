package propagation

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/webfleet-cv/webfleet/internal/store"
)

func openPropagationStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPropagationBootstrapsSiteWithMonitorsOnFreshMember(t *testing.T) {
	ctx := context.Background()
	src := openPropagationStore(t)
	dst := openPropagationStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := src.DB.Exec(`INSERT INTO sites(id,organization_id,name,primary_url,enabled,created_at,updated_at) VALUES(7,1,'New Site','https://new.example',1,?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := src.DB.Exec(`INSERT INTO monitors(id,site_id,kind,timeout_ms,expected_min,expected_max,created_at) VALUES(10,7,'http',10000,200,399,?)`, now); err != nil {
		t.Fatal(err)
	}

	source := New(src)
	env, err := source.Export(ctx, nil, core.Actor{Kind: "user", ID: "1", Permission: "sites.update"}, "members")
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 2 {
		t.Fatalf("expected site + monitor, got %d envelopes", len(env))
	}
	// Request definitions must precede the monitors that depend on them so the
	// foreign key is satisfied on a fresh destination.
	if env[0].Kind != "request-definition" || env[1].Kind != "monitor-definition" {
		t.Fatalf("bundle order %q, %q; request-definition must come first", env[0].Kind, env[1].Kind)
	}

	destination := New(dst)
	preview, err := core.PreviewLocal(ctx, destination, env, core.Actor{Kind: "user", ID: "1", Permission: "sites.update"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Applicable {
		t.Fatalf("bootstrap preview must be applicable, issues: %#v", preview.Issues)
	}
	if _, err = core.ApplyLocal(ctx, destination, env, core.Actor{Kind: "user", ID: "1", Permission: "sites.update"}); err != nil {
		t.Fatalf("bootstrap apply must succeed: %v", err)
	}
	var sites, monitors int
	if err = dst.DB.QueryRow(`SELECT COUNT(*) FROM sites WHERE id=7`).Scan(&sites); err != nil || sites != 1 {
		t.Fatalf("site not created: sites=%d err=%v", sites, err)
	}
	if err = dst.DB.QueryRow(`SELECT COUNT(*) FROM monitors WHERE id=10 AND site_id=7`).Scan(&monitors); err != nil || monitors != 1 {
		t.Fatalf("monitor not created: monitors=%d err=%v", monitors, err)
	}
}

func TestPropagationBlocksMonitorWithMissingSite(t *testing.T) {
	ctx := context.Background()
	src := openPropagationStore(t)
	dst := openPropagationStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := src.DB.Exec(`INSERT INTO sites(id,organization_id,name,primary_url,enabled,created_at,updated_at) VALUES(7,1,'New Site','https://new.example',1,?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := src.DB.Exec(`INSERT INTO monitors(id,site_id,kind,timeout_ms,expected_min,expected_max,created_at) VALUES(10,7,'http',10000,200,399,?)`, now); err != nil {
		t.Fatal(err)
	}

	source := New(src)
	env, err := source.Export(ctx, nil, core.Actor{Kind: "user", ID: "1", Permission: "sites.update"}, "members")
	if err != nil {
		t.Fatal(err)
	}
	// Drop the request-definition so the monitor's site is genuinely absent
	// from both the bundle and the destination: the preview must fail closed.
	var withoutSite []core.Envelope
	for _, e := range env {
		if e.Kind == "request-definition" {
			continue
		}
		withoutSite = append(withoutSite, e)
	}
	destination := New(dst)
	preview, err := core.PreviewLocal(ctx, destination, withoutSite, core.Actor{Kind: "user", ID: "1", Permission: "sites.update"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Applicable {
		t.Fatal("monitor referencing an absent site must be blocked")
	}
	found := false
	for _, issue := range preview.Issues {
		if issue.Kind == core.IssueMissingDependency && issue.Detail == "site:"+strconv.FormatInt(7, 10) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing-dependency site:7 issue, got %#v", preview.Issues)
	}
}

package feed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
)

const csafVexBody = `{
  "document": {"tracking": {"id": "VEX-1", "current_release_date": "2024-01-15T00:00:00Z"}},
  "product_tree": {"branches": [
    {"category": "product_name", "name": "openssl",
     "product": {"product_id": "openssl", "product_identification_helper": {"purl": "pkg:rpm/redhat/openssl"}}}
  ]},
  "vulnerabilities": [{"cve": "CVE-2024-1", "product_status": {"known_not_affected": ["openssl"]}}]
}`

func csafServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func TestCSAFVexClient_FetchesPerCVEAndFolds(t *testing.T) {
	srv, paths := csafServer(t, http.StatusOK, csafVexBody)
	got, err := feed.NewCSAFVexClient([]string{srv.URL + "/csaf/vex"}, srv.Client()).FetchCVE(context.Background(), "CVE-2024-1")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("proposals = %d, want 1", len(got))
	}
	a, ok := got[0].Proposal.Applicability()
	if !ok || a.Status != "not_affected" || a.Package != "openssl" {
		t.Errorf("applicability = %+v ok=%v", a, ok)
	}
	// URL follows the CSAF per-CVE convention: <base>/<year>/cve-<id>.json (lowercased).
	if len(*paths) != 1 || (*paths)[0] != "/csaf/vex/2024/cve-2024-1.json" {
		t.Errorf("requested paths = %v, want [/csaf/vex/2024/cve-2024-1.json]", *paths)
	}
}

func TestCSAFVexClient_NotFoundIsNoCoverage(t *testing.T) {
	srv, _ := csafServer(t, http.StatusNotFound, "")
	got, err := feed.NewCSAFVexClient([]string{srv.URL}, srv.Client()).FetchCVE(context.Background(), "CVE-2024-9")
	if err != nil || got != nil {
		t.Fatalf("404: got (%v,%v), want (nil,nil)", got, err)
	}
}

func TestCSAFVexClient_AllBasesErrorPropagates(t *testing.T) {
	srv, _ := csafServer(t, http.StatusInternalServerError, "")
	if _, err := feed.NewCSAFVexClient([]string{srv.URL}, srv.Client()).FetchCVE(context.Background(), "CVE-2024-1"); err == nil {
		t.Error("every base erroring must propagate so the sweep skips the CVE")
	}
}

func TestCSAFVexClient_OneBaseDownOthersServe(t *testing.T) {
	down, _ := csafServer(t, http.StatusInternalServerError, "")
	up, _ := csafServer(t, http.StatusOK, csafVexBody)
	// The first base errors, the second serves — the errored base is tried past, not fatal.
	got, err := feed.NewCSAFVexClient([]string{down.URL, up.URL}, up.Client()).FetchCVE(context.Background(), "CVE-2024-1")
	if err != nil {
		t.Fatalf("a reachable base must succeed despite another erroring: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("proposals = %d, want 1 (from the reachable base)", len(got))
	}
}

func TestCSAFVexClient_InvalidCVEArgSkipped(t *testing.T) {
	// An unparseable CVE returns before any request; also exercises the nil-http default and the
	// blank base-URL drop.
	got, err := feed.NewCSAFVexClient([]string{"", "  "}, nil).FetchCVE(context.Background(), "not-a-cve")
	if err != nil || got != nil {
		t.Fatalf("invalid cve: got (%v,%v), want (nil,nil)", got, err)
	}
}

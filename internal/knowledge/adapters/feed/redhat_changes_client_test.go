package feed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
)

func changesServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRedHatChangesClient_FiltersBySinceAndNormalizes(t *testing.T) {
	// The live row shape verified 2026-08-27: "<year>/cve-<id>.json","RFC3339".
	srv := changesServer(t, http.StatusOK,
		`"2026/cve-2026-21441.json","2026-08-27T13:05:47+00:00"`+"\n"+
			`"2025/cve-2025-66418.json","2026-08-01T00:00:00+00:00"`+"\n"+
			`"2026/not-a-cve.json","2026-08-27T13:05:47+00:00"`+"\n")
	c := feed.NewRedHatChangesClient(srv.URL, nil)

	since := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	changed, ok := c.ChangedSince(context.Background(), since)
	if !ok {
		t.Fatal("expected ok=true for a well-formed CSV")
	}
	if _, hit := changed["CVE-2026-21441"]; !hit {
		t.Errorf("row after since must be reported, canonicalized: got %v", changed)
	}
	if _, hit := changed["CVE-2025-66418"]; hit {
		t.Error("row before since must not be reported")
	}
	if len(changed) != 1 {
		t.Errorf("non-CVE paths must be skipped: got %v", changed)
	}
}

func TestRedHatChangesClient_FailsOpenOnEveryBadShape(t *testing.T) {
	ctx := context.Background()
	since := time.Unix(0, 0)

	// Non-200 wearing a body.
	if _, ok := feed.NewRedHatChangesClient(changesServer(t, http.StatusServiceUnavailable, "x").URL, nil).ChangedSince(ctx, since); ok {
		t.Error("non-200 must answer ok=false")
	}
	// A 200 whose body yields not a single valid row is a malformed file, not an empty window.
	if _, ok := feed.NewRedHatChangesClient(changesServer(t, http.StatusOK, "not,a,timestamp\nrows,either\n").URL, nil).ChangedSince(ctx, since); ok {
		t.Error("zero valid rows must answer ok=false")
	}
	// A CSV-level parse error mid-file (bare quote) means the file shape changed under us.
	if _, ok := feed.NewRedHatChangesClient(changesServer(t, http.StatusOK, `"2026/cve-2026-1.json","2026-08-27T13:05:47+00:00"`+"\n"+`"broken`+"\n").URL, nil).ChangedSince(ctx, since); ok {
		t.Error("a CSV parse error must answer ok=false")
	}
	// An unreachable server.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	if _, ok := feed.NewRedHatChangesClient(dead.URL, nil).ChangedSince(ctx, since); ok {
		t.Error("a transport error must answer ok=false")
	}
}

// Rows at exactly the watermark are NOT "after since" — the next completed sweep's watermark
// advances past them, so an equal timestamp must not re-trigger forever.
func TestRedHatChangesClient_EqualTimestampIsUnchanged(t *testing.T) {
	ts := "2026-08-27T13:05:47+00:00"
	srv := changesServer(t, http.StatusOK, `"2026/cve-2026-21441.json","`+ts+`"`+"\n")
	since, _ := time.Parse(time.RFC3339, ts)
	changed, ok := feed.NewRedHatChangesClient(srv.URL, nil).ChangedSince(context.Background(), since)
	if !ok || len(changed) != 0 {
		t.Fatalf("equal-timestamp row must count as unchanged: ok=%v changed=%v", ok, changed)
	}
}

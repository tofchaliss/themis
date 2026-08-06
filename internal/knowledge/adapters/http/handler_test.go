package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeRepo struct {
	card  domain.Faultline
	found bool
	err   error
}

func (r fakeRepo) GetByCVE(_ context.Context, cve string) (domain.Faultline, bool, error) {
	if r.err != nil {
		return domain.Faultline{}, false, r.err
	}
	if r.found && r.card.CVE().String() == cve {
		return r.card, true, nil
	}
	return domain.Faultline{}, false, nil
}

func (r fakeRepo) GetByID(_ context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	if r.err != nil {
		return domain.Faultline{}, r.err
	}
	if r.found && r.card.ID() == id {
		return r.card, nil
	}
	return domain.Faultline{}, store.ErrNotFound
}

func (r fakeRepo) Save(context.Context, domain.Faultline, bool, int, []app.OutboxNote) error {
	return nil
}

type fakeProjection struct {
	releases []string
	err      error
}

func (f fakeProjection) AffectedReleases(context.Context, string) ([]string, error) {
	return f.releases, f.err
}

func sampleCard(t *testing.T) domain.Faultline {
	t.Helper()
	cve, _ := value.NewCVEID("CVE-2024-1")
	f, _ := domain.NewFaultline("fl-1", cve)
	c, _ := value.NewCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	p, _ := domain.NewVulnFactsProposal("nvd", time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: []string{"<3.0"}})
	f.FoldProposal(p, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	return f
}

func server(t *testing.T, repo app.Repository, proj app.ProjectionReader) *httptest.Server {
	t.Helper()
	return feedServer(t, repo, proj, fakeFeedStore{})
}

// feedServer serves the full handler backed by a specific feed-health store (for GET /feeds).
func feedServer(t *testing.T, repo app.Repository, proj app.ProjectionReader, feeds app.FeedHealthStore) *httptest.Server {
	t.Helper()
	health := app.NewFeedHealthService(feeds, feedClock{})
	srv := httptest.NewServer(knhttp.NewHandler(app.NewReadService(repo, proj), health).Router())
	t.Cleanup(srv.Close)
	return srv
}

type feedClock struct{}

func (feedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type fakeFeedStore struct {
	rows []app.FeedHealthRow
	err  error
}

func (fakeFeedStore) RecordFeedSuccess(context.Context, string, int, time.Time) error { return nil }
func (fakeFeedStore) RecordFeedFailure(context.Context, string, int, time.Time) error { return nil }
func (f fakeFeedStore) FeedHealthRows(context.Context) ([]app.FeedHealthRow, error) {
	return f.rows, f.err
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [4096]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}

func TestGetFaultlineById(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})

	status, body := get(t, srv.URL+"/faultlines/fl-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var v struct {
		Cve, Stage string
		View       struct {
			Severity  string  `json:"severity"`
			CvssScore float32 `json:"cvss_score"`
		}
		Proposals []map[string]any
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Cve != "CVE-2024-1" || v.Stage != "enriched" || v.View.Severity != "high" || v.View.CvssScore != 7.5 {
		t.Errorf("view = %+v", v)
	}
	if len(v.Proposals) != 1 {
		t.Errorf("proposals = %d, want 1", len(v.Proposals))
	}

	// Unknown id → 404.
	if status, _ := get(t, srv.URL+"/faultlines/nope"); status != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", status)
	}
}

func TestGetFaultlineByCVE(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})
	if status, _ := get(t, srv.URL+"/faultlines?cve=CVE-2024-1"); status != http.StatusOK {
		t.Errorf("by-cve status = %d, want 200", status)
	}
	// Unknown CVE → 404.
	srv2 := server(t, fakeRepo{found: false}, fakeProjection{})
	if status, _ := get(t, srv2.URL+"/faultlines?cve=CVE-9999-9"); status != http.StatusNotFound {
		t.Errorf("unknown cve status = %d, want 404", status)
	}
}

func TestGetFaultlineReleases(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{releases: []string{"rel-1", "rel-2"}})
	status, body := get(t, srv.URL+"/faultlines/fl-1/releases")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	var rels []string
	if err := json.Unmarshal(body, &rels); err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 {
		t.Errorf("releases = %v, want 2", rels)
	}
}

func TestReadErrors(t *testing.T) {
	boom := errors.New("db down")
	srv := server(t, fakeRepo{err: boom}, fakeProjection{err: boom})
	for _, path := range []string{"/faultlines/fl-1", "/faultlines?cve=CVE-2024-1", "/faultlines/fl-1/releases"} {
		if status, _ := get(t, srv.URL+path); status != http.StatusInternalServerError {
			t.Errorf("%s status = %d, want 500", path, status)
		}
	}
}

func TestGetFeedHealth(t *testing.T) {
	recent := feedClock{}.Now().Add(-1 * time.Hour) // within every tier threshold
	feeds := fakeFeedStore{rows: []app.FeedHealthRow{
		{Source: "nvd", Tier: 1, LastSuccessAt: &recent, ConsecutiveFailures: 0}, // healthy
		{Source: "osv", Tier: 2, LastSuccessAt: &recent, ConsecutiveFailures: 3}, // Tier-2 failing → degraded
	}}
	srv := feedServer(t, fakeRepo{}, fakeProjection{}, feeds)

	status, body := get(t, srv.URL+"/feeds")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	var rep struct {
		SignalsStale  bool     `json:"signals_stale"`
		DegradedFeeds []string `json:"degraded_feeds"`
		Feeds         []struct {
			Source string `json:"source"`
			Status string `json:"status"`
			Tier   int    `json:"tier"`
		} `json:"feeds"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if rep.SignalsStale {
		t.Errorf("signals_stale = true, want false (no Tier-1 stale)")
	}
	if len(rep.Feeds) != 2 {
		t.Fatalf("feeds = %d, want 2", len(rep.Feeds))
	}
	if len(rep.DegradedFeeds) != 1 || rep.DegradedFeeds[0] != "osv" {
		t.Errorf("degraded_feeds = %v, want [osv]", rep.DegradedFeeds)
	}
}

func TestGetFeedHealthError(t *testing.T) {
	srv := feedServer(t, fakeRepo{}, fakeProjection{}, fakeFeedStore{err: errors.New("db down")})
	if status, _ := get(t, srv.URL+"/feeds"); status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
}

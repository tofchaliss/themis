package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/app"
)

type psirtEstate struct{}

func (psirtEstate) ReleaseProducts(context.Context) (map[string]app.ProductRef, error) {
	return map[string]app.ProductRef{"r1": {ID: "p1", Name: "product-a"}}, nil
}

type psirtSBOMs struct{}

func (psirtSBOMs) SBOMForRelease(context.Context, string) (string, bool, error) { return "e1", true, nil }

type psirtInv struct{}

func (psirtInv) GetInventory(context.Context, string) (app.Inventory, error) {
	return app.Inventory{Components: []app.InventoryComponent{{Name: "libfoo"}}}, nil
}

func psirtServer(t *testing.T, src app.PublishedSource, wirePSIRT bool) *httptest.Server {
	t.Helper()
	repo := fakeRepo{card: sampleCard(t), found: true}
	h := knhttp.NewHandler(app.NewReadService(repo, fakeProjection{}), app.NewFeedHealthService(fakeFeedStore{}, feedClock{}))
	if src != nil {
		pub := app.NewPublishedService(src, repo, feedClock{})
		h = h.WithPublished(pub)
		if wirePSIRT {
			h = h.WithPSIRT(app.NewPSIRTService(pub, psirtEstate{}, psirtSBOMs{}, psirtInv{}, nil, feedClock{}))
		}
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv
}

// EDR-PSIRT-01 P2: the alert answers original score + rating, the CWE word, the matched
// components, never a Themis score; it validates the floor, caches a repeat, and answers 503 /
// 502 like the world read it is built on.
func TestGetPSIRTAlerts(t *testing.T) {
	src := &fakePublishedSrc{rows: []app.PublishedCVE{
		{CVE: "CVE-2026-1", Published: time.Unix(1_700_000_000, 0).UTC(), Summary: "flaw", Severity: "critical", Score: 9.8,
			Modified: time.Unix(1_700_100_000, 0).UTC(), Weaknesses: []string{"CWE-78"}, Affected: []string{"libfoo"}},
		{CVE: "CVE-2026-2", Published: time.Unix(1_700_000_000, 0).UTC(), Severity: "high", Score: 7.5},
		{CVE: "CVE-2026-3", Published: time.Unix(1_700_000_000, 0).UTC(), Severity: "medium", Score: 5.0},
	}}
	srv := psirtServer(t, src, true)
	status, body := get(t, srv.URL+"/psirt/alerts?days=99")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var out struct {
		Alerts []struct {
			Cve              string     `json:"cve"`
			OriginalScore    float64    `json:"original_score"`
			OriginalSeverity string     `json:"original_severity"`
			ScoreSource      string     `json:"score_source"`
			IssueType        *string    `json:"issue_type"`
			Modified         *time.Time `json:"modified"`
			Summary          *string    `json:"summary"`
			Affected         []string   `json:"affected_products"`
			Matches          []struct {
				ProductName string `json:"product_name"`
				Component   string `json:"component"`
			} `json:"matches"`
			ExpertScore *float64 `json:"expert_score"`
		} `json:"alerts"`
		EstateUnavailable bool   `json:"estate_unavailable"`
		Table             string `json:"issue_type_table"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Alerts) != 2 || out.EstateUnavailable || out.Table == "" {
		t.Fatalf("out = %+v", out)
	}
	a := out.Alerts[0]
	if a.Cve != "CVE-2026-1" || a.OriginalScore < 9.79 || a.OriginalSeverity != "critical" || a.ScoreSource != "nvd" ||
		a.IssueType == nil || *a.IssueType != "Code execution" || a.Modified == nil || a.Summary == nil ||
		len(a.Affected) != 1 || len(a.Matches) != 1 || a.Matches[0].Component != "libfoo" || a.ExpertScore != nil {
		t.Errorf("first = %+v", a)
	}
	if b := out.Alerts[1]; b.IssueType != nil || b.Modified != nil || b.Matches == nil || len(b.Matches) != 0 {
		t.Errorf("a row stating nothing carries nothing, and matches is [] not null: %+v", b)
	}
	if s, _ := get(t, srv.URL+"/psirt/alerts?days=99"); s != http.StatusOK || src.calls != 1 {
		t.Errorf("cached repeat: status %d, source calls %d", s, src.calls)
	}
	if s, b := get(t, srv.URL+"/psirt/alerts?min_severity=medium"); s != http.StatusOK || len(b) == 0 || src.calls != 2 {
		t.Errorf("medium floor: status %d, calls %d", s, src.calls)
	}
	if s, _ := get(t, srv.URL+"/psirt/alerts?min_severity="); s != http.StatusOK {
		t.Errorf("empty floor = %d", s)
	}
	if s, _ := get(t, srv.URL+"/psirt/alerts?min_severity=urgent"); s != http.StatusBadRequest {
		t.Errorf("bad floor = %d, want 400", s)
	}
	if s, _ := get(t, psirtServer(t, &fakePublishedSrc{err: errors.New("nvd down")}, true).URL+"/psirt/alerts"); s != http.StatusBadGateway {
		t.Errorf("world down = %d, want 502", s)
	}
	if s, _ := get(t, psirtServer(t, src, false).URL+"/psirt/alerts"); s != http.StatusServiceUnavailable {
		t.Errorf("not wired = %d, want 503", s)
	}
	if s, _ := get(t, psirtServer(t, nil, false).URL+"/psirt/alerts"); s != http.StatusServiceUnavailable {
		t.Errorf("no source = %d, want 503", s)
	}
}

package http_test

// POST /faultlines/gather (G-AI-1): the on-demand per-CVE fetch's HTTP face.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type gatherHTTPSrc struct{ facts app.CVEFacts }

func (g gatherHTTPSrc) VulnsForCVE(context.Context, value.CVEID) (app.CVEFacts, error) {
	return g.facts, nil
}

// gatherRepo is a minimal in-memory Repository for the fold the gather drives (the shared
// fakeRepo above is read-only by design).
type gatherRepo struct{ cards map[string]domain.Faultline }

func (r *gatherRepo) GetByCVE(_ context.Context, cve string) (domain.Faultline, bool, error) {
	f, ok := r.cards[cve]
	return f, ok, nil
}
func (r *gatherRepo) GetByID(_ context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	for _, f := range r.cards {
		if f.ID() == id {
			return f, nil
		}
	}
	return domain.Faultline{}, nil
}
func (r *gatherRepo) Save(_ context.Context, f domain.Faultline, _ bool, _ int, _ []app.OutboxNote) error {
	r.cards[f.CVE().String()] = f
	return nil
}

type gatherIDs struct{ n int }

func (g *gatherIDs) NewID() string { g.n++; return "fl-gathered" }

type gatherClock struct{}

func (gatherClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func gatherServer(t *testing.T, gather *app.GatherService) *httptest.Server {
	t.Helper()
	health := app.NewFeedHealthService(fakeFeedStore{}, feedClock{})
	h := knhttp.NewHandler(app.NewReadService(fakeRepo{}, fakeProjection{}), health)
	if gather != nil {
		h = h.WithGather(gather)
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv
}

func TestGatherEndpoint(t *testing.T) {
	repo := &gatherRepo{cards: map[string]domain.Faultline{}}
	fold := app.NewFaultlineService(repo, &gatherIDs{}, gatherClock{}, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	cve, _ := value.NewCVEID("CVE-2026-0001")
	cvss, _ := value.NewCVSS(9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	prop, _ := domain.NewVulnFactsProposal("nvd", gatherClock{}.Now(),
		domain.VulnFacts{Severity: value.SeverityCritical, CVSS: cvss, AffectedRanges: []string{"<2.0"}})
	facts := app.CVEFacts{Found: true, Proposal: app.ProposalFor{CVE: cve, Proposal: prop}}
	srv := gatherServer(t, app.NewGatherService(fold, app.GatherSource{Name: "nvd", Src: gatherHTTPSrc{facts: facts}}))

	code, body := post(t, srv.URL+"/faultlines/gather", `{"cve":"CVE-2026-0001"}`)
	if code != http.StatusOK || !strings.Contains(body, `"recorded":true`) || !strings.Contains(body, `"faultline_id"`) {
		t.Fatalf("gather = %d %s", code, body)
	}

	if code, body = post(t, srv.URL+"/faultlines/gather", `{"cve":"nope"}`); code != http.StatusBadRequest {
		t.Errorf("invalid cve = %d %s", code, body)
	}
	if code, body = post(t, srv.URL+"/faultlines/gather", `{not json`); code != http.StatusBadRequest {
		t.Errorf("bad body = %d %s", code, body)
	}

	// Unwired: the endpoint refuses honestly rather than pretending to have looked.
	bare := gatherServer(t, nil)
	if code, body = post(t, bare.URL+"/faultlines/gather", `{"cve":"CVE-2026-0001"}`); code != http.StatusServiceUnavailable {
		t.Errorf("unwired = %d %s", code, body)
	}
}

func post(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

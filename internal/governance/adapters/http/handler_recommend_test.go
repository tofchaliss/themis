package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/app"
)

type fakeAdvisor struct {
	rec      app.Recommendation
	produced bool
	err      error
}

func (a fakeAdvisor) RecommendPosition(_ context.Context, _ string) (app.Recommendation, bool, error) {
	return a.rec, a.produced, a.err
}

func serverWithAdvisor(t *testing.T, repo *fakeRepo, adv app.PositionAdvisor) *httptest.Server {
	t.Helper()
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(adv)
	read := app.NewReadService(repo, fakeProjection{})
	srv := httptest.NewServer(govhttp.NewHandler(write, read).Router())
	t.Cleanup(srv.Close)
	return srv
}

func TestRecommendPositionEndpointProduced(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "F1", "rel-1", "fl-1", "CVE-1"))
	adv := fakeAdvisor{produced: true, rec: app.Recommendation{
		Stance: "affected", Confidence: 0.8, Reasoning: "KEV-listed", Capability: "recommend_position@v1",
	}}
	srv := serverWithAdvisor(t, repo, adv)
	code, body := do(t, http.MethodPost, srv.URL+"/findings/F1/recommend", nil)
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", code, body)
	}
}

func TestRecommendPositionEndpointNoProposal(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "F1", "rel-1", "fl-1", "CVE-1"))
	srv := serverWithAdvisor(t, repo, fakeAdvisor{produced: false})
	code, _ := do(t, http.MethodPost, srv.URL+"/findings/F1/recommend", nil)
	if code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", code)
	}
}

func TestRecommendPositionEndpointNotFound(t *testing.T) {
	repo := newRepo() // no finding seeded
	adv := fakeAdvisor{produced: true, rec: app.Recommendation{Stance: "affected", Capability: "c"}}
	srv := serverWithAdvisor(t, repo, adv)
	code, _ := do(t, http.MethodPost, srv.URL+"/findings/missing/recommend", nil)
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", code)
	}
}

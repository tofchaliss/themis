package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/intelligence"
	"github.com/themis-project/themis/internal/governance/app"
)

// TestGovernanceIntelligenceSeam drives the on-demand seam end-to-end over HTTP: a human
// POSTs /findings/{id}/recommend to Governance, which (AI enabled) invokes the real
// Intelligence client against a fake Intelligence Gateway and records the returned
// advisory Proposal — never auto-accepted.
func TestGovernanceIntelligenceSeam(t *testing.T) {
	var gotBody map[string]string
	intel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/capabilities/recommend_position/invoke" {
			t.Errorf("intel path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"capability":"recommend_position@v1","finding_id":"F1","stance":"affected",` +
			`"confidence":0.8,"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"KEV-listed"}`))
	}))
	defer intel.Close()

	repo := newRepo()
	repo.seed(identified(t, "F1", "rel-1", "fl-1", "CVE-1"))
	client := intelligence.NewClient(intel.URL, intel.Client())
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(client)
	srv := httptest.NewServer(govhttp.NewHandler(write, app.NewReadService(repo, fakeProjection{})).Router())
	defer srv.Close()

	// Human on-demand request.
	code, _ := do(t, http.MethodPost, srv.URL+"/findings/F1/recommend", nil)
	if code != http.StatusCreated {
		t.Fatalf("recommend status = %d, want 201", code)
	}
	// The exact wire request carried the subject finding id.
	if gotBody["finding_id"] != "F1" {
		t.Errorf("intelligence received finding_id %q, want F1", gotBody["finding_id"])
	}

	// The advisory proposal was recorded as an AI proposal, still awaiting a human decision.
	f, err := repo.GetByID(context.Background(), "F1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(f.Proposals()) != 1 {
		t.Fatalf("want 1 recorded proposal, got %d", len(f.Proposals()))
	}
	p := f.Proposals()[0]
	if string(p.Proposer().Kind) != "ai" || p.Proposer().ID != "recommend_position@v1" {
		t.Errorf("proposer = %+v, want ai/recommend_position@v1", p.Proposer())
	}
	if string(p.Status()) != "proposed" {
		t.Errorf("AI proposal must not be auto-accepted; status = %s", p.Status())
	}
}

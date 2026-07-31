package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
			`"confidence":0.8,"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"KEV-listed",` +
			`"decided_by":"llm:affected"}`))
	}))
	defer intel.Close()

	repo := newRepo()
	repo.seed(identified(t, "F1", "rel-1", "fl-1", "CVE-1"))
	client := intelligence.NewClient(intel.URL, intel.Client())
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(client)
	srv := httptest.NewServer(govhttp.NewHandler(write, app.NewReadService(repo, fakeProjection{}, nil)).Router())
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
	// The decided-by provenance travels the wire into the recorded rationale.
	if !strings.Contains(p.Rationale(), "[llm:affected]") {
		t.Errorf("rationale must carry the decided-by provenance; got %q", p.Rationale())
	}
}

// TestGovernanceIntelligenceSeamInsufficient drives the honest "no recommendation" path
// over the wire: the Gateway declines (204 — insufficient / disabled / unavailable), and
// Governance records NO proposal, never an error — the pipeline is unaffected.
func TestGovernanceIntelligenceSeamInsufficient(t *testing.T) {
	intel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // the Gateway produced no proposal
	}))
	defer intel.Close()

	repo := newRepo()
	repo.seed(identified(t, "F1", "rel-1", "fl-1", "CVE-1"))
	client := intelligence.NewClient(intel.URL, intel.Client())
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(client)
	srv := httptest.NewServer(govhttp.NewHandler(write, app.NewReadService(repo, fakeProjection{}, nil)).Router())
	defer srv.Close()

	code, _ := do(t, http.MethodPost, srv.URL+"/findings/F1/recommend", nil)
	if code != http.StatusNoContent {
		t.Fatalf("a declined recommendation must yield 204, got %d", code)
	}
	f, err := repo.GetByID(context.Background(), "F1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(f.Proposals()) != 0 {
		t.Errorf("no proposal must be recorded when the Gateway declines; got %d", len(f.Proposals()))
	}
}

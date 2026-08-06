package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// buildE2E assembles the full Δ1 Gateway over fake Governance + Knowledge read APIs and
// a deterministic fake provider whose response is providerResponse — the per-context
// e2e (identifiers -> grounded -> validated -> Proposal), no running model.
func buildE2E(t *testing.T, providerResponse string) *Handler {
	// Default grounding: component 1.0.0 is inside the affected range (<1.2), so the rule
	// defers and the LLM path runs — exercising the Δ1 behaviour under test.
	return buildE2EGrounded(t, providerResponse, "pkg:golang/x@1.0.0", `["<1.2"]`)
}

func buildE2EGrounded(t *testing.T, providerResponse, purl, affectedRanges string) *Handler {
	t.Helper()
	// ONE server serving ONE projection — the runtime no longer stitches two responses
	// together, which is what stopped it orchestrating (EDR-TRUST-01 T10).
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"finding":{"id":"F1","release_id":"R1","faultline_id":"FL1",` +
			`"cve":"CVE-2024-0001","stage":"identified","components":[{"purl":"` + purl + `"}]},` +
			`"knowledge":{"faultline_id":"FL1","cve":"CVE-2024-0001","severity":"high","epss":0.4,` +
			`"kev":true,"exploit_public":true,"fixed_versions":[],"affected_ranges":` + affectedRanges + `}}`))
	}))
	t.Cleanup(gov.Close)

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:   domain.DefaultRegistry(),
		Projection: readapi.NewAssessmentClient(gov.URL, gov.Client()),
		Prompt:     pr,
		Engines: []app.Engine{
			engine.NewLLMEngine(provider.NewStaticRouter(provider.NewFakeProvider(providerResponse))),
		},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return NewHandler(gw, nil)
}

func TestE2EGroundedProposal(t *testing.T) {
	resp := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
		`"evidence":[{"kind":"faultline","ref":"FL1"},{"kind":"cve","ref":"CVE-2024-0001"}],"reasoning":"KEV-listed, no fix"}`
	rr := do(t, buildE2E(t, resp), `{"finding_id":"F1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"stance":"affected"`) {
		t.Errorf("expected an affected proposal; body=%s", rr.Body.String())
	}
}

func TestE2EHallucinationNoProposal(t *testing.T) {
	// Cites a CVE that is not in the assembled grounding — stage-2 must reject it.
	resp := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
		`"evidence":[{"kind":"cve","ref":"CVE-9999-9999"}],"reasoning":"hallucinated"}`
	rr := do(t, buildE2E(t, resp), `{"finding_id":"F1"}`)
	if rr.Code != http.StatusNoContent {
		t.Errorf("hallucinated evidence must yield 204 (no proposal), got %d", rr.Code)
	}
}

func TestE2EDisallowedStanceNoProposal(t *testing.T) {
	// A human/process stance the capability may not recommend — schema enum rejects it.
	resp := `{"finding_id":"F1","recommended_stance":"deferred","confidence":0.5,"evidence":[],"reasoning":"x"}`
	rr := do(t, buildE2E(t, resp), `{"finding_id":"F1"}`)
	if rr.Code != http.StatusNoContent {
		t.Errorf("disallowed stance must yield 204, got %d", rr.Code)
	}
}

// Δ2: component 2.0.0 is OUTSIDE the affected range (<1.2) → the deterministic rule decides
// not_affected and short-circuits; the provider (which would say "affected") is never used.
// The runtime no longer settles a provable question (EDR-TRUST-01 T5). An out-of-range
// component used to short-circuit here with `decided_by: rule:not_affected`; the
// deterministic verdict now runs in the backend, on enrichment, and — crucially — whether or
// not AI is switched on at all. What reaches this endpoint is a reasoning request, so the
// model answers it.
//
// This is a deliberate behaviour change at this endpoint, pinned rather than merely deleted:
// nothing here may quietly start deciding again.
func TestE2ENoDeterministicShortCircuitInTheRuntime(t *testing.T) {
	llmSays := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.9,"evidence":[],"reasoning":"llm"}`
	h := buildE2EGrounded(t, llmSays, "pkg:golang/x@2.0.0", `["<1.2"]`)
	rr := do(t, h, `{"finding_id":"F1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"decided_by":"rule:`) {
		t.Errorf("the runtime must not carry rule provenance any more; body=%s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"decided_by":"llm:`) {
		t.Errorf("the reasoning step should have answered; body=%s", rr.Body.String())
	}
}

// Δ2: the model honestly declines → insufficient → 204 (no proposal), never an error.
func TestE2EInsufficientNoProposal(t *testing.T) {
	resp := `{"finding_id":"F1","recommended_stance":"insufficient","confidence":0,"evidence":[],"reasoning":"not enough data"}`
	rr := do(t, buildE2E(t, resp), `{"finding_id":"F1"}`)
	if rr.Code != http.StatusNoContent {
		t.Errorf("insufficient must yield 204 (no proposal), got %d; body=%s", rr.Code, rr.Body.String())
	}
}

// Replayability (EDR-TRUST-01 T10). A Domain Projection is deterministic and self-contained,
// so it IS a test fixture: the whole capability runs from a recorded JSON blob, through the
// real client decode path, with no database, no Governance, no Knowledge and no bus.
//
// That property is not incidental — it is the payoff for the runtime doing no gathering. When
// the runtime composed two live reads, reproducing a reasoning failure meant reproducing two
// services' states; now it means pasting one JSON document.
func TestE2EReplaysFromARecordedProjectionFixture(t *testing.T) {
	const recorded = `{
	  "finding": {"id":"F1","release_id":"R1","faultline_id":"FL1","cve":"CVE-2024-0001",
	              "stage":"identified","components":[{"purl":"pkg:golang/x@1.0.0"}]},
	  "knowledge": {"faultline_id":"FL1","cve":"CVE-2024-0001","severity":"high","epss":0.4,
	                "kev":true,"exploit_public":true,"affected_ranges":["<1.2"],"fixed_versions":[]}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(recorded))
	}))
	defer srv.Close()

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	llm := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
		`"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"replayed"}`
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:   domain.DefaultRegistry(),
		Projection: readapi.NewAssessmentClient(srv.URL, srv.Client()),
		Prompt:     pr,
		Engines:    []app.Engine{engine.NewLLMEngine(provider.NewStaticRouter(provider.NewFakeProvider(llm)))},
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	rr := do(t, NewHandler(gw, nil), `{"subject":{"type":"finding","ids":["F1"]}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	// The cited evidence resolved against the recorded projection — grounding verification
	// ran end-to-end against the fixture, with nothing live behind it.
	if !strings.Contains(rr.Body.String(), `"stance":"affected"`) {
		t.Errorf("body = %s", rr.Body.String())
	}
}

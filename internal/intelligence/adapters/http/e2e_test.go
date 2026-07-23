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
	t.Helper()
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"F1","release_id":"R1","faultline_id":"FL1","cve":"CVE-2024-0001",` +
			`"stage":"identified","components":[{"purl":"pkg:golang/x@1.0.0"}]}`))
	}))
	t.Cleanup(gov.Close)
	know := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"FL1","cve":"CVE-2024-0001","view":{"severity":"high","epss":0.4,` +
			`"kev":true,"exploit_public":true,"fixed_versions":[],"affected_ranges":["<1.2"]}}`))
	}))
	t.Cleanup(know.Close)

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:  domain.DefaultRegistry(),
		Finding:   readapi.NewFindingClient(gov.URL, gov.Client()),
		Faultline: readapi.NewFaultlineClient(know.URL, know.Client()),
		Prompt:    pr,
		Engine:    engine.NewLLMEngine(provider.NewStaticRouter(provider.NewFakeProvider(providerResponse))),
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

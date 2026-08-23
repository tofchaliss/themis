package wiring_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/adapters/embed"
	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/adapters/index"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/adapters/wiring"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// precedentSensitiveProvider stands in for the LLM: it reads the rendered prompt and, when a
// prior enterprise decision of "not_affected" is present, recommends not_affected — otherwise
// affected. This lets the e2e prove that a RETRIEVED semantic precedent changes the
// recommendation, with no live model. It is the Δ3a acceptance test / demo.
type precedentSensitiveProvider struct{ lastPrompt string }

func (p *precedentSensitiveProvider) Complete(_ context.Context, req app.CompletionRequest) (app.CompletionResult, error) {
	p.lastPrompt = req.Prompt
	stance := "affected"
	// Key on the indexed precedent's rationale text, which appears in the prompt ONLY when a
	// precedent was actually retrieved (unlike "not_affected", which the instructions always
	// list as an allowed stance). Presence of the precedent flips the recommendation.
	if strings.Contains(req.Prompt, "vulnerable function not reachable") {
		stance = "not_affected"
	}
	raw := `{"finding_id":"F1","recommended_stance":"` + stance +
		`","confidence":0.9,"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"weighed against precedent"}`
	return app.CompletionResult{Text: raw, TokensUsed: 1}, nil
}
func (p *precedentSensitiveProvider) Name() string  { return "precedent-sensitive-fake" }
func (p *precedentSensitiveProvider) Model() string { return "fake" }

type stubProjectionReader struct{ p domain.FindingAssessment }

func (s stubProjectionReader) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	return s.p, nil
}

func (s stubProjectionReader) GetReleasePosture(context.Context, string) (domain.ReleasePosture, error) {
	return domain.ReleasePosture{}, nil
}

func (s stubProjectionReader) GetReleaseComparison(context.Context, string, string) (domain.ReleaseComparison, error) {
	return domain.ReleaseComparison{}, nil
}

func demoGateway(t *testing.T, prov app.Provider, idx *index.Memory, emb app.Embedder) *app.Gateway {
	t.Helper()
	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry: domain.DefaultRegistry(),
		Projection: stubProjectionReader{p: domain.FindingAssessment{
			Finding: domain.FindingView{
				ID: "F1", ReleaseID: "rel-new", FaultlineID: "FL1", CVE: "CVE-2026-NEW",
				Components: []string{"pkg:golang/openssl"},
			},
			Knowledge: domain.FaultlineView{ID: "FL1", CVE: "CVE-2026-NEW", Severity: "high"},
		}},
		Prompt: pr,
		// The retrieval seam is a service, not an engine: the same instance the read API
		// (GET /findings/{id}/similar) serves engineers from. No exact-CVE fallback reader
		// here, so the demo exercises the semantic path alone.
		Precedents: app.NewPrecedentService(emb, idx, nil, 5),
		Engines: []app.Engine{
			engine.NewLLMEngine(provider.NewTieredRouter(prov, nil, nil)),
		},
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return gw
}

// TestDemoSemanticPrecedentChangesRecommendation is the Δ3a demo (Use Case #4): a never-before-
// seen CVE gets a recommendation grounded in semantically similar PAST decisions. With a cold
// index the recommendation is "affected"; after a similar past not_affected Position (a DIFFERENT
// CVE on the SAME component) is indexed, the retrieved precedent flips it to "not_affected".
func TestDemoSemanticPrecedentChangesRecommendation(t *testing.T) {
	emb := embed.NewFakeEmbedder(256)
	idx := index.NewMemory()
	prov := &precedentSensitiveProvider{}
	gw := demoGateway(t, prov, idx, emb)
	ctx := context.Background()

	// Case A — cold index (no precedent): the recommendation is "affected".
	pA, ocA := gw.Invoke(ctx, "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr-A")
	if !ocA.Produced || pA.Recommendation.Stance != domain.StanceAffected {
		t.Fatalf("cold index: outcome=%+v stance=%v, want produced/affected", ocA, pA.Recommendation.Stance)
	}
	if ocA.PrecedentsUsed != 0 {
		t.Errorf("cold index PrecedentsUsed = %d, want 0", ocA.PrecedentsUsed)
	}

	// Index a semantically similar past decision: a DIFFERENT CVE on the SAME component (openssl),
	// decided not_affected in another release. Embed the SAME text the query embeds so the vectors
	// are comparable (this is exactly what the population consumer does).
	vec, err := emb.Embed(ctx, domain.SubjectText("high", []string{"pkg:golang/openssl"}))
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	idx.Upsert(store.EmbeddingRecord{
		FindingID: "F-past", ReleaseID: "rel-old", FaultlineID: "FL-old", CVE: "CVE-2025-OLD",
		Component: "pkg:golang/openssl", Stance: "not_affected", Rationale: "vulnerable function not reachable",
		Vector: vec,
	})

	// Case B — same subject, warm index: the retrieved precedent changes the recommendation.
	pB, ocB := gw.Invoke(ctx, "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr-B")
	if !ocB.Produced || pB.Recommendation.Stance != domain.StanceNotAffected {
		t.Fatalf("warm index: outcome=%+v stance=%v, want produced/not_affected (precedent should flip it)", ocB, pB.Recommendation.Stance)
	}
	if ocB.PrecedentsUsed != 1 {
		t.Errorf("warm index PrecedentsUsed = %d, want 1 (provenance)", ocB.PrecedentsUsed)
	}
	if !strings.Contains(prov.lastPrompt, "CVE-2025-OLD") {
		t.Errorf("the prompt must cite the retrieved precedent's CVE\n%s", prov.lastPrompt)
	}
}

func TestWireStatelessVsStateful(t *testing.T) {
	base := wiring.Config{
		GovernanceURL: "http://gov",
		UseFake:       true, HTTPClient: http.DefaultClient,
	}

	// Stateless: no store → no retrieval plane.
	stateless, err := wiring.Wire(base)
	if err != nil {
		t.Fatalf("wire stateless: %v", err)
	}
	if stateless.Index != nil || stateless.Consumer != nil {
		t.Errorf("stateless Wire must not build an index/consumer, got index=%v consumer=%v", stateless.Index, stateless.Consumer)
	}
	if stateless.Handler == nil || stateless.Gateway == nil {
		t.Error("stateless Wire must still build the Gateway + Handler")
	}

	// Stateful: a store lights up the Δ3a retrieval plane (index + population consumer). The
	// store's pool is never dereferenced during Wire, so a nil-pool store is fine here.
	cfg := base
	cfg.Store = store.New(nil)
	stateful, err := wiring.Wire(cfg)
	if err != nil {
		t.Fatalf("wire stateful: %v", err)
	}
	if stateful.Index == nil || stateful.Consumer == nil {
		t.Errorf("stateful Wire must build the index + population consumer, got index=%v consumer=%v", stateful.Index, stateful.Consumer)
	}
}

// TestWireHonoursTheConfiguredProviderTimeout guards a defect that made THEMIS_LLM_TIMEOUT inert.
//
// There are TWO deadlines on one invocation: the provider HTTP client's, and the Gateway's own
// per-invocation deadline. The shorter always wins. Wire populated only the former, so the
// Gateway silently kept its hard-coded 60s default — and an operator raising THEMIS_LLM_TIMEOUT
// for a slow local model saw every call still abort at 60s with `provider_error`, surfacing as a
// 204 that reads like "the AI declined" (observed on the VM 2026-08-07: three calls, durations
// 59.995s / 59.991s / 59.989s, with THEMIS_LLM_TIMEOUT=300s set).
//
// The test drives a deliberately slow provider endpoint and asserts the call is cut off near the
// CONFIGURED deadline. Without the fix it would run to the 60s default instead.
func TestWireHonoursTheConfiguredProviderTimeout(t *testing.T) {
	slowLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second) // far longer than the deadline under test
		w.WriteHeader(http.StatusOK)
	}))
	defer slowLLM.Close()

	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"finding":{"id":"F1","release_id":"rel-1","faultline_id":"FL1",
			"cve":"CVE-2026-1","stage":"identified","components":[{"purl":"pkg:golang/openssl"}]},
			"knowledge":{"faultline_id":"FL1","cve":"CVE-2026-1","severity":"high"}}`))
	}))
	defer gov.Close()

	intel, err := wiring.Wire(wiring.Config{
		GovernanceURL: gov.URL,
		OllamaURL:     slowLLM.URL,
		Model:         "slow-model",
		// A long HTTP-client timeout on purpose: if the Gateway deadline were ignored, nothing
		// else would stop the call, and the assertion below would fail on elapsed time.
		HTTPClient:      &http.Client{Timeout: 30 * time.Second},
		ProviderTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("wire: %v", err)
	}

	start := time.Now()
	_, out := intel.Gateway.Invoke(context.Background(), "recommend_position",
		domain.Selection{Type: domain.SelectionFinding, IDs: []string{"F1"}}, "corr-1")
	elapsed := time.Since(start)

	if out.Produced {
		t.Fatal("a provider that never answers must not produce a proposal")
	}
	if elapsed > time.Second {
		t.Errorf("invocation took %v — the configured ProviderTimeout was not applied", elapsed)
	}
}

//go:build llm

package http

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// These tests drive the AI seam end-to-end against a REAL model over the OpenAI-compatible
// chat-completions API — the non-deterministic check the deterministic suite deliberately omits
// (CI must be reproducible, so it never talks to a model).
//
// They exist because of a defect class `make check-ci` CANNOT see. The prompt and the Grounding
// Verification gate are an interface with **no compiler between them**, and a fake provider returns
// whatever the test author already believed — so a fake can never surface a disagreement between
// the two. Measured 2026-08-07: every fake-provider test passed while the live `plan_remediation`
// capability was refused **three times running**, each time for a citation form the prompt had
// invited and the gate rejected.
//
// Because the Gateway provider is a pure OpenAI-compatible client, ANY such backend works by
// pointing the base URL at it:
//
//	Ollama:     THEMIS_LLM_URL=http://localhost:11434 THEMIS_LLM_MODEL=llama3.1:8b   make e2e-llm
//	LM Studio:  THEMIS_LLM_URL=http://localhost:1234  THEMIS_LLM_MODEL=<loaded-model> make e2e-llm
//	vLLM:       THEMIS_LLM_URL=http://localhost:8000  THEMIS_LLM_MODEL=<served-model> make e2e-llm
//
// OPT-IN behind the `llm` build tag, and each SKIPS when the server is unreachable.

// llmEndpoint returns the configured endpoint, skipping the test when nothing answers there.
func llmEndpoint(t *testing.T) (url, model string) {
	t.Helper()
	url = envOr("THEMIS_LLM_URL", "http://localhost:11434")
	model = envOr("THEMIS_LLM_MODEL", "llama3.1:8b")
	probe := &http.Client{Timeout: 3 * time.Second}
	resp, err := probe.Get(url + "/v1/models")
	if err != nil {
		t.Skipf("no OpenAI-compatible LLM server at %s (%v) — start Ollama / LM Studio / vLLM and load %q", url, err, model)
	}
	_ = resp.Body.Close()
	return url, model
}

// realProvider builds the live provider with a timeout generous enough for a cold model load.
func realProvider(url, model string) app.Provider {
	return provider.NewOllamaProvider(url, model, &http.Client{Timeout: 300 * time.Second}).
		WithAPIKey(os.Getenv("THEMIS_LLM_API_KEY")).                // optional bearer (LM Studio / OpenAI / vLLM)
		WithResponseFormat(os.Getenv("THEMIS_LLM_RESPONSE_FORMAT")) // "" = Ollama default; "json_schema" for LM Studio
}

func realGateway(t *testing.T, governanceURL, url, model string) *app.Gateway {
	t.Helper()
	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:        domain.DefaultRegistry(),
		Projection:      readapi.NewAssessmentClient(governanceURL, nil),
		Prompt:          pr,
		Engines:         []app.Engine{engine.NewLLMEngine(provider.NewStaticRouter(realProvider(url, model)))},
		ProviderTimeout: 300 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gw
}

func invoke(t *testing.T, h *Handler, capability, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/capabilities/"+capability+"/invoke", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr
}

// TestE2ERealLLM_RecommendPosition drives the Decision capability against a real model.
//
// A real model is non-deterministic, so it asserts only that the output survives the Gateway's
// staged validation — a schema+business-valid Proposal (200 with `llm:<stance>` provenance) or an
// honest "no proposal" (204) — NOT a specific stance.
func TestE2ERealLLM_RecommendPosition(t *testing.T) {
	url, model := llmEndpoint(t)

	// One authoritative Domain Projection, exactly as Governance produces it (T10). Installed
	// 1.26.5 is inside "<2.0.0", so the deterministic range gate does not decide and the model runs.
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"finding":{"id":"F1","release_id":"R1","faultline_id":"FL1","cve":"CVE-2024-0001",
			           "stage":"identified","components":[{"purl":"pkg:pypi/urllib3@1.26.5"}]},
			"knowledge":{"faultline_id":"FL1","cve":"CVE-2024-0001","severity":"high","cvss_score":7.5,
			             "epss":0.6,"kev":true,"exploit_public":true,
			             "fixed_versions":["2.0.0"],"affected_ranges":["<2.0.0"]}}`))
	}))
	defer gov.Close()

	h := NewHandler(realGateway(t, gov.URL, url, model), nil)
	rr := invoke(t, h, "recommend_position", `{"subject":{"type":"finding","ids":["F1"]}}`)
	t.Logf("recommend_position on %q @ %s → HTTP %d\n%s", model, url, rr.Code, rr.Body.String())

	switch rr.Code {
	case http.StatusOK:
		if !strings.Contains(rr.Body.String(), `"decided_by":"llm:`) {
			t.Errorf("a 200 must carry an llm:<stance> provenance; body=%s", rr.Body.String())
		}
	case http.StatusNoContent:
		assertNotAGroundingDisagreement(t, rr)
	default:
		t.Fatalf("unexpected status %d; body=%s", rr.Code, rr.Body.String())
	}
}

// TestE2ERealLLM_PlanRemediation drives the Information capability (plan_remediation@v1) against a
// real model over a release-scoped projection.
//
// This is the test PLAN-4 asked for. The three live refusals it guards against were all the same
// shape: the model cited the heading of the plan step it was discussing — `PyYAML (rpm)`, then the
// bare package name, then the merged list `httpd, mod_http2` — and Grounding Verification, which is
// the ONLY gate on an Information Response (T8), discarded the whole answer. Nothing in the
// deterministic suite could have caught it.
func TestE2ERealLLM_PlanRemediation(t *testing.T) {
	url, model := llmEndpoint(t)

	// A release posture with a MERGED step (two packages, identical CVE set) and a single-package
	// step. The merged one is deliberate: its heading renders as a package LIST, which is the exact
	// citation form that was refused live.
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
		  {"finding_id":"f1","cve":"CVE-2026-1","residual_priority":90,"effective_priority":90,
		   "components":[{"purl":"pkg:rpm/rocky/httpd@2.4.37","name":"httpd","version":"2.4.37",
		                  "ecosystem":"rpm","source":"httpd"}]},
		  {"finding_id":"f2","cve":"CVE-2026-1","residual_priority":90,"effective_priority":90,
		   "components":[{"purl":"pkg:rpm/rocky/mod_http2@1.15","name":"mod_http2","version":"1.15",
		                  "ecosystem":"rpm","source":"mod_http2"}]},
		  {"finding_id":"f3","cve":"CVE-2026-2","residual_priority":70,"effective_priority":70,
		   "components":[{"purl":"pkg:rpm/rocky/python3-ply@3.9","name":"python3-ply","version":"3.9",
		                  "ecosystem":"rpm","source":"python-ply"}]}
		]`))
	}))
	defer gov.Close()

	h := NewHandler(realGateway(t, gov.URL, url, model), nil)
	rr := invoke(t, h, "plan_remediation", `{"subject":{"type":"release","ids":["rel-1"]}}`)
	t.Logf("plan_remediation on %q @ %s → HTTP %d\n%s", model, url, rr.Code, rr.Body.String())

	switch rr.Code {
	case http.StatusOK:
		body := rr.Body.String()
		// An Information Response is NOT a Proposal: nothing on this path may reach Governance (T7).
		if strings.Contains(body, `"recommendation"`) || strings.Contains(body, `"stance"`) {
			t.Errorf("an Information Response must carry no proposal/stance; body=%s", body)
		}
		if !strings.Contains(body, `"information"`) {
			t.Errorf("a 200 must carry the plan text; body=%s", body)
		}
	case http.StatusNoContent:
		assertNotAGroundingDisagreement(t, rr)
	default:
		t.Fatalf("unexpected status %d; body=%s", rr.Code, rr.Body.String())
	}
}

// assertNotAGroundingDisagreement fails a 204 that was caused by the prompt and the grounding gate
// disagreeing, while tolerating the outcomes that are genuinely fine.
//
// This is the whole point of running a real model. A declined recommendation (`insufficient`) is
// the seam working as designed and must not fail a build; a provider timeout is an environment
// problem. But `business_invalid` means the model cited something the projection does not contain —
// and every live instance of that so far has been OUR prompt inviting a citation OUR gate refuses.
// Failing on it is what turns three hand-found refusals into a gate.
func assertNotAGroundingDisagreement(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	reason := rr.Header().Get(reasonHeader)
	detail := rr.Header().Get(detailHeader)
	switch {
	case strings.HasPrefix(reason, app.ReasonBusinessInvalid):
		t.Fatalf("the model's output was refused as ungrounded — the prompt and the grounding gate "+
			"disagree about what a valid citation looks like: %s (%s)", reason, detail)
	case reason == "":
		t.Fatalf("a 204 must state its reason (AI-204-1)")
	default:
		t.Logf("no proposal, and legitimately so: reason=%q detail=%q", reason, detail)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

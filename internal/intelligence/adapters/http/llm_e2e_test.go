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

// TestE2ERealLLM drives recommend_position end-to-end against a REAL model over the
// OpenAI-compatible chat-completions API — the non-deterministic check the deterministic
// suite deliberately omits (CI must be reproducible, so it never talks to a model).
//
// Because the Gateway provider is a pure OpenAI-compatible client, ANY such backend works
// by pointing the base URL at it — this is C1's vendor-neutrality, exercised concretely:
//
//	Ollama:     THEMIS_LLM_URL=http://localhost:11434 THEMIS_LLM_MODEL=llama3.1:8b   make e2e-llm
//	LM Studio:  THEMIS_LLM_URL=http://localhost:1234  THEMIS_LLM_MODEL=<loaded-model> make e2e-llm
//	vLLM:       THEMIS_LLM_URL=http://localhost:8000  THEMIS_LLM_MODEL=<served-model> make e2e-llm
//
// It is OPT-IN behind the `llm` build tag and SKIPS when the server is unreachable, so a
// normal `go test` / `make check` never runs it. A real model is non-deterministic, so it
// asserts only that the output survives the Gateway's 3-stage validation — a schema+
// business-valid Proposal (200 with an `llm:<stance>` provenance) or an honest "no
// proposal" (204) — NOT a specific stance.
func TestE2ERealLLM(t *testing.T) {
	url := envOr("THEMIS_LLM_URL", "http://localhost:11434")
	model := envOr("THEMIS_LLM_MODEL", "llama3.1:8b")

	// Skip unless the OpenAI-compatible server actually answers /v1/models.
	probe := &http.Client{Timeout: 3 * time.Second}
	resp, err := probe.Get(url + "/v1/models")
	if err != nil {
		t.Skipf("no OpenAI-compatible LLM server at %s (%v) — start Ollama / LM Studio / vLLM and load %q", url, err, model)
	}
	_ = resp.Body.Close()

	// In-range grounding (installed 1.26.5 is inside "<2.0.0") → the version-range rule
	// DEFERS → the REAL model runs.
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"F1","release_id":"R1","faultline_id":"FL1","cve":"CVE-2024-0001",` +
			`"stage":"identified","components":[{"purl":"pkg:pypi/urllib3@1.26.5"}]}`))
	}))
	defer gov.Close()
	know := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"FL1","cve":"CVE-2024-0001","view":{"severity":"high","epss":0.6,` +
			`"kev":true,"exploit_public":true,"fixed_versions":["2.0.0"],"affected_ranges":["<2.0.0"]}}`))
	}))
	defer know.Close()

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	realProvider := provider.NewOllamaProvider(url, model, &http.Client{Timeout: 150 * time.Second}).
		WithAPIKey(os.Getenv("THEMIS_LLM_API_KEY")).                // optional bearer token (LM Studio / OpenAI / vLLM)
		WithResponseFormat(os.Getenv("THEMIS_LLM_RESPONSE_FORMAT")) // "" = Ollama default; "json_schema" for LM Studio
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:  domain.DefaultRegistry(),
		Finding:   readapi.NewFindingClient(gov.URL, gov.Client()),
		Faultline: readapi.NewFaultlineClient(know.URL, know.Client()),
		Prompt:    pr,
		Engines: []app.Engine{
			engine.NewLLMEngine(provider.NewStaticRouter(realProvider)),
		},
		ProviderTimeout: 180 * time.Second, // a cold model load can be slow
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	rr := do(t, NewHandler(gw, nil), `{"finding_id":"F1"}`)
	t.Logf("real model %q @ %s → HTTP %d\n%s", model, url, rr.Code, rr.Body.String())

	switch rr.Code {
	case http.StatusOK:
		if !strings.Contains(rr.Body.String(), `"decided_by":"llm:`) {
			t.Errorf("a 200 must carry an llm:<stance> provenance; body=%s", rr.Body.String())
		}
	case http.StatusNoContent:
		// Honest "no proposal" — the model declined or its output failed validation. Also valid.
	default:
		t.Fatalf("unexpected status %d; body=%s", rr.Code, rr.Body.String())
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

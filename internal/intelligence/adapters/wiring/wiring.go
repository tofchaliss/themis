// Package wiring is the Intelligence Gateway's composition root: it assembles the reactive
// Gateway from config — read-API Knowledge Providers, the Rule + LLM engines over their
// provider (Ollama by default, a dev fake optionally), the prompt renderer, and the reactive
// HTTP API. When a Store is supplied it additionally builds the Δ3a retrieval plane: an
// embedder, the in-memory Operational Semantic Index, the Knowledge engine, and the bus
// population consumer — so `recommend_position` is grounded in semantically similar past
// Positions. With no Store the Gateway is stateless (the Knowledge step skips; the exact-CVE
// fallback still grounds).
package wiring

import (
	"net/http"

	"github.com/themis-project/themis/internal/intelligence/adapters/admission"
	"github.com/themis-project/themis/internal/intelligence/adapters/embed"
	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	intelhttp "github.com/themis-project/themis/internal/intelligence/adapters/http"
	"github.com/themis-project/themis/internal/intelligence/adapters/inbound"
	"github.com/themis-project/themis/internal/intelligence/adapters/index"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// fakeEmbedDim is the dimensionality of the deterministic fake embedder (dev/CI). Any value
// works; 256 keeps hash collisions low for the demo e2e.
const fakeEmbedDim = 256

// Config wires the Gateway's dependencies from the node configuration.
type Config struct {
	GovernanceURL  string // Governance read-API base URL (Finding grounding)
	KnowledgeURL   string // Knowledge read-API base URL (Faultline grounding)
	OllamaURL      string // Ollama base URL (OpenAI-compatible; used by both the LLM and the embedder)
	Model          string // pinned LLM model, e.g. "llama3.1:8b"
	APIKey         string // optional bearer token for an authenticated OpenAI-compatible server
	ResponseFormat string // structured-output mode: "" json_object (Ollama) | json_schema (LM Studio/OpenAI) | text | none
	UseFake        bool   // dev/CI: use the deterministic fake provider AND fake embedder (no model)
	Logger         *observability.Logger
	HTTPClient     *http.Client

	// Δ3a Operational Semantic Index (optional). Store == nil → a stateless Gateway (no semantic
	// precedent; the exact-CVE fallback still grounds recommendations).
	Store      *store.Store
	EmbedModel string // embedding model for RC-1 (e.g. "nomic-embed-text"); ignored when UseFake
	TopK       int    // semantic precedents to retrieve (0 → the engine default)
}

// Intelligence is the wired Gateway surface. Index and Consumer are non-nil only when a Store
// was configured (the Δ3a retrieval plane) — cmd boot-loads the Index and drives the Consumer
// off the bus.
type Intelligence struct {
	Handler  http.Handler      // the reactive invoke API (mount under /api/v1)
	Gateway  *app.Gateway      //
	Index    *index.Memory     // nil when Store is nil — the boot-load target
	Consumer *inbound.Consumer // nil when Store is nil — the bus population consumer
}

// Wire assembles the Gateway. It returns an error only if a capability's output schema fails
// to compile (a programming error).
func Wire(cfg Config) (Intelligence, error) {
	fr := readapi.NewFindingClient(cfg.GovernanceURL, cfg.HTTPClient)
	flr := readapi.NewFaultlineClient(cfg.KnowledgeURL, cfg.HTTPClient)
	prc := readapi.NewPrecedentClient(cfg.GovernanceURL, cfg.HTTPClient)

	var prov app.Provider
	if cfg.UseFake {
		prov = provider.NewFakeProvider(
			`{"finding_id":"","recommended_stance":"not_affected","confidence":0,"evidence":[],"reasoning":"dev fake provider"}`)
	} else {
		prov = provider.NewOllamaProvider(cfg.OllamaURL, cfg.Model, cfg.HTTPClient).
			WithAPIKey(cfg.APIKey).WithResponseFormat(cfg.ResponseFormat)
	}
	// No rule engine: provable verdicts run in the backend, before AI (EDR-TRUST-01 T5).
	llmEng := engine.NewLLMEngine(provider.NewStaticRouter(prov))
	engines := []app.Engine{llmEng}

	// Δ3a retrieval plane, built only when a store is configured.
	var idx *index.Memory
	var consumer *inbound.Consumer
	if cfg.Store != nil {
		var emb app.Embedder
		if cfg.UseFake {
			emb = embed.NewFakeEmbedder(fakeEmbedDim)
		} else {
			emb = embed.NewOllamaEmbedder(cfg.OllamaURL, cfg.EmbedModel, cfg.HTTPClient).WithAPIKey(cfg.APIKey)
		}
		idx = index.NewMemory()
		engines = append(engines, engine.NewKnowledgeEngine(emb, idx, cfg.TopK))
		consumer = inbound.NewConsumer(fr, flr, prc, emb, cfg.Store, idx)
	}

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		return Intelligence{}, err
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:  domain.DefaultRegistry(),
		Finding:   fr,
		Faultline: flr,
		Precedent: prc,
		Redactor:  admission.NewBasicRedactor(), // C7 secret/PII scrub (authorizer = deployment seam)
		Prompt:    pr,
		Engines:   engines,
	})
	if err != nil {
		return Intelligence{}, err
	}
	return Intelligence{
		Handler:  intelhttp.NewHandler(gw, cfg.Logger).Routes(),
		Gateway:  gw,
		Index:    idx,
		Consumer: consumer,
	}, nil
}

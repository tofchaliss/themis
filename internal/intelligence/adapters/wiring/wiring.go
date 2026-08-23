// Package wiring is the Intelligence Gateway's composition root: it assembles the reactive
// Gateway from config — read-API Knowledge Providers, the Rule + LLM engines over their
// provider (Ollama by default, a dev fake optionally), the prompt renderer, and the reactive
// HTTP API. When a Store is supplied it additionally builds the Δ3a retrieval plane: an
// embedder, the in-memory Operational Semantic Index, and the bus population consumer — so
// `recommend_position` is grounded in semantically similar past Positions. With no Store the
// Gateway is stateless (semantic retrieval skips; the exact-CVE fallback still grounds).
//
// Retrieval itself is an app-level service (app.PrecedentService), not an engine, and exactly
// ONE instance is built here for both of its consumers: the Gateway grounds a recommendation
// on it, and the read API (GET /findings/{id}/similar) shows the same result to an engineer.
// Wiring two would let the model and the human be told different things.
package wiring

import (
	"net/http"
	"time"

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
	GovernanceURL string // Governance read-API base URL (the FindingAssessment projection — the runtime's ONLY business read)
	OllamaURL     string // Ollama base URL (OpenAI-compatible; used by both the LLM and the embedder)
	Model         string // pinned LLM model, e.g. "llama3.1:8b"
	// EscalationModel / EconomyModel are the optional router tiers (phase3-intelligence-router):
	// a LARGER model an honest `insufficient` retries on once (G-AI-2b), and a SMALLER model a
	// nearly-spent budget window degrades to (G-AI-4). Empty = tier unconfigured; a value equal
	// to Model is treated as unconfigured too (escalating to the same model spends for nothing).
	EscalationModel string
	EconomyModel    string
	// BudgetDegradeFraction is the degrade-not-fail low-water mark (0 → the Gateway default 0.20).
	BudgetDegradeFraction float64
	APIKey                string // optional bearer token for an authenticated OpenAI-compatible server
	ResponseFormat        string // structured-output mode: "" json_object (Ollama) | json_schema (LM Studio/OpenAI) | text | none
	UseFake               bool   // dev/CI: use the deterministic fake provider AND fake embedder (no model)
	Logger                *observability.Logger
	HTTPClient            *http.Client
	// ProviderTimeout is the Gateway's per-invocation deadline around provider I/O. 0 → the
	// Gateway default (60s).
	//
	// It MUST be set from the same source as HTTPClient.Timeout. There are two independent
	// deadlines on one call — the HTTP client's and the Gateway's — and the shorter always wins.
	// This field was previously never populated, so raising THEMIS_LLM_TIMEOUT moved only the
	// HTTP client and every call still died at the hard-coded 60s with `provider_error`. The
	// documented remedy for a slow local model therefore did nothing.
	ProviderTimeout time.Duration

	// Δ3a Operational Semantic Index (optional). Store == nil → a stateless Gateway (no semantic
	// precedent; the exact-CVE fallback still grounds recommendations).
	Store      *store.Store
	EmbedModel string // embedding model for RC-1 (e.g. "nomic-embed-text"); ignored when UseFake
	TopK       int    // semantic precedents to retrieve (0 → the engine default)
	// BudgetTokens / BudgetWindow — D4's per-capability spend ceiling; both unset = unlimited.
	BudgetTokens int
	// MaxRunTokens — G-AI-4's per-run ceiling; 0 = unlimited.
	MaxRunTokens int
	BudgetWindow time.Duration
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
	// One projection read, from the context that owns the Finding Selection Type (T10).
	// There is deliberately NO Knowledge address here: Governance composes the enrichment
	// into the projection, which is what stopped the runtime orchestrating its own grounding.
	proj := readapi.NewAssessmentClient(cfg.GovernanceURL, cfg.HTTPClient)
	prc := readapi.NewPrecedentClient(cfg.GovernanceURL, cfg.HTTPClient)

	var prov, escProv, ecoProv app.Provider
	if cfg.UseFake {
		prov = provider.NewFakeProvider(
			`{"finding_id":"","recommended_stance":"not_affected","confidence":0,"evidence":[],"reasoning":"dev fake provider"}`)
	} else {
		ollama := func(model string) app.Provider {
			return provider.NewOllamaProvider(cfg.OllamaURL, model, cfg.HTTPClient).
				WithAPIKey(cfg.APIKey).WithResponseFormat(cfg.ResponseFormat)
		}
		prov = ollama(cfg.Model)
		// Optional router tiers: same server, same client, different model. The router itself
		// treats a tier model equal to the primary as unconfigured (see NewTieredRouter).
		if cfg.EscalationModel != "" {
			escProv = ollama(cfg.EscalationModel)
		}
		if cfg.EconomyModel != "" {
			ecoProv = ollama(cfg.EconomyModel)
		}
	}
	// No rule engine: provable verdicts run in the backend, before AI (EDR-TRUST-01 T5).
	// ONE router instance serves both consumers: the LLM engine selects through it, and the
	// Gateway asks it what is Available — a model is chosen in exactly one place (INT-0062).
	rtr := provider.NewTieredRouter(prov, escProv, ecoProv)
	// Say when a configured tier was neutralized (its model equals the primary's): silently
	// ignoring the config would make escalation look broken to the operator who typo'd it.
	if cfg.Logger != nil {
		if escProv != nil && !rtr.Available(app.TierEscalation) {
			cfg.Logger.Warn("escalation model equals the primary — tier disabled (escalating to the same model spends for nothing)")
		}
		if ecoProv != nil && !rtr.Available(app.TierEconomy) {
			cfg.Logger.Warn("economy model equals the primary — tier disabled")
		}
	}
	llmEng := engine.NewLLMEngine(rtr)
	engines := []app.Engine{llmEng}

	// Δ3a retrieval plane, built only when a store is configured. ONE PrecedentService is built
	// here and handed to BOTH the Gateway (grounding for recommend_position) and the read
	// handler (GET /findings/{id}/similar) — the single-seam rule from app/precedent.go. Wiring
	// them separately would be the bug that rule exists to prevent.
	//
	// Without a store there is no semantic index, but the service is still built: the exact-CVE
	// fallback needs no embeddings, so a stateless Gateway keeps the precedent it always had and
	// the read API degrades to exact-CVE matches rather than 404ing.
	var idx *index.Memory
	var consumer *inbound.Consumer
	var emb app.Embedder
	if cfg.Store != nil {
		if cfg.UseFake {
			emb = embed.NewFakeEmbedder(fakeEmbedDim)
		} else {
			emb = embed.NewOllamaEmbedder(cfg.OllamaURL, cfg.EmbedModel, cfg.HTTPClient).WithAPIKey(cfg.APIKey)
		}
		idx = index.NewMemory()
		consumer = inbound.NewConsumer(proj, prc, emb, cfg.Store, idx)
	}
	// index.Memory is a concrete pointer; a nil one must reach the service as a nil INTERFACE,
	// not a non-nil interface wrapping a nil pointer, or the nil check inside it never fires.
	var vidx app.VectorIndex
	if idx != nil {
		vidx = idx
	}
	// WithComparisons wires the G-AI-3 delta ranking through the same Governance client the
	// projections come from — a precedent decided on a near-identical release outranks one from
	// a very different release, for the Gateway's grounding and /similar alike.
	precedents := app.NewPrecedentService(emb, vidx, prc, cfg.TopK).WithProjection(proj).WithComparisons(proj)

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		return Intelligence{}, err
	}
	// Make the deterministic plan grouping readable without a model. The `GROUP BY` is the half
	// of a plan that is supposed to be auditable; without this it could only be inspected through
	// the LLM's prose, where a grouping bug and a bad generation look the same.
	// Nil-guarded: cfg.Logger is unset in tests and in any caller that wires the Gateway without
	// observability. Instrumentation must never be able to break the code it observes — the same
	// rule the metric recorders follow.
	if cfg.Logger != nil {
		pr = pr.WithLogger(cfg.Logger.Component("plan"))
	}
	// ONE redactor instance for both output boundaries: the prompt bound for a provider, and
	// the HTTP response bound for an engineer. Same discipline, applied twice, because they are
	// genuinely different exits from the process.
	redactor := admission.NewBasicRedactor()
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:              domain.DefaultRegistry(),
		Projection:            proj,
		Precedents:            precedents,
		Redactor:              redactor, // C7 secret/PII scrub (authorizer = deployment seam)
		Prompt:                pr,
		Engines:               engines,
		ProviderTimeout:       cfg.ProviderTimeout,
		BudgetTokens:          cfg.BudgetTokens,
		MaxRunTokens:          cfg.MaxRunTokens,
		BudgetWindow:          cfg.BudgetWindow,
		Router:                rtr,
		BudgetDegradeFraction: cfg.BudgetDegradeFraction,
	})
	if err != nil {
		return Intelligence{}, err
	}
	return Intelligence{
		Handler:  intelhttp.NewHandler(gw, cfg.Logger).WithPrecedents(precedents, redactor).Routes(),
		Gateway:  gw,
		Index:    idx,
		Consumer: consumer,
	}, nil
}

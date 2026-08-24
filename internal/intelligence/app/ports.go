package app

import (
	"context"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// Provider is a concrete model backend behind an engine (INT-0070), confined to the
// adapters ring. Δ1 has an Ollama provider (OpenAI-compatible) and a deterministic
// fake; swapping a provider never touches this port or anything above it.
type Provider interface {
	Complete(ctx context.Context, req CompletionRequest) (CompletionResult, error)
	Name() string
	Model() string
}

// CompletionRequest is a single model call. JSONSchema, when set, asks the provider
// to constrain output (OpenAI-compatible structured output); providers that cannot
// honor it fall back to prompt instruction + stage-1 schema validation.
type CompletionRequest struct {
	Prompt      string
	Temperature float64
	JSONSchema  string
}

// CompletionResult is the raw model response.
type CompletionResult struct {
	Text       string
	TokensUsed int
}

// ModelTier is the runtime routing decision the Gateway makes per invocation
// (D6 · INT-0062, phase3-intelligence-router). It is deliberately APP-ring vocabulary:
// a capability declares requirements and never names a model or a tier — the tier is
// chosen by the Gateway from what happened at runtime (an honest decline escalates, a
// nearly-spent budget degrades), which is exactly the kind of infrastructure decision
// INT-0062 confines here.
type ModelTier string

const (
	// TierPrimary is the deployment's default chat model (THEMIS_INTELLIGENCE_MODEL).
	TierPrimary ModelTier = "primary"
	// TierEscalation is the larger model an honest `insufficient` retries on ONCE
	// (G-AI-2b) — the upgrade counterpart of degrade-not-fail. Optional.
	TierEscalation ModelTier = "escalation"
	// TierEconomy is the smaller model a nearly-spent budget window routes to
	// (G-AI-4 degrade-not-fail) — spend shrinks before it stops. Optional.
	TierEconomy ModelTier = "economy"
)

// Router picks the Provider for a capability's routing requirements at runtime
// (D6 · INT-0062). Select falls back to the primary provider for an unconfigured
// tier, so a mis-threaded tier can never fail an invocation; Available reports
// whether a DISTINCT model backs the tier, so the Gateway can decide whether an
// escalation or degrade is worth anything before spending it.
type Router interface {
	Select(req domain.RoutingRequirements, tier ModelTier) (Provider, error)
	Available(tier ModelTier) bool
}

// Engine is a kind of reasoning. Execute runs one plan step and returns its output —
// generated text (LLM) or retrieved grounding (Knowledge). An engine never settles a
// question: provable verdicts are the backend's, before AI runs (EDR-TRUST-01 T5).
type Engine interface {
	Kind() domain.EngineKind
	Execute(ctx context.Context, in ExecInput) (EngineResult, error)
}

// ExecInput is a plan step ready to run. The LLM engine consumes the pre-rendered Prompt;
// the Knowledge engine reads the assembled grounding in Context. Carrying both keeps one
// Engine port across engine kinds without requiring a rendered prompt for retrieval steps.
type ExecInput struct {
	Prompt      string
	JSONSchema  string
	Temperature float64
	Routing     domain.RoutingRequirements
	// Tier is the Gateway's runtime model-tier decision for this step ("" = primary).
	// The LLM engine hands it to the Router; retrieval engines ignore it.
	Tier    ModelTier
	Context domain.AssembledContext // grounding — read by the retrieval engine
}

// EngineResult is one engine's output. A generative engine (LLM) fills Raw + provenance for
// 3-stage validation; a retrieval engine (Knowledge) fills only Precedents.
//
// There is deliberately no deterministic-decision field. Provable verdicts are computed in
// the backend, before AI runs at all (EDR-TRUST-01 T5) — an engine here never settles a
// question, it only supplies reasoning or grounding.
type EngineResult struct {
	Raw        string
	Provider   string
	Model      string
	TokensUsed int
	// Precedents, when set by the Knowledge engine (Δ3a), are the semantically similar past
	// Positions the Gateway merges into the grounding before the LLM step.
	Precedents []domain.PrecedentPosition
}

// PromptRenderer builds the provider-facing prompt for a capability from the
// assembled context (D6). It is Gateway infrastructure — no prompt strings live in
// the domain or app rings; the template is an adapter-side asset.
type PromptRenderer interface {
	Render(capabilityID string, ctx domain.AssembledContext) (string, error)
	// Version returns the capability's prompt content hash (Δ4a D-Δ4a-3), stamped on the
	// Outcome so every telemetry / invocation-log / eval row is attributable to the exact
	// prompt that ran. "" when unknown (e.g. a test renderer that does not track versions).
	Version(capabilityID string) string
}

// InvocationCapturer records a completed invocation for the Δ4a replay harness (D-Δ4a-5).
// It is called from the Gateway AFTER redaction, with the frozen assembled context and raw
// output already scrubbed — so a captured entry can never durably hold an un-redacted secret.
// Optional and best-effort: a nil capturer disables capture, and a capture error is ignored
// (a logging/eval concern must never fail an invocation). The Gateway hands JSON bytes, not
// domain types, so the app ring stays free of any store shape.
type InvocationCapturer interface {
	Capture(ctx context.Context, rec CapturedInvocation)
}

// CapturedInvocation is the redacted, frozen record of one invocation.
type CapturedInvocation struct {
	CorrelationID string
	Capability    string
	PromptVersion string
	Model         string
	Tier          string
	ContextJSON   []byte // the assembled context, marshaled + redacted
	OutputJSON    []byte // the raw model output, marshaled + redacted; nil when no LLM step ran
	Reason        string
	DeclineClass  string
	Tokens        int
}

// ProjectionReader fetches the Domain Projection for a Selection (EDR-TRUST-01 T10).
//
// It is the runtime's ONLY business read, and it composes nothing: one business-named
// projection, fetched by id, produced by the context that owns the Selection Type. The
// runtime does not know which contexts contributed to it, does not orchestrate across them,
// and issues no follow-up reads to complete it.
//
// Precision on rule 1 ("the runtime never gathers"): what that forbids is the runtime
// participating in business orchestration — composing several contexts, or asking for a
// capability-shaped bundle, either of which moves part of the capability definition into the
// runtime. Fetching a **business-named** projection moves nothing: `FindingAssessment` is
// what a dashboard or a report reads too. The naming rule is what makes this distinction
// real rather than a loophole — a `recommend_position_context` endpoint would have been the
// violation.
type ProjectionReader interface {
	GetAssessment(ctx context.Context, findingID string) (domain.FindingAssessment, error)
	// GetReleasePosture fetches the release-scoped projection — every Finding on a Release with
	// its priority and components. Governance owns it (it owns the Release Selection Type's
	// security view), and a dashboard and a report read the same thing.
	GetReleasePosture(ctx context.Context, releaseID string) (domain.ReleasePosture, error)
	// GetReleaseComparison fetches Governance's cross-release posture diff (EDR-GOVERNANCE-01
	// D16) for compare_releases@v1 (AI-CMP-1). Governance owns the buckets, their ordering AND
	// the honesty guard (422 evidence-less / 502 evidence unreachable) — a guard refusal
	// surfaces here as an error and becomes an honest no-grounding outcome, never a narration
	// of a diff that proves nothing.
	GetReleaseComparison(ctx context.Context, baselineID, candidateID string) (domain.ReleaseComparison, error)
}

// PrecedentReader is a Knowledge Provider (D5, Δ2 C6): reads our own past Enterprise
// Positions on the same CVE (Faultline) from OTHER releases, for richer LLM grounding.
// It is the exact-CVE fallback, pulled only when semantic retrieval found nothing; a read
// failure degrades to no precedent and never blocks the recommendation.
type PrecedentReader interface {
	GetPrecedents(ctx context.Context, faultlineID, excludeReleaseID string) ([]domain.PrecedentPosition, error)
}

// Embedder turns text into a dense vector for the Operational Semantic Index (KS2, Book IV
// Chapter 8 / EDR-INTELLIGENCE-01 Rev 4, Δ3a). The Knowledge Engine embeds the subject
// Finding's text to retrieve semantically similar past Positions; the population consumer
// embeds each new decision. Confined to the adapters ring — a local Ollama embedder in
// production, a deterministic fake in CI. Model() names the embedding model so the index can
// be stamped and rebuilt on a model swap (R6).
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
	Model() string
}

// VectorIndex is the in-memory nearest-neighbour search over the Operational Semantic Index
// (KS2, Δ3a). Search returns up to k past Positions most cosine-similar to the query vector,
// excluding the subject's own release, each carrying its similarity Score. It is loaded from
// the store on boot and kept fresh by the population consumer — operational and rebuildable
// (D12), never truth.
type VectorIndex interface {
	Search(query []float32, k int, excludeReleaseID string) []domain.PrecedentPosition
}

// Authorizer is the pre-invocation authorization check (D10, Δ2 C7). A non-nil error
// rejects the request BEFORE any grounding or provider call. Δ2 wires no authorizer
// (nil = allow-all), because caller identity is a deployment seam (auth middleware) — the
// same hook shape as Governance's decider. A real deployment supplies one.
type Authorizer interface {
	Authorize(ctx context.Context, capabilityID, subjectFindingID string) error
}

// Redactor scrubs secrets / PII from the prompt before it reaches a provider (D10 C7) —
// the same redaction discipline as Communication. Δ2 is local-only, so this is
// defense-in-depth; it becomes load-bearing when cloud providers arrive (G-AI-5). nil =
// no redaction.
type Redactor interface {
	Redact(text string) string
}

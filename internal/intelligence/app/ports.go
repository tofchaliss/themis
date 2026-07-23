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

// Router picks the Provider for a capability's routing requirements at runtime
// (D6 · INT-0062). Δ1 has one provider so routing is trivial; the port lets Δ2 add
// cost/privacy-aware selection without touching callers.
type Router interface {
	Select(req domain.RoutingRequirements) (Provider, error)
}

// Engine is a kind of reasoning (Revision 2). Δ1 ships one LLM engine and no
// dispatcher. Execute runs one plan step (a rendered prompt) and returns the raw
// model output for validation.
type Engine interface {
	Kind() domain.EngineKind
	Execute(ctx context.Context, in ExecInput) (EngineResult, error)
}

// ExecInput is a rendered plan step ready to run.
type ExecInput struct {
	Prompt      string
	JSONSchema  string
	Temperature float64
	Routing     domain.RoutingRequirements
}

// EngineResult is the raw model output plus provenance for telemetry (D9).
type EngineResult struct {
	Raw        string
	Provider   string
	Model      string
	TokensUsed int
}

// PromptRenderer builds the provider-facing prompt for a capability from the
// assembled context (D6). It is Gateway infrastructure — no prompt strings live in
// the domain or app rings; the template is an adapter-side asset.
type PromptRenderer interface {
	Render(capabilityID string, ctx domain.AssembledContext) (string, error)
}

// FindingReader is a Knowledge Provider (D5): reads the subject Finding from
// Governance's read API. It decodes wire JSON into the domain's own view type — no
// cross-context import.
type FindingReader interface {
	GetFinding(ctx context.Context, findingID string) (domain.FindingView, error)
}

// FaultlineReader is a Knowledge Provider (D5): reads a Faultline's enrichment from
// Knowledge's read API into the domain's own view type.
type FaultlineReader interface {
	GetFaultline(ctx context.Context, faultlineID string) (domain.FaultlineView, error)
}

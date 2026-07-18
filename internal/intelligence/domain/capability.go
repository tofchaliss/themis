package domain

// EngineKind is the kind of reasoning an execution-plan step targets (Revision 2).
// Δ1 ships only the LLM engine; the Rule and Knowledge engines + the Engine
// Dispatcher arrive in later deltas, behind the same Engine port.
type EngineKind string

// EngineLLM is the generative-model engine — the only engine Δ1 builds.
const EngineLLM EngineKind = "llm"

// Step is one node of a Capability's ExecutionPlan: which kind of engine runs and,
// for the LLM engine, which prompt template the Gateway renders (D6). Δ1 plans have
// exactly one LLM step.
type Step struct {
	Engine EngineKind
	Prompt string // prompt-template id, rendered by the Gateway; no prompt strings in business code
}

// ExecutionPlan is the ordered engine steps a Capability compiles to (Revision 2).
// Δ1 plans are a single LLM step; a slice keeps multi-step / multi-engine plans
// additive for Δ2+.
type ExecutionPlan []Step

// ContextNeed names one grounding input the deterministic Context Construction must
// assemble via a Knowledge Provider (read API, never a DB — D5), keyed by the
// invocation subject.
type ContextNeed string

const (
	// NeedFinding is the subject Finding, read from Governance's read API.
	NeedFinding ContextNeed = "finding"
	// NeedFaultline is the Finding's Faultline enrichment, read from Knowledge's read API.
	NeedFaultline ContextNeed = "faultline"
)

// PrivacyClass classifies the sensitivity of a capability's assembled context (D10).
// Δ1 is local-only, so everything is internal; the field travels for the Δ2
// security/privacy admission step.
type PrivacyClass string

// PrivacyInternal is the default class — routine enrichment, no special handling.
const PrivacyInternal PrivacyClass = "internal"

// RoutingRequirements are the capability's declared needs the (Δ2) router weighs.
// Δ1 has one provider so routing is trivial, but the fields travel for later deltas
// (INT-0062 cost-aware routing).
type RoutingRequirements struct {
	Privacy   PrivacyClass
	LocalOnly bool
}

// Capability is a named AI operation invoked by id (INT-0058). It declares what it
// needs (Needs), how it runs (Plan), and how its output is validated (OutputSchema +
// AllowedStances); provider/model/prompt are hidden behind it.
type Capability struct {
	ID             string
	Version        string
	Needs          []ContextNeed
	Plan           ExecutionPlan
	OutputSchema   string  // JSON Schema for the raw model output (stage-1 validation, D7)
	AllowedStances []Stance // the recommendable subset (stage-2 business rule, D7)
	Routing        RoutingRequirements
}

// Ref is the "id@version" provenance string carried on every Proposal this
// capability produces (D2 · INT-0067).
func (c Capability) Ref() string { return c.ID + "@" + c.Version }

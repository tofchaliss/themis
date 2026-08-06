package domain

// Registry is the in-code Capability catalog (D11). Δ1 holds a single live version
// per capability; DB-backed version sets + evaluation-driven selection arrive in Δ4
// behind this same lookup interface. Callers invoke by id only (INT-0058).
type Registry struct {
	byID map[string]Capability
}

// NewRegistry builds a Registry from the given capabilities, keyed by id. The
// catalog is authored (not user input), so a later duplicate id simply overwrites.
func NewRegistry(caps ...Capability) *Registry {
	byID := make(map[string]Capability, len(caps))
	for _, c := range caps {
		byID[c.ID] = c
	}
	return &Registry{byID: byID}
}

// Lookup returns the live Capability for id, or ok=false if the id is unknown.
func (r *Registry) Lookup(id string) (Capability, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// All returns every registered capability (iteration order is unspecified). Used to
// precompile per-capability validators at Gateway construction.
func (r *Registry) All() []Capability {
	caps := make([]Capability, 0, len(r.byID))
	for _, c := range r.byID {
		caps = append(caps, c)
	}
	return caps
}

// RecommendPositionV1 is the recommend_position capability: AI-assisted affected/not-affected
// triage. It grounds the subject Finding + its Faultline enrichment and runs a two-step
// **[Knowledge → LLM]** plan — the Knowledge engine enriches the grounding with semantically
// similar past Enterprise Positions (best-effort precedent, RC-1), then the LLM reasons over
// the precedent-enriched grounding. It may propose only the recommendable stance subset.
//
// The deterministic version-range step is deliberately absent (EDR-TRUST-01 T5): a provable
// verdict is a computation, not a reasoning task, so it runs in the backend — before AI and
// independently of whether AI is switched on at all. Routing it through here made a
// correctness feature depend on an optional plane, contradicting D13.
func RecommendPositionV1() Capability {
	return Capability{
		ID:      "recommend_position",
		Version: "v1",
		Needs:   []ContextNeed{NeedFinding, NeedFaultline},
		Plan: ExecutionPlan{
			{Engine: EngineKnowledge},
			{Engine: EngineLLM, Prompt: "recommend_position"},
		},
		OutputSchema:   recommendPositionSchema,
		AllowedStances: []Stance{StanceAffected, StanceNotAffected, StanceMitigated},
		Routing:        RoutingRequirements{Privacy: PrivacyInternal, LocalOnly: true},
	}
}

// DefaultRegistry is the Δ1 catalog: just recommend_position@v1.
func DefaultRegistry() *Registry {
	return NewRegistry(RecommendPositionV1())
}

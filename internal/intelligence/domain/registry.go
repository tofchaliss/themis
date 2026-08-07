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
		// Exactly one Finding: it reasons about a single (Release, Faultline) concern.
		SelectionType: SelectionFinding,
		MinSelection:  1,
		MaxSelection:  1,
		Output:        OutputDecision, // its stance aspires to become an Enterprise Position
		Needs:         []ContextNeed{NeedFinding, NeedFaultline},
		Plan: ExecutionPlan{
			{Engine: EngineKnowledge},
			{Engine: EngineLLM, Prompt: "recommend_position"},
		},
		OutputSchema:   recommendPositionSchema,
		AllowedStances: []Stance{StanceAffected, StanceNotAffected, StanceMitigated},
		Routing:        RoutingRequirements{Privacy: PrivacyInternal, LocalOnly: true},
	}
}

// PlanRemediationV1 is the release-scoped remediation planner: given one Release, it explains
// what to fix first and why, over the outstanding Findings in Governance's release posture.
//
// It is an **Information** capability (T7). A plan proposes no stance on any Finding, so nothing
// enters Governance, there is nothing to accept or reject, and the output is ephemeral. That is
// not a limitation — it is what makes a release-scoped capability safe to add: the worst outcome
// of a wrong plan is a human disagreeing with it, never a vulnerability silently suppressed.
//
// The GROUPING is deliberately not the model's job. ReleasePosture.PlanActions collapses the
// Findings into upgrade actions deterministically before the prompt is rendered, because "these
// nine CVEs share one module upgrade" is a GROUP BY, not reasoning (T10). The model is asked for
// the part that genuinely needs judgement: sequencing, trade-offs, and what to say about the
// actions that have no clean fix.
//
// It carries no Knowledge step: precedent retrieval is scoped to past Positions on Findings, and
// a release plan is not a position. Adding it would spend embedding calls on grounding that does
// not apply.
func PlanRemediationV1() Capability {
	return Capability{
		ID:      "plan_remediation",
		Version: "v1",
		// Exactly one Release. The bound doubles as the fan-out guard (T9): a plan spanning
		// several releases is a different capability with a different projection, not this one
		// invoked repeatedly.
		SelectionType: SelectionRelease,
		MinSelection:  1,
		MaxSelection:  1,
		Output:        OutputInformation,
		Needs:         []ContextNeed{NeedReleasePosture},
		Plan: ExecutionPlan{
			{Engine: EngineLLM, Prompt: "plan_remediation"},
		},
		OutputSchema: planRemediationSchema,
		// No stances: an Information Response recommends nothing (T7).
		AllowedStances: nil,
		Routing:        RoutingRequirements{Privacy: PrivacyInternal, LocalOnly: true},
	}
}

// DefaultRegistry is the shipped catalog: recommend_position@v1 (Decision, one Finding) and
// plan_remediation@v1 (Information, one Release).
func DefaultRegistry() *Registry {
	return NewRegistry(RecommendPositionV1(), PlanRemediationV1())
}

package engine

import (
	"context"

	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// RuleEngine is the deterministic, all-Go rule engine (Revision 3 / Δ2). It evaluates a
// RuleSet over the assembled grounding — no provider, no prompt — and returns a certain
// Decision or defers (nil Decision) to the next plan step. It is the "logic-first" step
// the Dispatcher runs before the LLM engine.
type RuleEngine struct {
	rules domain.RuleSet
}

// NewRuleEngine builds a rule engine over the given ordered rules. Δ2 wires the single
// version-range rule; more rules are additive, provided none duplicates Governance.
func NewRuleEngine(rules ...domain.Rule) *RuleEngine {
	return &RuleEngine{rules: domain.RuleSet(rules)}
}

// Kind reports that this is the Rule engine.
func (e *RuleEngine) Kind() domain.EngineKind { return domain.EngineRule }

// Execute runs the rules over the grounding in the ExecInput. A rule decision short-circuits
// the plan (Decision set); no decision defers (Decision nil). It never calls a provider,
// so it carries no provider/model/token provenance.
func (e *RuleEngine) Execute(_ context.Context, in app.ExecInput) (app.EngineResult, error) {
	if d, ok := e.rules.Decide(in.Context); ok {
		return app.EngineResult{Decision: &d}, nil
	}
	return app.EngineResult{}, nil
}

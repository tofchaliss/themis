package app

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// declineRaw is the model honestly saying "can't tell" — the one outcome escalation exists for.
const declineRaw = `{"finding_id":"F1","recommended_stance":"insufficient","confidence":0,` +
	`"evidence":[],"reasoning":"not enough data"}`

// fakeTierRouter answers only Available — the Gateway asks it what exists; the ENGINE does the
// selecting (one place a model is ever chosen), so Select here is never called by the Gateway.
type fakeTierRouter struct{ esc, eco bool }

func (r fakeTierRouter) Select(_ domain.RoutingRequirements, _ ModelTier) (Provider, error) {
	return nil, nil
}

func (r fakeTierRouter) Available(tier ModelTier) bool {
	switch tier {
	case TierPrimary:
		return true
	case TierEscalation:
		return r.esc
	case TierEconomy:
		return r.eco
	}
	return false
}

// tierEngine replies per TIER (not per attempt), recording the order tiers were tried in.
type tierEngine struct {
	byTier map[ModelTier]string
	tokens int
	seen   []ModelTier
}

func (e *tierEngine) Kind() domain.EngineKind { return domain.EngineLLM }

func (e *tierEngine) Execute(_ context.Context, in ExecInput) (EngineResult, error) {
	e.seen = append(e.seen, in.Tier)
	tokens := e.tokens
	if tokens == 0 {
		tokens = 5
	}
	return EngineResult{Raw: e.byTier[in.Tier], Provider: "fakeprov", Model: "model-" + string(in.Tier), TokensUsed: tokens}, nil
}

func tierGateway(t *testing.T, eng Engine, rtr Router, budgetTokens int) *Gateway {
	t.Helper()
	cfg := GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: groundedProjection(),
		Prompt: fakePrompt{}, Engines: []Engine{eng}, Router: rtr,
	}
	if budgetTokens > 0 {
		cfg.BudgetTokens, cfg.BudgetWindow = budgetTokens, time.Hour
	}
	g, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g
}

func invokeRecommend(g *Gateway) (domain.Proposal, Outcome) {
	return g.Invoke(context.Background(), "recommend_position",
		domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
}

// G-AI-2b: the primary's honest decline retries ONCE on the escalation tier, and the bigger
// model's answer stands. Both calls debit — an escalation's cost is real.
func TestInvoke_EscalatesOnceOnInsufficient(t *testing.T) {
	eng := &tierEngine{byTier: map[ModelTier]string{TierPrimary: declineRaw, TierEscalation: okRaw}, tokens: 10}
	g := tierGateway(t, eng, fakeTierRouter{esc: true}, 1000)

	p, oc := invokeRecommend(g)
	if !oc.Produced || oc.Reason != ReasonOK {
		t.Fatalf("outcome = %+v, want the escalation's produced answer", oc)
	}
	if oc.Tier != string(TierEscalation) || oc.Model != "model-escalation" {
		t.Errorf("tier/model = %q/%q, want escalation provenance", oc.Tier, oc.Model)
	}
	if len(eng.seen) != 2 || eng.seen[0] != TierPrimary || eng.seen[1] != TierEscalation {
		t.Errorf("tiers tried = %v, want [primary escalation]", eng.seen)
	}
	if got := g.budget.Remaining(g.now()); got != 1000-20 {
		t.Errorf("budget remaining = %d, want both tiers debited (980)", got)
	}
	if p.Capability == "" || p.Metadata.Model != "model-escalation" {
		t.Errorf("proposal = %+v, want a real proposal carrying the escalation model's provenance", p.Metadata)
	}
}

// The bigger model could not tell either: the final outcome is still the honest insufficient,
// but its telemetry now SAYS both tiers tried — the distinction G-AI-2 needs observable.
func TestInvoke_EscalationAlsoInsufficient(t *testing.T) {
	eng := &tierEngine{byTier: map[ModelTier]string{TierPrimary: declineRaw, TierEscalation: declineRaw}}
	g := tierGateway(t, eng, fakeTierRouter{esc: true}, 0)

	_, oc := invokeRecommend(g)
	if oc.Produced || oc.Reason != ReasonInsufficient || oc.DecidedBy != "llm:insufficient" {
		t.Fatalf("outcome = %+v, want insufficient", oc)
	}
	if oc.Tier != string(TierEscalation) || len(eng.seen) != 2 {
		t.Errorf("tier = %q after %v, want the escalation recorded as the last word", oc.Tier, eng.seen)
	}
}

// No distinct escalation model → no second call: an honest decline stays a one-call outcome.
func TestInvoke_NoEscalationWithoutTheTier(t *testing.T) {
	eng := &tierEngine{byTier: map[ModelTier]string{TierPrimary: declineRaw}}
	g := tierGateway(t, eng, fakeTierRouter{esc: false}, 0)

	_, oc := invokeRecommend(g)
	if oc.Reason != ReasonInsufficient || oc.Tier != string(TierPrimary) || len(eng.seen) != 1 {
		t.Errorf("outcome = %+v after %v, want a single primary decline", oc, eng.seen)
	}
}

// An exhausted window stops the escalation: the primary's call spent the budget, so the
// decline stands rather than borrowing tokens the window no longer has.
func TestInvoke_BudgetStopsEscalation(t *testing.T) {
	eng := &tierEngine{byTier: map[ModelTier]string{TierPrimary: declineRaw, TierEscalation: okRaw}, tokens: 50}
	g := tierGateway(t, eng, fakeTierRouter{esc: true}, 50) // the first call consumes it all

	_, oc := invokeRecommend(g)
	if oc.Reason != ReasonInsufficient || len(eng.seen) != 1 {
		t.Errorf("outcome = %+v after %v, want the decline to stand unescalated", oc, eng.seen)
	}
}

// G-AI-4 degrade-not-fail: with the window nearly spent and an economy model available, the
// invocation routes there — spend shrinks before it stops. Full exhaustion still refuses.
func TestInvoke_DegradesToEconomyOnLowBudget(t *testing.T) {
	eng := &tierEngine{byTier: map[ModelTier]string{TierPrimary: okRaw, TierEconomy: okRaw}, tokens: 85}
	g := tierGateway(t, eng, fakeTierRouter{eco: true}, 100)

	// First invocation: budget full → primary. Spends 85 of 100.
	_, oc := invokeRecommend(g)
	if oc.Tier != string(TierPrimary) {
		t.Fatalf("first invocation tier = %q, want primary", oc.Tier)
	}
	// Second: remaining 15 < 20% of 100 → economy.
	_, oc = invokeRecommend(g)
	if !oc.Produced || oc.Tier != string(TierEconomy) || oc.Model != "model-economy" {
		t.Fatalf("low-budget outcome = %+v, want the economy tier producing", oc)
	}
	// Third: remaining is negative (spent 170 of 100) → exhaustion still refuses.
	_, oc = invokeRecommend(g)
	if oc.Reason != ReasonBudgetExhausted {
		t.Errorf("exhausted outcome = %+v, want budget_exhausted — degrade never removes the ceiling", oc)
	}
}

// A degraded invocation that declines does NOT escalate: climbing to the largest model from
// inside a nearly-spent window would defeat the reason the invocation was degraded at all.
func TestInvoke_DegradedDeclineDoesNotEscalate(t *testing.T) {
	eng := &tierEngine{byTier: map[ModelTier]string{TierPrimary: okRaw, TierEconomy: declineRaw, TierEscalation: okRaw}, tokens: 85}
	g := tierGateway(t, eng, fakeTierRouter{esc: true, eco: true}, 100)

	_, _ = invokeRecommend(g) // spend down to 15 remaining
	_, oc := invokeRecommend(g)
	if oc.Reason != ReasonInsufficient || oc.Tier != string(TierEconomy) || len(eng.seen) != 2 {
		t.Errorf("outcome = %+v after %v, want the economy decline to stand", oc, eng.seen)
	}
}

func TestBudgetLimit(t *testing.T) {
	if got := NewBudget(100, time.Hour).Limit(); got != 100 {
		t.Errorf("Limit = %d, want 100", got)
	}
	if got := NewBudget(0, 0).Limit(); got != 0 {
		t.Errorf("unlimited Limit = %d, want 0", got)
	}
	var b *Budget
	if got := b.Limit(); got != 0 {
		t.Errorf("nil Limit = %d, want 0", got)
	}
}

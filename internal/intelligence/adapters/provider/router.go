package provider

import (
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// TieredRouter binds the Gateway's runtime tier decisions to concrete providers
// (D6 · INT-0062, phase3-intelligence-router): a mandatory primary, plus optional
// escalation (larger — G-AI-2b) and economy (smaller — G-AI-4 degrade-not-fail)
// providers. It replaces the Δ1 StaticRouter; a single-model deployment simply
// configures no optional tiers and behaves identically.
type TieredRouter struct {
	primary    app.Provider
	escalation app.Provider // nil = tier unconfigured
	economy    app.Provider // nil = tier unconfigured
}

// NewTieredRouter builds the router. escalation/economy may be nil. A tier provider
// whose model equals the primary's is treated as UNCONFIGURED: escalating or degrading
// to the same model is a spend with nothing to show for it, and silently honoring the
// misconfiguration would make both behaviours look broken ("it escalated and nothing
// changed").
func NewTieredRouter(primary, escalation, economy app.Provider) *TieredRouter {
	if escalation != nil && escalation.Model() == primary.Model() {
		escalation = nil
	}
	if economy != nil && economy.Model() == primary.Model() {
		economy = nil
	}
	return &TieredRouter{primary: primary, escalation: escalation, economy: economy}
}

// Select returns the tier's provider, falling back to the primary for an unconfigured
// (or unknown) tier — a mis-threaded tier must never fail an invocation.
func (r *TieredRouter) Select(_ domain.RoutingRequirements, tier app.ModelTier) (app.Provider, error) {
	switch tier {
	case app.TierEscalation:
		if r.escalation != nil {
			return r.escalation, nil
		}
	case app.TierEconomy:
		if r.economy != nil {
			return r.economy, nil
		}
	}
	return r.primary, nil
}

// Available reports whether a DISTINCT model backs the tier — the question the Gateway
// asks before deciding an escalation or degrade is worth spending anything on. The
// primary is always available.
func (r *TieredRouter) Available(tier app.ModelTier) bool {
	switch tier {
	case app.TierPrimary:
		return true
	case app.TierEscalation:
		return r.escalation != nil
	case app.TierEconomy:
		return r.economy != nil
	default:
		return false
	}
}

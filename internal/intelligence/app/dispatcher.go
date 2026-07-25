package app

import "github.com/themis-project/themis/internal/intelligence/domain"

// Dispatcher is the typed Engine Dispatcher (Revision 3 / Δ2): it routes an execution
// plan step to the engine registered for the step's kind (Rule, LLM). It holds no
// policy — the Gateway walks the plan and interprets each engine's result; the
// Dispatcher only resolves kind → engine. Adding an engine kind is one registration.
type Dispatcher struct {
	engines map[domain.EngineKind]Engine
}

// NewDispatcher indexes the given engines by their Kind. A later engine of the same
// kind overwrites an earlier one (the wiring is authored, not user input).
func NewDispatcher(engines ...Engine) *Dispatcher {
	m := make(map[domain.EngineKind]Engine, len(engines))
	for _, e := range engines {
		m[e.Kind()] = e
	}
	return &Dispatcher{engines: m}
}

// For returns the engine registered for kind, or ok=false when no engine of that kind
// is wired (a plan referencing an unwired engine is a composition error the Gateway
// surfaces as a no-proposal).
func (d *Dispatcher) For(kind domain.EngineKind) (Engine, bool) {
	e, ok := d.engines[kind]
	return e, ok
}

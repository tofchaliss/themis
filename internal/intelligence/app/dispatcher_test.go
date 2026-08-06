package app

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

type kindEngine struct{ kind domain.EngineKind }

func (e kindEngine) Kind() domain.EngineKind { return e.kind }
func (e kindEngine) Execute(context.Context, ExecInput) (EngineResult, error) {
	return EngineResult{}, nil
}

func TestDispatcherRoutesByKind(t *testing.T) {
	knowledge := kindEngine{kind: domain.EngineKnowledge}
	llm := kindEngine{kind: domain.EngineLLM}
	d := NewDispatcher(knowledge, llm)

	if got, ok := d.For(domain.EngineKnowledge); !ok || got != knowledge {
		t.Errorf("For(knowledge) = %v, %v; want the knowledge engine", got, ok)
	}
	if got, ok := d.For(domain.EngineLLM); !ok || got != llm {
		t.Errorf("For(llm) = %v, %v; want the llm engine", got, ok)
	}
	// A kind nothing registered — including "rule", which the runtime no longer has at all
	// now that provable verdicts run in the backend (EDR-TRUST-01 T5).
	if _, ok := d.For(domain.EngineKind("rule")); ok {
		t.Error("For(unwired kind) should return ok=false")
	}
}

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
	rule := kindEngine{kind: domain.EngineRule}
	llm := kindEngine{kind: domain.EngineLLM}
	d := NewDispatcher(rule, llm)

	if got, ok := d.For(domain.EngineRule); !ok || got != rule {
		t.Errorf("For(rule) = %v, %v; want the rule engine", got, ok)
	}
	if got, ok := d.For(domain.EngineLLM); !ok || got != llm {
		t.Errorf("For(llm) = %v, %v; want the llm engine", got, ok)
	}
	if _, ok := d.For(domain.EngineKind("knowledge")); ok {
		t.Error("For(unwired kind) should return ok=false")
	}
}

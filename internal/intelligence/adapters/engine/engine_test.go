package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

type fakeProvider struct {
	text string
	err  error
}

func (f fakeProvider) Complete(_ context.Context, _ app.CompletionRequest) (app.CompletionResult, error) {
	if f.err != nil {
		return app.CompletionResult{}, f.err
	}
	return app.CompletionResult{Text: f.text, TokensUsed: 7}, nil
}
func (f fakeProvider) Name() string  { return "fakeprov" }
func (f fakeProvider) Model() string { return "fakemodel" }

type fakeRouter struct {
	provider app.Provider
	err      error
}

func (r fakeRouter) Select(_ domain.RoutingRequirements) (app.Provider, error) {
	return r.provider, r.err
}

func TestLLMEngineKind(t *testing.T) {
	e := NewLLMEngine(fakeRouter{provider: fakeProvider{}})
	if e.Kind() != domain.EngineLLM {
		t.Errorf("Kind = %q, want llm", e.Kind())
	}
}

func TestLLMEngineExecuteHappy(t *testing.T) {
	e := NewLLMEngine(fakeRouter{provider: fakeProvider{text: "raw-output"}})
	res, err := e.Execute(context.Background(), app.ExecInput{Prompt: "p", Temperature: 0})
	if err != nil {
		t.Fatalf("Execute err: %v", err)
	}
	if res.Raw != "raw-output" || res.Provider != "fakeprov" || res.Model != "fakemodel" || res.TokensUsed != 7 {
		t.Errorf("unexpected result %+v", res)
	}
}

func TestLLMEngineExecuteRouterError(t *testing.T) {
	e := NewLLMEngine(fakeRouter{err: errors.New("no provider")})
	if _, err := e.Execute(context.Background(), app.ExecInput{}); err == nil {
		t.Error("expected router error")
	}
}

func TestLLMEngineExecuteProviderError(t *testing.T) {
	e := NewLLMEngine(fakeRouter{provider: fakeProvider{err: errors.New("model down")}})
	if _, err := e.Execute(context.Background(), app.ExecInput{Prompt: "p"}); err == nil {
		t.Error("expected provider error")
	}
}

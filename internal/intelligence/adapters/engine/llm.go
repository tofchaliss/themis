// Package engine holds the Intelligence Gateway's engines behind the app.Engine port
// (Revision 2). Δ1 ships one LLM engine and no dispatcher; the Rule and Knowledge
// engines arrive in later deltas behind this same port.
package engine

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// LLMEngine is the generative-model engine. It routes to a Provider (Δ1: trivial,
// one provider) and runs the rendered prompt, returning the raw model output for
// validation. It holds no prompt strings — the prompt arrives already rendered.
type LLMEngine struct {
	router app.Router
}

// NewLLMEngine binds the engine to a router.
func NewLLMEngine(r app.Router) *LLMEngine { return &LLMEngine{router: r} }

// Kind reports that this is the LLM engine.
func (e *LLMEngine) Kind() domain.EngineKind { return domain.EngineLLM }

// Execute routes to a provider and runs the rendered prompt, returning the raw
// output plus provenance.
func (e *LLMEngine) Execute(ctx context.Context, in app.ExecInput) (app.EngineResult, error) {
	p, err := e.router.Select(in.Routing)
	if err != nil {
		return app.EngineResult{}, fmt.Errorf("llm engine: route: %w", err)
	}
	res, err := p.Complete(ctx, app.CompletionRequest{
		Prompt:      in.Prompt,
		Temperature: in.Temperature,
		JSONSchema:  in.JSONSchema,
	})
	if err != nil {
		return app.EngineResult{}, fmt.Errorf("llm engine: complete: %w", err)
	}
	return app.EngineResult{
		Raw:        res.Text,
		Provider:   p.Name(),
		Model:      p.Model(),
		TokensUsed: res.TokensUsed,
	}, nil
}

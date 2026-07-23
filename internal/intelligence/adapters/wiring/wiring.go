// Package wiring is the Intelligence Gateway's composition root (Δ1): it assembles
// the stateless reactive Gateway from config — read-API Knowledge Providers, the LLM
// engine over its provider (Ollama by default, a dev fake optionally), the prompt
// renderer, and the reactive HTTP API.
package wiring

import (
	"net/http"

	intelhttp "github.com/themis-project/themis/internal/intelligence/adapters/http"
	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Config wires the Gateway's dependencies from the node configuration.
type Config struct {
	GovernanceURL string // Governance read-API base URL (Finding grounding)
	KnowledgeURL  string // Knowledge read-API base URL (Faultline grounding)
	OllamaURL     string // Ollama base URL (OpenAI-compatible)
	Model         string // pinned model, e.g. "llama3.1:8b"
	UseFake       bool   // dev/CI: use the deterministic fake provider (no model)
	Logger        *observability.Logger
	HTTPClient    *http.Client
}

// Intelligence is the wired Gateway surface.
type Intelligence struct {
	Handler http.Handler // the reactive invoke API (mount under /api/v1)
	Gateway *app.Gateway
}

// Wire assembles the stateless Gateway. It returns an error only if a capability's
// output schema fails to compile (a programming error).
func Wire(cfg Config) (Intelligence, error) {
	fr := readapi.NewFindingClient(cfg.GovernanceURL, cfg.HTTPClient)
	flr := readapi.NewFaultlineClient(cfg.KnowledgeURL, cfg.HTTPClient)

	var prov app.Provider
	if cfg.UseFake {
		prov = provider.NewFakeProvider(
			`{"finding_id":"","recommended_stance":"not_affected","confidence":0,"evidence":[],"reasoning":"dev fake provider"}`)
	} else {
		prov = provider.NewOllamaProvider(cfg.OllamaURL, cfg.Model, cfg.HTTPClient)
	}
	eng := engine.NewLLMEngine(provider.NewStaticRouter(prov))

	pr, err := engine.NewPromptRenderer()
	if err != nil {
		return Intelligence{}, err
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:  domain.DefaultRegistry(),
		Finding:   fr,
		Faultline: flr,
		Prompt:    pr,
		Engine:    eng,
	})
	if err != nil {
		return Intelligence{}, err
	}
	return Intelligence{
		Handler: intelhttp.NewHandler(gw, cfg.Logger).Routes(),
		Gateway: gw,
	}, nil
}

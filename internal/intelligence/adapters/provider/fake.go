// Package provider holds the Intelligence Gateway's concrete model backends behind
// the app.Provider port (INT-0070): the Ollama provider (OpenAI-compatible HTTP) and
// a deterministic fake for CI, plus the Δ1 static router. All provider-specific code
// is confined here; a provider swap never touches the domain or app rings.
package provider

import (
	"context"

	"github.com/themis-project/themis/internal/intelligence/app"
)

// FakeProvider is a deterministic Provider for CI and tests (Revision 2): it returns
// a pre-set response with no model call, so the whole Gateway pipeline is provable
// end-to-end without a running Ollama.
type FakeProvider struct {
	Response string
	Tokens   int
	Err      error
}

// NewFakeProvider returns a fake that always replies with response.
func NewFakeProvider(response string) *FakeProvider {
	return &FakeProvider{Response: response, Tokens: 1}
}

// Complete returns the fake's configured response (or its configured error).
func (f *FakeProvider) Complete(_ context.Context, _ app.CompletionRequest) (app.CompletionResult, error) {
	if f.Err != nil {
		return app.CompletionResult{}, f.Err
	}
	return app.CompletionResult{Text: f.Response, TokensUsed: f.Tokens}, nil
}

// Name identifies the provider for telemetry.
func (f *FakeProvider) Name() string { return "fake" }

// Model identifies the model for telemetry.
func (f *FakeProvider) Model() string { return "fake" }

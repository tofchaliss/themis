package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/themis-project/themis/internal/intelligence/app"
)

// OllamaProvider calls a local (or in-cluster) Ollama server over its
// OpenAI-compatible chat-completions endpoint (Revision 2). Speaking the
// OpenAI-compatible schema means the same adapter targets Ollama and any other
// OpenAI-compatible server by config — the runtime is swappable without code change.
type OllamaProvider struct {
	baseURL string
	model   string
	http    *http.Client
}

// NewOllamaProvider returns a provider that posts to baseURL (e.g.
// "http://localhost:11434") using model (e.g. "llama3.1:8b"). hc may be nil.
func NewOllamaProvider(baseURL, model string, hc *http.Client) *OllamaProvider {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &OllamaProvider{baseURL: baseURL, model: model, http: hc}
}

// Name identifies the provider for telemetry.
func (p *OllamaProvider) Name() string { return "ollama" }

// Model identifies the pinned model for telemetry.
func (p *OllamaProvider) Model() string { return p.model }

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponseFormat struct {
	Type string `json:"type"`
}

type openAIRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIMessage       `json:"messages"`
	Temperature    float64               `json:"temperature"`
	Stream         bool                  `json:"stream"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

// Complete sends the rendered prompt as a single user message and returns the raw
// assistant content. When a JSONSchema is supplied it requests JSON-object output so
// the model is constrained to emit valid JSON (stage-1 validation checks the shape).
func (p *OllamaProvider) Complete(ctx context.Context, req app.CompletionRequest) (app.CompletionResult, error) {
	body := openAIRequest{
		Model:       p.model,
		Messages:    []openAIMessage{{Role: "user", Content: req.Prompt}},
		Temperature: req.Temperature,
		Stream:      false,
	}
	if req.JSONSchema != "" {
		body.ResponseFormat = &openAIResponseFormat{Type: "json_object"}
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(httpReq)
	if err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return app.CompletionResult{}, fmt.Errorf("ollama: status %d: %s", resp.StatusCode, string(data))
	}

	var parsed openAIResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return app.CompletionResult{}, fmt.Errorf("ollama: no choices in response")
	}
	return app.CompletionResult{
		Text:       parsed.Choices[0].Message.Content,
		TokensUsed: parsed.Usage.TotalTokens,
	}, nil
}

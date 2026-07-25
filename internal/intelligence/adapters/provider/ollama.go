package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/intelligence/app"
)

// OllamaProvider calls a local (or in-cluster) Ollama server over its
// OpenAI-compatible chat-completions endpoint (Revision 2). Speaking the
// OpenAI-compatible schema means the same adapter targets Ollama and any other
// OpenAI-compatible server by config — the runtime is swappable without code change.
type OllamaProvider struct {
	baseURL        string
	model          string
	apiKey         string
	responseFormat string // "", "json_object" (Ollama default), "json_schema" (LM Studio/OpenAI), "text", "none"
	http           *http.Client
}

// NewOllamaProvider returns a provider that posts to baseURL (e.g.
// "http://localhost:11434") using model (e.g. "llama3.1:8b"). hc may be nil.
func NewOllamaProvider(baseURL, model string, hc *http.Client) *OllamaProvider {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &OllamaProvider{baseURL: baseURL, model: model, http: hc}
}

// WithAPIKey sets an optional bearer token sent as `Authorization: Bearer <key>` — needed
// by OpenAI-compatible servers that require auth (OpenAI, LM Studio with "Require API Key",
// vLLM with a key). An empty key sends no header (Ollama's default needs none). Fluent.
func (p *OllamaProvider) WithAPIKey(key string) *OllamaProvider {
	p.apiKey = key
	return p
}

// WithResponseFormat selects how structured output is requested (OpenAI-compatible servers
// diverge): "" / "json_object" = Ollama's default; "json_schema" = strict schema output
// (LM Studio, OpenAI); "text" = no constraint; "none" = omit the field. Fluent.
func (p *OllamaProvider) WithResponseFormat(mode string) *OllamaProvider {
	p.responseFormat = mode
	return p
}

// responseFormatFor builds the response_format for the capability's schema per the
// configured mode. No schema → no format.
func (p *OllamaProvider) responseFormatFor(schema string) *openAIResponseFormat {
	if schema == "" {
		return nil
	}
	switch p.responseFormat {
	case "none", "off":
		return nil
	case "text":
		return &openAIResponseFormat{Type: "text"}
	case "json_schema":
		return &openAIResponseFormat{Type: "json_schema",
			JSONSchema: &jsonSchemaSpec{Name: "output", Schema: json.RawMessage(schema)}}
	default: // "" or "json_object"
		return &openAIResponseFormat{Type: "json_object"}
	}
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
	Type       string          `json:"type"`
	JSONSchema *jsonSchemaSpec `json:"json_schema,omitempty"`
}

type jsonSchemaSpec struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
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
	body.ResponseFormat = p.responseFormatFor(req.JSONSchema)

	buf, err := json.Marshal(body)
	if err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return app.CompletionResult{}, fmt.Errorf("ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

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
		Text:       stripCodeFences(parsed.Choices[0].Message.Content),
		TokensUsed: parsed.Usage.TotalTokens,
	}, nil
}

// stripCodeFences unwraps a ```json … ``` (or bare ``` … ```) markdown fence some models
// wrap JSON in, so stage-1 parsing sees raw JSON. Unfenced text is returned unchanged.
func stripCodeFences(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "```") {
		return s
	}
	t = strings.TrimPrefix(t, "```")
	if i := strings.IndexByte(t, '\n'); i >= 0 {
		if first := strings.TrimSpace(t[:i]); !strings.ContainsAny(first, "{[\"") {
			t = t[i+1:] // drop a leading language tag line like "json"
		}
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(t), "```"))
}

// Package embed holds the Intelligence Gateway's concrete embedding backends behind the
// app.Embedder port (Δ3a): an Ollama embedder over the OpenAI-compatible /v1/embeddings
// endpoint (so the same adapter targets Ollama, LM Studio, vLLM, or OpenAI by config) and a
// deterministic feature-hashing fake for CI. All embedding-provider code is confined here; a
// backend swap never touches the domain or app rings.
package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/themis-project/themis/internal/intelligence/app"
)

var _ app.Embedder = (*OllamaEmbedder)(nil)

// OllamaEmbedder calls a local (or in-cluster) OpenAI-compatible server's embeddings endpoint
// to turn text into a dense vector. Speaking the OpenAI-compatible schema means one adapter
// targets Ollama (nomic-embed-text), LM Studio, vLLM, or OpenAI — the runtime is swappable by
// config, no code change.
type OllamaEmbedder struct {
	baseURL string
	model   string
	apiKey  string
	http    *http.Client
}

// NewOllamaEmbedder returns an embedder that posts to baseURL (e.g. "http://localhost:11434")
// using model (e.g. "nomic-embed-text"). hc may be nil.
func NewOllamaEmbedder(baseURL, model string, hc *http.Client) *OllamaEmbedder {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &OllamaEmbedder{baseURL: baseURL, model: model, http: hc}
}

// WithAPIKey sets an optional bearer token sent as `Authorization: Bearer <key>` — needed by
// OpenAI-compatible servers that require auth. An empty key sends no header (Ollama's default
// needs none). Fluent.
func (e *OllamaEmbedder) WithAPIKey(key string) *OllamaEmbedder {
	e.apiKey = key
	return e
}

// Model identifies the embedding model for telemetry and index model-stamping (R6).
func (e *OllamaEmbedder) Model() string { return e.model }

type embeddingsRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingsResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// Embed returns the dense vector for text. A non-200 response, an empty body, or a response
// carrying no embedding is an error — the caller degrades gracefully (population skips the
// row; retrieval falls back to no precedent), never persists a bad vector.
func (e *OllamaEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	buf, err := json.Marshal(embeddingsRequest{Model: e.model, Input: text})
	if err != nil {
		return nil, fmt.Errorf("embed: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/v1/embeddings", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("embed: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("embed: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("embed: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embed: status %d: %s", resp.StatusCode, string(data))
	}

	var parsed embeddingsResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("embed: decode response: %w", err)
	}
	if len(parsed.Data) == 0 || len(parsed.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embed: empty embedding in response")
	}
	return parsed.Data[0].Embedding, nil
}

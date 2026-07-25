package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

func TestFakeProvider(t *testing.T) {
	f := NewFakeProvider("hello")
	res, err := f.Complete(context.Background(), app.CompletionRequest{})
	if err != nil {
		t.Fatalf("Complete err: %v", err)
	}
	if res.Text != "hello" || res.TokensUsed != 1 {
		t.Errorf("unexpected result %+v", res)
	}
	if f.Name() != "fake" || f.Model() != "fake" {
		t.Errorf("name/model = %s/%s", f.Name(), f.Model())
	}

	f.Err = errors.New("boom")
	if _, err := f.Complete(context.Background(), app.CompletionRequest{}); err == nil {
		t.Error("expected error when Err set")
	}
}

func TestStaticRouter(t *testing.T) {
	f := NewFakeProvider("x")
	r := NewStaticRouter(f)
	p, err := r.Select(domain.RoutingRequirements{LocalOnly: true})
	if err != nil {
		t.Fatalf("Select err: %v", err)
	}
	if p != f {
		t.Error("router must return the single configured provider")
	}
}

func TestOllamaProviderHappy(t *testing.T) {
	const content = `{"finding_id":"F1","recommended_stance":"affected"}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":` +
			mustJSONString(content) + `}}],"usage":{"total_tokens":42}}`))
	}))
	defer srv.Close()

	p := NewOllamaProvider(srv.URL, "llama3.1:8b", srv.Client())
	res, err := p.Complete(context.Background(), app.CompletionRequest{Prompt: "hi", JSONSchema: "{}"})
	if err != nil {
		t.Fatalf("Complete err: %v", err)
	}
	if res.Text != content || res.TokensUsed != 42 {
		t.Errorf("unexpected result %+v", res)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %s, want /v1/chat/completions", gotPath)
	}
	if p.Name() != "ollama" || p.Model() != "llama3.1:8b" {
		t.Errorf("name/model = %s/%s", p.Name(), p.Model())
	}
}

func TestOllamaProviderAPIKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"}}],"usage":{"total_tokens":1}}`))
	}))
	defer srv.Close()

	// With a key → Authorization: Bearer <key> (OpenAI / LM Studio / vLLM auth).
	p := NewOllamaProvider(srv.URL, "m", srv.Client()).WithAPIKey("sk-secret")
	if _, err := p.Complete(context.Background(), app.CompletionRequest{Prompt: "hi"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotAuth != "Bearer sk-secret" {
		t.Errorf("Authorization = %q, want Bearer sk-secret", gotAuth)
	}

	// Without a key → no Authorization header (Ollama's default needs none).
	gotAuth = "sentinel"
	if _, err := NewOllamaProvider(srv.URL, "m", srv.Client()).Complete(context.Background(), app.CompletionRequest{Prompt: "hi"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("no key must send no Authorization header, got %q", gotAuth)
	}
}

func TestOllamaResponseFormat(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"}}],"usage":{"total_tokens":1}}`))
	}))
	defer srv.Close()

	rf := func(mode string, schema string) map[string]any {
		p := NewOllamaProvider(srv.URL, "m", srv.Client()).WithResponseFormat(mode)
		if _, err := p.Complete(context.Background(), app.CompletionRequest{Prompt: "hi", JSONSchema: schema}); err != nil {
			t.Fatalf("Complete(%q): %v", mode, err)
		}
		if gotBody["response_format"] == nil {
			return nil
		}
		return gotBody["response_format"].(map[string]any)
	}
	const schema = `{"type":"object"}`

	if got := rf("", schema); got == nil || got["type"] != "json_object" {
		t.Errorf(`default → %v, want json_object`, got)
	}
	if got := rf("json_object", schema); got["type"] != "json_object" {
		t.Errorf("json_object → %v", got)
	}
	if got := rf("json_schema", schema); got == nil || got["type"] != "json_schema" || got["json_schema"] == nil {
		t.Errorf("json_schema → %v, want type json_schema + schema", got)
	}
	if got := rf("text", schema); got["type"] != "text" {
		t.Errorf("text → %v", got)
	}
	if got := rf("none", schema); got != nil {
		t.Errorf("none → %v, want omitted", got)
	}
	if got := rf("json_object", ""); got != nil {
		t.Errorf("no schema must omit response_format, got %v", got)
	}
}

func TestStripCodeFences(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"a\":1}\n```": `{"a":1}`, // language tag dropped
		"```\n{\"a\":1}\n```":     `{"a":1}`, // bare fence
		"```{\"a\":1}\n```":       `{"a":1}`, // first line already content → not dropped
		`{"a":1}`:                 `{"a":1}`, // unfenced → unchanged
	}
	for in, want := range cases {
		if got := stripCodeFences(in); got != want {
			t.Errorf("stripCodeFences(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOllamaProviderErrors(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		baseURL string // when set, no server is used (transport-level failure)
	}{
		{name: "non-200", status: 500, body: "upstream boom"},
		{name: "bad-json", status: 200, body: "{not json"},
		{name: "no-choices", status: 200, body: `{"choices":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			p := NewOllamaProvider(srv.URL, "m", srv.Client())
			if _, err := p.Complete(context.Background(), app.CompletionRequest{Prompt: "x"}); err == nil {
				t.Error("expected error")
			}
		})
	}

	t.Run("build-request-error", func(t *testing.T) {
		p := NewOllamaProvider("http://exa\x00mple", "m", nil) // control char → url parse error
		if _, err := p.Complete(context.Background(), app.CompletionRequest{}); err == nil {
			t.Error("expected build-request error")
		}
	})

	t.Run("transport-error", func(t *testing.T) {
		p := NewOllamaProvider("http://127.0.0.1:1", "m", &http.Client{}) // refused
		if _, err := p.Complete(context.Background(), app.CompletionRequest{}); err == nil {
			t.Error("expected transport error")
		}
	})
}

// mustJSONString quotes s as a JSON string literal for embedding in a response body.
func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

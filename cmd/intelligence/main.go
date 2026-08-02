// Command intelligence runs the Intelligence Gateway as an independent service
// (EDR-INTELLIGENCE-01 D3/D12, Revision 2 · Δ1): the reactive AI-enrichment surface.
// It serves the synchronous invoke API (POST /api/v1/capabilities/{id}/invoke),
// grounding each capability via the Governance + Knowledge read APIs and running one
// LLM engine over Ollama. It is STATELESS — no datastore — and part of the optional
// AI plane (deployed only when AI is enabled; when disabled, Governance simply never
// calls it). Composition lives in internal/intelligence/adapters/wiring.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/intelligence/adapters/wiring"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment; every option is documented here (the
// self-documented-config convention, R2) and in deploy/node.env.example.
type config struct {
	addr          string // THEMIS_INTELLIGENCE_ADDR — listen address (default ":8086").
	governanceURL string // THEMIS_GOVERNANCE_URL — Governance read-API base URL.
	knowledgeURL  string // THEMIS_KNOWLEDGE_URL — Knowledge read-API base URL.
	ollamaURL     string // THEMIS_OLLAMA_URL — Ollama (OpenAI-compatible) base URL.
	model         string // THEMIS_INTELLIGENCE_MODEL — pinned model (default "llama3.1:8b").
	useFake       bool   // THEMIS_INTELLIGENCE_PROVIDER=fake — dev/CI provider (no model).
	apiKey        string // THEMIS_LLM_API_KEY — optional bearer token for an authenticated server.
	respFormat    string // THEMIS_LLM_RESPONSE_FORMAT — structured-output mode (json_object|json_schema|text|none).
	llmTimeout    time.Duration // THEMIS_LLM_TIMEOUT — provider HTTP client timeout (Go duration, default 60s). Raise for a slower/larger local model whose grounded recommend exceeds 60s (else the call aborts with provider_error → an "insufficient" 204).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		addr:          envDefault("THEMIS_INTELLIGENCE_ADDR", ":8086"),
		governanceURL: envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		knowledgeURL:  envDefault("THEMIS_KNOWLEDGE_URL", "http://localhost:8085"),
		ollamaURL:     envDefault("THEMIS_OLLAMA_URL", "http://localhost:11434"),
		model:         envDefault("THEMIS_INTELLIGENCE_MODEL", "llama3.1:8b"),
		useFake:       os.Getenv("THEMIS_INTELLIGENCE_PROVIDER") == "fake",
		apiKey:        os.Getenv("THEMIS_LLM_API_KEY"),
		respFormat:    os.Getenv("THEMIS_LLM_RESPONSE_FORMAT"),
		llmTimeout:    envDurationDefault("THEMIS_LLM_TIMEOUT", 60*time.Second),

		authDSN:      os.Getenv("THEMIS_AUTH_DATABASE_DSN"),
		authRequired: os.Getenv("THEMIS_AUTH_REQUIRED") == "1",
	}
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("intelligence"))
	if err != nil {
		log.Fatalf("intelligence: observability: %v", err)
	}
	defer func() { _ = shutdownObs(context.Background()); _ = logger.Sync() }()

	intel, err := wiring.Wire(wiring.Config{
		GovernanceURL:  cfg.governanceURL,
		KnowledgeURL:   cfg.knowledgeURL,
		OllamaURL:      cfg.ollamaURL,
		Model:          cfg.model,
		UseFake:        cfg.useFake,
		APIKey:         cfg.apiKey,
		ResponseFormat: cfg.respFormat,
		Logger:         logger,
		HTTPClient:     &http.Client{Timeout: cfg.llmTimeout},
	})
	if err != nil {
		logger.Error("wire failed", observability.Err(err))
		os.Exit(1)
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	closeAuth := authedMount(ctx, router, cfg, logger, intel.Handler)
	defer closeAuth()

	logger.Info("listening",
		observability.String("addr", cfg.addr),
		observability.Bool("fake_provider", cfg.useFake),
		observability.String("model", cfg.model))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// authedMount mounts the API under the authenticated group when THEMIS_AUTH_DATABASE_DSN is
// set (RequireAPIKey then the method-based RequireWriteScope — EDR-SECURITY-01 D1/D4);
// otherwise it mounts open with a warning (single-context dev). THEMIS_AUTH_REQUIRED=1
// hard-fails when the DSN is unset so a production node can never boot open. The returned
// cleanup closes the auth pool (a no-op when auth is disabled).
func authedMount(ctx context.Context, router chi.Router, cfg config, logger *observability.Logger, handler http.Handler) func() {
	if cfg.authDSN == "" {
		if cfg.authRequired {
			logger.Error("startup aborted: THEMIS_AUTH_REQUIRED=1 but THEMIS_AUTH_DATABASE_DSN is empty")
			os.Exit(1)
		}
		logger.Warn("AUTH DISABLED — set THEMIS_AUTH_DATABASE_DSN to require X-API-Key (dev only)")
		router.Mount("/api/v1", handler)
		return func() {}
	}
	authn, closeAuth, err := auth.Open(ctx, cfg.authDSN)
	if err != nil {
		logger.Error("auth store failed", observability.Err(err))
		os.Exit(1)
	}
	router.Group(func(r chi.Router) {
		r.Use(authn.RequireAPIKey)
		r.Use(auth.RequireWriteScope)
		r.Mount("/api/v1", handler)
	})
	logger.Info("API-key auth enabled (X-API-Key)")
	return closeAuth
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDurationDefault parses a Go duration from key, falling back to def when unset or unparseable.
func envDurationDefault(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

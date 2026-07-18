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
}

func loadConfig() config {
	return config{
		addr:          envDefault("THEMIS_INTELLIGENCE_ADDR", ":8086"),
		governanceURL: envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		knowledgeURL:  envDefault("THEMIS_KNOWLEDGE_URL", "http://localhost:8085"),
		ollamaURL:     envDefault("THEMIS_OLLAMA_URL", "http://localhost:11434"),
		model:         envDefault("THEMIS_INTELLIGENCE_MODEL", "llama3.1:8b"),
		useFake:       os.Getenv("THEMIS_INTELLIGENCE_PROVIDER") == "fake",
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
		GovernanceURL: cfg.governanceURL,
		KnowledgeURL:  cfg.knowledgeURL,
		OllamaURL:     cfg.ollamaURL,
		Model:         cfg.model,
		UseFake:       cfg.useFake,
		Logger:        logger,
		HTTPClient:    &http.Client{Timeout: 60 * time.Second},
	})
	if err != nil {
		logger.Error("wire failed", observability.Err(err))
		os.Exit(1)
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Mount("/api/v1", intel.Handler)

	logger.Info("listening",
		observability.String("addr", cfg.addr),
		observability.Bool("fake_provider", cfg.useFake),
		observability.String("model", cfg.model))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

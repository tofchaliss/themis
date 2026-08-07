// Command intelligence runs the Intelligence Gateway as an independent service
// (EDR-INTELLIGENCE-01): the reactive AI-enrichment surface. It serves the synchronous invoke
// API (POST /api/v1/capabilities/{id}/invoke), grounding each capability from the Governance
// FindingAssessment projection — its ONLY business read (EDR-TRUST-01 T10; the runtime no
// longer reads Knowledge or assembles its own context) — and running the Knowledge → LLM plan
// over Ollama.
//
// When THEMIS_DATABASE_DSN is set it also owns the Operational Semantic Index (KS2, Δ3a): its
// only datastore, a derived + rebuildable vector index over the enterprise's own past
// Positions. A bus reader (gated on THEMIS_BUS_DATABASE_DSN) drains Governance Position events
// to keep it fresh; the in-memory index is loaded from the store on boot. With no store DSN the
// Gateway is stateless (semantic precedent disabled; the exact-CVE fallback still grounds), part
// of the optional AI plane. Composition lives in internal/intelligence/adapters/wiring.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/intelligence/adapters/inbound"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/adapters/wiring"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment; every option is documented here (the
// self-documented-config convention, R2) and in deploy/node.env.example.
type config struct {
	addr          string        // THEMIS_INTELLIGENCE_ADDR — listen address (default ":8086").
	governanceURL string        // THEMIS_GOVERNANCE_URL — Governance read-API base URL.
	ollamaURL     string        // THEMIS_OLLAMA_URL — Ollama (OpenAI-compatible) base URL (LLM + embedder).
	model         string        // THEMIS_INTELLIGENCE_MODEL — pinned LLM model (default "llama3.1:8b").
	useFake       bool          // THEMIS_INTELLIGENCE_PROVIDER=fake — dev/CI provider + embedder (no model).
	apiKey        string        // THEMIS_LLM_API_KEY — optional bearer token for an authenticated server.
	respFormat    string        // THEMIS_LLM_RESPONSE_FORMAT — structured-output mode (json_object|json_schema|text|none).
	llmTimeout    time.Duration // THEMIS_LLM_TIMEOUT — provider HTTP client timeout (Go duration, default 60s). Raise for a slower/larger local model whose grounded recommend exceeds 60s (else the call aborts with provider_error → an "insufficient" 204).

	// Δ3a Operational Semantic Index (semantic precedent, RC-1). Optional — empty DSN = stateless.
	dsn            string // THEMIS_DATABASE_DSN — the Intelligence store DSN (position_embeddings + inbox). Empty ⇒ semantic precedent disabled (exact-CVE fallback only).
	migrate        bool   // THEMIS_INTELLIGENCE_MIGRATE=1 — apply the intelligence store migrations on startup.
	migrationsPath string // THEMIS_INTELLIGENCE_MIGRATIONS — path to the intelligence migrations dir.
	embedModel     string // THEMIS_INTELLIGENCE_EMBED_MODEL — embedding model (default "nomic-embed-text"); ignored with the fake provider.
	topK           int    // THEMIS_INTELLIGENCE_PRECEDENT_TOPK — semantic precedents retrieved per recommendation (default 5).
	rebuild        bool   // THEMIS_INTELLIGENCE_REBUILD=1 — purge the index + reset the bus cursor on boot, re-embedding every past Position from the stream (use after an embedding-model change).

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database. Set ⇒ the reader drains Governance Position events to populate the index; empty ⇒ no population (single-context dev).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		addr:          envDefault("THEMIS_INTELLIGENCE_ADDR", ":8086"),
		governanceURL: envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		ollamaURL:     envDefault("THEMIS_OLLAMA_URL", "http://localhost:11434"),
		model:         envDefault("THEMIS_INTELLIGENCE_MODEL", "llama3.1:8b"),
		useFake:       os.Getenv("THEMIS_INTELLIGENCE_PROVIDER") == "fake",
		apiKey:        os.Getenv("THEMIS_LLM_API_KEY"),
		respFormat:    os.Getenv("THEMIS_LLM_RESPONSE_FORMAT"),
		llmTimeout:    envDurationDefault("THEMIS_LLM_TIMEOUT", 60*time.Second),

		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		migrate:        os.Getenv("THEMIS_INTELLIGENCE_MIGRATE") == "1",
		migrationsPath: envDefault("THEMIS_INTELLIGENCE_MIGRATIONS", "internal/intelligence/adapters/store/migrations"),
		embedModel:     envDefault("THEMIS_INTELLIGENCE_EMBED_MODEL", "nomic-embed-text"),
		topK:           envIntDefault("THEMIS_INTELLIGENCE_PRECEDENT_TOPK", 5),
		rebuild:        os.Getenv("THEMIS_INTELLIGENCE_REBUILD") == "1",

		busDSN:            os.Getenv("THEMIS_BUS_DATABASE_DSN"),
		busMigrate:        os.Getenv("THEMIS_BUS_MIGRATE") == "1",
		busMigrationsPath: envDefault("THEMIS_BUS_MIGRATIONS", eventbus.DefaultMigrationsPath),

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

	// Optional Operational Semantic Index store (Δ3a). An empty DSN keeps the Gateway stateless.
	var st *store.Store
	var pool *pgxpool.Pool
	if cfg.dsn != "" {
		if cfg.migrate {
			if err := applyMigrations(cfg.dsn, cfg.migrationsPath); err != nil {
				logger.Error("migrate failed", observability.Err(err))
				os.Exit(1)
			}
		}
		pool, err = pgxpool.New(ctx, cfg.dsn)
		if err != nil {
			logger.Error("db pool failed", observability.Err(err))
			os.Exit(1)
		}
		defer pool.Close()
		st = store.New(pool)
	} else {
		logger.Warn("THEMIS_DATABASE_DSN not set — semantic precedent (RC-1) disabled; exact-CVE fallback only")
	}

	busPool, closeBus := openBus(ctx, cfg, logger)
	defer closeBus()

	intel, err := wiring.Wire(wiring.Config{
		GovernanceURL:  cfg.governanceURL,
		OllamaURL:      cfg.ollamaURL,
		Model:          cfg.model,
		UseFake:        cfg.useFake,
		APIKey:         cfg.apiKey,
		ResponseFormat: cfg.respFormat,
		Logger:         logger,
		HTTPClient:     &http.Client{Timeout: cfg.llmTimeout},
		Store:          st,
		EmbedModel:     cfg.embedModel,
		TopK:           cfg.topK,
	})
	if err != nil {
		logger.Error("wire failed", observability.Err(err))
		os.Exit(1)
	}

	// Boot-load the in-memory index from the persisted embeddings, optionally rebuilding first
	// (purge + cursor reset → re-embed from scratch, e.g. after an embedding-model change).
	if st != nil {
		if cfg.rebuild {
			if err := rebuildIndex(ctx, st, busPool); err != nil {
				logger.Error("index rebuild failed", observability.Err(err))
				os.Exit(1)
			}
			logger.Info("index rebuild requested — purged store + reset bus cursor; re-embedding from the stream")
		}
		records, err := st.LoadAll(ctx)
		if err != nil {
			logger.Error("index load failed", observability.Err(err))
			os.Exit(1)
		}
		intel.Index.Load(records)
		logger.Info("operational semantic index loaded", observability.Int("embeddings", len(records)))
	}

	// The bus reader populates the index from Governance Position events (Δ3a R6). It needs both
	// the bus pool (source) and the store pool (exactly-once inbox target).
	if busPool != nil && pool != nil && intel.Consumer != nil {
		reader := inbound.Subscription.NewReader(busPool, logger.Component("reader"),
			store.NewInboxConsumer(pool, intel.Consumer))
		go readerLoop(reader, logger.Component("reader"))
		logger.Info("governance position-stream reader enabled (index population)")
	} else {
		logger.Info("index population reader disabled (needs THEMIS_BUS_DATABASE_DSN + THEMIS_DATABASE_DSN)")
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	// Operational metrics, OUTSIDE the authenticated /api/v1 group: this is data for the
	// platform's own scraper, carries no business content, and gating it would mean handing
	// scrape credentials to monitoring.
	router.Handle("/metrics", observability.Default().Handler())
	closeAuth := authedMount(ctx, router, cfg, logger, intel.Handler)
	defer closeAuth()

	logger.Info("listening",
		observability.String("addr", cfg.addr),
		observability.Bool("fake_provider", cfg.useFake),
		observability.String("model", cfg.model),
		observability.Bool("semantic_precedent", st != nil))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// rebuildIndex purges the store (embeddings + the inbox) and resets the Intelligence consumer's
// bus cursor, so the reader re-drains every historical Position event and re-embeds it with the
// current model. Safe because the cursor is only an optimization — correctness is the inbox
// (EDR-EVENTBUS-01 D5). A no-op on the cursor when the bus is not configured.
func rebuildIndex(ctx context.Context, st *store.Store, busPool *pgxpool.Pool) error {
	if err := st.Purge(ctx); err != nil {
		return err
	}
	if busPool != nil {
		if _, err := busPool.Exec(ctx,
			`DELETE FROM stream_cursor WHERE consumer = $1`, inbound.Subscription.Consumer); err != nil {
			return err
		}
	}
	return nil
}

// readerLoop drains the subscribed stream on a fixed cadence. A poison halt stops the loop
// loudly rather than silent-skipping — the reader has already alerted.
func readerLoop(reader *eventbus.Reader, logger *observability.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := reader.Drain(context.Background()); err != nil {
			logger.Error("reader drain failed", observability.Err(err))
			if reader.Halted() {
				logger.Error("stream halted — reader loop stopping until restart")
				return
			}
		}
	}
}

// openBus opens the pool on the `bus` database (optionally migrating it), or returns nil when no
// bus DSN is configured. The returned cleanup closes the pool (a no-op when nil).
func openBus(ctx context.Context, cfg config, logger *observability.Logger) (*pgxpool.Pool, func()) {
	if cfg.busDSN == "" {
		return nil, func() {}
	}
	if cfg.busMigrate {
		if err := applyMigrations(cfg.busDSN, cfg.busMigrationsPath); err != nil {
			logger.Error("bus migrate failed", observability.Err(err))
			os.Exit(1)
		}
	}
	busPool, err := pgxpool.New(ctx, cfg.busDSN)
	if err != nil {
		logger.Error("bus pool failed", observability.Err(err))
		os.Exit(1)
	}
	logger.Info("event bus connected")
	return busPool, busPool.Close
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

func applyMigrations(dsn, path string) error {
	m, err := migrate.New("file://"+path, dsn)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
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

// envIntDefault parses a positive int from key, falling back to def when unset or unparseable.
func envIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

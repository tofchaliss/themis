// Command governance runs the Governance bounded context as an independent service
// (EDR-GOVERNANCE-01 D13): the authority for Findings + Enterprise Positions. It serves the
// triage + read REST API, drains the transactional outbox to publish Position/lifecycle
// events, and accepts inbound Knowledge events (ComponentMatched / FaultlineEnriched /
// FaultlineSuperseded) that open-or-update Findings and raise re-evaluation proposals.
// Composition (adapters -> app ports) lives in internal/governance/adapters/wiring.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/governance/adapters/intelligence"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/adapters/wiring"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string // THEMIS_GOVERNANCE_ADDR — listen address (default ":8083").
	migrate        bool   // THEMIS_GOVERNANCE_MIGRATE=1 — apply the governance migrations on startup.
	devPurge       bool   // THEMIS_GOVERNANCE_DEV_PURGE=1 — expose DELETE /dev/governance (dev only; never in production).
	migrationsPath string // THEMIS_GOVERNANCE_MIGRATIONS — path to the governance migrations dir.
	aiEnabled      bool   // THEMIS_GOVERNANCE_AI_ENABLED=1 (and THEMIS_INTELLIGENCE_ENABLED!=0) — wire the real Intelligence client (D13 disable gate).
	intelligenceURL string // THEMIS_INTELLIGENCE_URL — Intelligence Gateway base URL (when AI enabled).
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_GOVERNANCE_ADDR", ":8083"),
		migrate:        os.Getenv("THEMIS_GOVERNANCE_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_GOVERNANCE_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_GOVERNANCE_MIGRATIONS", "internal/governance/adapters/store/migrations"),
		aiEnabled:      os.Getenv("THEMIS_GOVERNANCE_AI_ENABLED") == "1" && os.Getenv("THEMIS_INTELLIGENCE_ENABLED") != "0",
		intelligenceURL: envDefault("THEMIS_INTELLIGENCE_URL", "http://localhost:8086"),
	}
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("governance"))
	if err != nil {
		log.Fatalf("governance: observability: %v", err)
	}
	defer func() { _ = shutdownObs(context.Background()); _ = logger.Sync() }()

	if cfg.dsn == "" {
		logger.Error("startup aborted: THEMIS_DATABASE_DSN is required")
		os.Exit(1)
	}

	if cfg.migrate {
		if err := applyMigrations(cfg.dsn, cfg.migrationsPath); err != nil {
			logger.Error("migrate failed", observability.Err(err))
			os.Exit(1)
		}
	}

	pool, err := pgxpool.New(ctx, cfg.dsn)
	if err != nil {
		logger.Error("db pool failed", observability.Err(err))
		os.Exit(1)
	}
	defer pool.Close()

	// Disable gate (D13): one wiring choice — the real Intelligence client enables AI,
	// the no-op advisor disables it. The pipeline is correct either way.
	var advisor app.PositionAdvisor = intelligence.NoopAdvisor{}
	if cfg.aiEnabled {
		advisor = intelligence.NewClient(cfg.intelligenceURL, &http.Client{Timeout: 60 * time.Second})
		logger.Info("AI enrichment enabled", observability.String("intelligence_url", cfg.intelligenceURL))
	}

	gov := wiring.Wire(pool, logPublisher{logger}, advisor)

	go relayLoop(gov.Reconcile, logger.Component("reconcile"))

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Mount("/api/v1", gov.Handler)

	// Inbound Knowledge-event intake. Until the Event Infrastructure (M5) bus lands, the
	// seam is fed over HTTP: {"type": "...", "payload": <raw knowledge event>}.
	router.Post("/internal/knowledge-events", func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := gov.Consumer.Handle(r.Context(), env.Type, env.Payload); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if cfg.devPurge {
		router.Delete("/dev/governance", func(w http.ResponseWriter, r *http.Request) {
			if err := gov.Store.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/governance)")
	}

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// relayLoop drains the transactional outbox on a fixed cadence via the state-based
// reconciler (D12) — publishing Position/lifecycle events. The publisher is a logging
// stand-in until the Event Infrastructure (M5) event bus is available.
func relayLoop(recon *app.ReconcileService, logger *observability.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := recon.Reconcile(context.Background()); err != nil {
			logger.Error("reconcile failed", observability.Err(err))
		}
	}
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

type logPublisher struct{ logger *observability.Logger }

func (p logPublisher) Publish(_ context.Context, n store.OutboxNote) error {
	p.logger.Info("published outbox note",
		observability.String("id", n.ID), observability.String("type", n.EventType))
	return nil
}

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

	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/adapters/intelligence"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/adapters/wiring"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn             string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr            string // THEMIS_GOVERNANCE_ADDR — listen address (default ":8083").
	migrate         bool   // THEMIS_GOVERNANCE_MIGRATE=1 — apply the governance migrations on startup.
	devPurge        bool   // THEMIS_GOVERNANCE_DEV_PURGE=1 — expose DELETE /dev/governance (dev only; never in production).
	migrationsPath  string // THEMIS_GOVERNANCE_MIGRATIONS — path to the governance migrations dir.
	aiEnabled       bool   // THEMIS_GOVERNANCE_AI_ENABLED=1 (and THEMIS_INTELLIGENCE_ENABLED!=0) — wire the real Intelligence client (D13 disable gate).
	intelligenceURL string // THEMIS_INTELLIGENCE_URL — Intelligence Gateway base URL (when AI enabled).

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database holding the event_log. When set, the outbox relay publishes to the real event bus (EB-04); when empty, a logging stand-in is used (single-context dev without the bus).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations to THEMIS_BUS_DATABASE_DSN on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).
}

func loadConfig() config {
	return config{
		dsn:             os.Getenv("THEMIS_DATABASE_DSN"),
		addr:            envDefault("THEMIS_GOVERNANCE_ADDR", ":8083"),
		migrate:         os.Getenv("THEMIS_GOVERNANCE_MIGRATE") == "1",
		devPurge:        os.Getenv("THEMIS_GOVERNANCE_DEV_PURGE") == "1",
		migrationsPath:  envDefault("THEMIS_GOVERNANCE_MIGRATIONS", "internal/governance/adapters/store/migrations"),
		aiEnabled:       os.Getenv("THEMIS_GOVERNANCE_AI_ENABLED") == "1" && os.Getenv("THEMIS_INTELLIGENCE_ENABLED") != "0",
		intelligenceURL: envDefault("THEMIS_INTELLIGENCE_URL", "http://localhost:8086"),

		busDSN:            os.Getenv("THEMIS_BUS_DATABASE_DSN"),
		busMigrate:        os.Getenv("THEMIS_BUS_MIGRATE") == "1",
		busMigrationsPath: envDefault("THEMIS_BUS_MIGRATIONS", eventbus.DefaultMigrationsPath),
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

	busPool, closeBus := openBus(ctx, cfg, logger)
	defer closeBus()

	var publisher store.Publisher = logPublisher{logger}
	if busPool != nil {
		publisher = eventbus.NewPublisher(busPool)
	}

	gov := wiring.Wire(pool, publisher, advisor)

	go relayLoop(gov.Reconcile, logger.Component("reconcile"))

	// The bus reader drives Finding open/update + re-evaluation off the Knowledge stream
	// (EB-07/08). Without a bus it is disabled — inbound events then arrive only over the
	// /internal HTTP seam below (dev).
	if busPool != nil {
		reader := inbound.Subscription.NewReader(busPool, logger.Component("reader"),
			store.NewInboxConsumer(pool, gov.Consumer))
		go readerLoop(reader, logger.Component("reader"))
		logger.Info("knowledge-stream reader enabled")
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Mount("/api/v1", gov.Handler)

	// Inbound Knowledge-event intake. Until the Event Infrastructure (M5) bus reader lands,
	// the seam is fed over HTTP with the full kernel Envelope JSON (the reader will call the
	// same Consumer.Handle). A body carrying only {"type","payload"} still decodes — the
	// unset envelope fields are transport metadata the ACL does not read.
	router.Post("/internal/knowledge-events", func(w http.ResponseWriter, r *http.Request) {
		var env event.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := gov.Consumer.Handle(r.Context(), env); err != nil {
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

// openBus opens the pool on the `bus` database (optionally migrating it), or returns nil when
// no bus DSN is configured — in which case the relay uses a logging publisher and the reader
// is disabled (a single context stays runnable without the bus, dev). The returned cleanup
// closes the pool (a no-op when nil).
func openBus(ctx context.Context, cfg config, logger *observability.Logger) (*pgxpool.Pool, func()) {
	if cfg.busDSN == "" {
		logger.Info("event bus not configured (THEMIS_BUS_DATABASE_DSN empty); using logging publisher, reader disabled")
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

// readerLoop drains the subscribed stream on a fixed cadence; a poison halt (D8) stops the
// loop loudly rather than silent-skipping (the reader has already alerted).
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

type logPublisher struct{ logger *observability.Logger }

func (p logPublisher) Publish(_ context.Context, env event.Envelope) error {
	p.logger.Info("published envelope",
		observability.String("id", env.ID), observability.String("type", env.Type),
		observability.String("subject", env.Subject))
	return nil
}

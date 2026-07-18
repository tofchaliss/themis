// Command communication runs the Communication bounded context as an independent service
// (EDR-COMMUNICATION-01 D12): the publication surface. It serves the human-triggered
// publish + read/preview REST API, consumes Governance Position events into the
// publishable-positions worklist, delivers recorded Publications on their channels (exactly-
// once via the durable pending status), drains the terminal-event outbox, and prunes payload
// storage past the retention window. Composition lives in
// internal/communication/adapters/wiring.
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

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/adapters/wiring"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string // THEMIS_COMMUNICATION_ADDR — listen address (default ":8084").
	governanceURL  string // THEMIS_GOVERNANCE_URL — Governance read-API base URL (default "http://localhost:8083").
	migrate        bool   // THEMIS_COMMUNICATION_MIGRATE=1 — apply the communication migrations on startup.
	devPurge       bool   // THEMIS_COMMUNICATION_DEV_PURGE=1 — expose DELETE /dev/communication (dev only).
	migrationsPath string // THEMIS_COMMUNICATION_MIGRATIONS — path to the communication migrations dir.
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_COMMUNICATION_ADDR", ":8084"),
		governanceURL:  envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		migrate:        os.Getenv("THEMIS_COMMUNICATION_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_COMMUNICATION_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_COMMUNICATION_MIGRATIONS", "internal/communication/adapters/store/migrations"),
	}
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("communication"))
	if err != nil {
		log.Fatalf("communication: observability: %v", err)
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

	comm := wiring.Wire(pool, cfg.governanceURL,
		delivery.NewLogDeliverer(logger.Component("delivery")), delivery.PassThroughRedactor{}, logPublisher{logger})

	go workerLoop(comm, logger.Component("worker"))

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Mount("/api/v1", comm.Handler)

	// Inbound Governance Position-event intake. Until the Event Infrastructure (M5) bus
	// lands, the seam is fed over HTTP: {"type": "...", "payload": <raw governance event>}.
	router.Post("/internal/governance-events", func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := comm.Consumer.Handle(r.Context(), env.Type, env.Payload); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if cfg.devPurge {
		router.Delete("/dev/communication", func(w http.ResponseWriter, r *http.Request) {
			if err := comm.Store.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/communication)")
	}

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// workerLoop runs the background workers on a fixed cadence: deliver pending Publications,
// drain the terminal-event outbox (the state-based reconciler), and prune payloads past the
// retention window.
func workerLoop(comm wiring.Communication, logger *observability.Logger) {
	deliverTick := time.NewTicker(2 * time.Second)
	pruneTick := time.NewTicker(1 * time.Hour)
	defer deliverTick.Stop()
	defer pruneTick.Stop()
	ctx := context.Background()
	for {
		select {
		case <-deliverTick.C:
			if _, err := comm.Delivery.DeliverPending(ctx); err != nil {
				logger.Error("deliver failed", observability.Err(err))
			}
			if _, err := comm.Reconcile.Reconcile(ctx); err != nil {
				logger.Error("reconcile failed", observability.Err(err))
			}
		case <-pruneTick.C:
			if n, err := comm.Retention.Prune(ctx); err != nil {
				logger.Error("prune failed", observability.Err(err))
			} else if n > 0 {
				logger.Info("pruned payloads", observability.Int("count", n))
			}
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

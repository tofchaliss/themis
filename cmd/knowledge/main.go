// Command knowledge runs the Knowledge bounded context as an independent service: the
// Faultline read API, the transactional-outbox relay (publishing Faultline facts), and a bus
// reader on the Evidence stream that drives correlation (EvidenceRegistered → correlate a
// release's inventory against discovered vulnerabilities). Composition (adapters -> app
// ports) lives in internal/knowledge/adapters/wiring so the binary and tests share wiring.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/adapters/wiring"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string // THEMIS_KNOWLEDGE_ADDR — listen address (default ":8082").
	migrate        bool   // THEMIS_KNOWLEDGE_MIGRATE=1 — apply the knowledge migrations on startup.
	devPurge       bool   // THEMIS_KNOWLEDGE_DEV_PURGE=1 — expose DELETE /dev/knowledge (dev only).
	migrationsPath string // THEMIS_KNOWLEDGE_MIGRATIONS — path to the knowledge migrations dir.
	evidenceURL    string // THEMIS_EVIDENCE_URL — Evidence read-API base URL (inventory source; default "http://localhost:8081").
	osvURL         string // THEMIS_OSV_URL — OSV query base URL (lazy discovery; default "https://api.osv.dev").

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database. When set, the relay publishes and the reader drains the Evidence stream; when empty, a logging publisher is used and the reader is disabled (single-context dev).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_KNOWLEDGE_ADDR", ":8082"),
		migrate:        os.Getenv("THEMIS_KNOWLEDGE_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_KNOWLEDGE_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_KNOWLEDGE_MIGRATIONS", "internal/knowledge/adapters/store/migrations"),
		evidenceURL:    envDefault("THEMIS_EVIDENCE_URL", "http://localhost:8081"),
		osvURL:         envDefault("THEMIS_OSV_URL", "https://api.osv.dev"),

		busDSN:            os.Getenv("THEMIS_BUS_DATABASE_DSN"),
		busMigrate:        os.Getenv("THEMIS_BUS_MIGRATE") == "1",
		busMigrationsPath: envDefault("THEMIS_BUS_MIGRATIONS", eventbus.DefaultMigrationsPath),
	}
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("knowledge"))
	if err != nil {
		log.Fatalf("knowledge: observability: %v", err)
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

	busPool, closeBus := openBus(ctx, cfg, logger)
	defer closeBus()

	var publisher store.Publisher = logPublisher{logger}
	if busPool != nil {
		publisher = eventbus.NewPublisher(busPool)
	}

	kn := wiring.Wire(pool, cfg.evidenceURL, cfg.osvURL, publisher)

	go relayLoop(kn.Relay, logger.Component("relay"))

	// The bus reader drives correlation off the Evidence stream (EB-07/08). Without a bus it
	// is disabled — correlation then only runs via direct calls (dev).
	if busPool != nil {
		reader := inbound.Subscription.NewReader(busPool, logger.Component("reader"),
			store.NewInboxConsumer(pool, kn.Consumer))
		go readerLoop(reader, logger.Component("reader"))
		logger.Info("evidence-stream reader enabled")
	} else {
		logger.Info("event bus not configured; correlation reader disabled")
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Mount("/api/v1", kn.Handler)
	if cfg.devPurge {
		router.Delete("/dev/knowledge", func(w http.ResponseWriter, r *http.Request) {
			if err := kn.Store.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/knowledge)")
	}

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// relayLoop drains the transactional outbox on a fixed cadence, publishing Faultline facts.
func relayLoop(relay *store.Relay, logger *observability.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := relay.DeliverPending(context.Background()); err != nil {
			logger.Error("relay failed", observability.Err(err))
		}
	}
}

// readerLoop drains the subscribed stream on a fixed cadence. A poison halt (D8) stops the
// loop loudly rather than silent-skipping — the reader has already alerted.
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

// openBus opens the pool on the `bus` database (optionally migrating it), or returns nil when
// no bus DSN is configured. The returned cleanup closes the pool (a no-op when nil).
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

func (p logPublisher) Publish(_ context.Context, env event.Envelope) error {
	p.logger.Info("published envelope",
		observability.String("id", env.ID), observability.String("type", env.Type),
		observability.String("subject", env.Subject))
	return nil
}

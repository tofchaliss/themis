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
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/adapters/wiring"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
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

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database holding the event_log. When set, the outbox relay publishes to the real event bus (EB-04); when empty, a logging stand-in is used (single-context dev without the bus).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations to THEMIS_BUS_DATABASE_DSN on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_COMMUNICATION_ADDR", ":8084"),
		governanceURL:  envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		migrate:        os.Getenv("THEMIS_COMMUNICATION_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_COMMUNICATION_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_COMMUNICATION_MIGRATIONS", "internal/communication/adapters/store/migrations"),

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

	busPool, closeBus := openBus(ctx, cfg, logger)
	defer closeBus()

	var publisher store.Publisher = logPublisher{logger}
	if busPool != nil {
		publisher = eventbus.NewPublisher(busPool)
	}

	comm := wiring.Wire(pool, cfg.governanceURL,
		delivery.NewLogDeliverer(logger.Component("delivery")), delivery.PassThroughRedactor{}, publisher)

	go workerLoop(comm, logger.Component("worker"))

	// The bus reader drives the publishable-positions worklist off the Governance stream
	// (EB-07/08). Without a bus it is disabled — Position events then arrive only over the
	// /internal HTTP seam below (dev).
	if busPool != nil {
		reader := inbound.Subscription.NewReader(busPool, logger.Component("reader"),
			store.NewInboxConsumer(pool, comm.Consumer))
		go readerLoop(reader, logger.Component("reader"))
		logger.Info("governance-stream reader enabled")
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	closeAuth := authedMount(ctx, router, cfg, logger, comm.Handler)
	defer closeAuth()

	// Inbound Governance Position-event intake. Until the Event Infrastructure (M5) bus
	// reader lands, the seam is fed over HTTP with the full kernel Envelope JSON (the reader
	// will call the same Consumer.Handle). A body carrying only {"type","payload"} still
	// decodes — the unset envelope fields are transport metadata the ACL does not read.
	router.Post("/internal/governance-events", func(w http.ResponseWriter, r *http.Request) {
		var env event.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := comm.Consumer.Handle(r.Context(), env); err != nil {
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

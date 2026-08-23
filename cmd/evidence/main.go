// Command evidence runs the Evidence bounded context as an independent service:
// the REST API plus a transactional-outbox relay loop. Composition (adapters ->
// app ports) lives in internal/evidence/adapters/wiring so the binary and the
// e2e tests share identical wiring.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/adapters/wiring"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/health"
	"github.com/themis-project/themis/internal/platform/observability"
	registrystore "github.com/themis-project/themis/internal/registry/adapters/store"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string   // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string   // THEMIS_EVIDENCE_ADDR — listen address (default ":8081").
	knownReleases  []string // THEMIS_EVIDENCE_KNOWN_RELEASES — dev only: comma-separated release ids the stub SubjectRef accepts. When empty, SubjectRef is registry-backed (registry.ReleaseExists over the same DB; run cmd/registry to migrate/populate).
	migrate        bool     // THEMIS_EVIDENCE_MIGRATE=1 — apply the Evidence migrations on startup.
	devPurge       bool     // THEMIS_EVIDENCE_DEV_PURGE=1 — expose DELETE /dev/evidence (dev only; never in production).
	migrationsPath string   // THEMIS_EVIDENCE_MIGRATIONS — path to the Evidence migrations dir.

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database holding the event_log. When set, the outbox relay publishes to the real event bus (EB-04); when empty, a logging stand-in is used (single-context dev without the bus).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations to THEMIS_BUS_DATABASE_DSN on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_EVIDENCE_ADDR", ":8081"),
		knownReleases:  splitNonEmpty(os.Getenv("THEMIS_EVIDENCE_KNOWN_RELEASES")),
		migrate:        os.Getenv("THEMIS_EVIDENCE_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_EVIDENCE_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_EVIDENCE_MIGRATIONS", "internal/evidence/adapters/store/migrations"),

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

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("evidence"))
	if err != nil {
		log.Fatalf("evidence: observability: %v", err)
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

	var apiHandler http.Handler
	var st *store.Store
	if len(cfg.knownReleases) > 0 {
		apiHandler, st = wiring.EvidenceAPI(pool, subjectref.NewStub(cfg.knownReleases...))
		logger.Info("SubjectRef = dev stub", observability.Int("known_releases", len(cfg.knownReleases)))
	} else {
		apiHandler, st = wiring.EvidenceAPI(pool, registrySubjectRef{store: registrystore.New(pool)})
		logger.Info("SubjectRef = registry-backed (registry.ReleaseExists)")
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	// Operational metrics, OUTSIDE the authenticated /api/v1 group: this is data for the
	// platform's own scraper, carries no business content, and gating it would mean handing
	// scrape credentials to monitoring.
	router.Handle("/metrics", observability.Default().Handler())
	// Liveness + readiness, outside /api/v1 like /metrics (R6/F5): /healthz says the process
	// serves; /readyz says it can actually answer — DB reachable, migrations present, and the
	// stored credential still valid on a FRESH connection (pooled connections survive a
	// password rotation, so every node reports healthy until they all fail at the next restart).
	credWatch := health.NewCredentialWatch(health.PgxDialer(cfg.dsn), 0, func(err error) {
		logger.Error("db credentials are STALE: fresh connections fail; pooled connections keep serving until the next restart", observability.Err(err))
	})
	go credWatch.Run(ctx)
	router.Get("/healthz", health.Healthz())
	router.Get("/readyz", health.Readyz(
		health.PoolCheck("db", pool),
		health.ExecCheck("migrations", pool, "SELECT version FROM schema_migrations LIMIT 1"),
		credWatch.Check("db-credentials"),
	))
	closeAuth := authedMount(ctx, router, cfg, logger, apiHandler)
	defer closeAuth()
	if cfg.devPurge {
		router.Delete("/dev/evidence", func(w http.ResponseWriter, r *http.Request) {
			if err := st.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/evidence)")
	}

	publisher, closeBus := newPublisher(ctx, cfg, logger)
	defer closeBus()

	go relayLoop(pool, publisher, logger.Component("relay"))

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// relayLoop delivers outbox notes on a fixed cadence, appending each to the event bus
// via the given publisher (EB-04).
func relayLoop(pool *pgxpool.Pool, publisher store.Publisher, logger *observability.Logger) {
	relay := store.NewRelay(pool, publisher, 100)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := relay.DeliverPending(context.Background()); err != nil {
			logger.Error("relay failed", observability.Err(err))
		}
	}
}

// newPublisher builds the outbox relay's publisher. With THEMIS_BUS_DATABASE_DSN set it
// is the real platform Publisher appending to the bus event_log (EB-04); with it empty a
// logging stand-in keeps a single context runnable without the bus (dev). The returned
// cleanup closes the bus pool (a no-op for the stand-in).
func newPublisher(ctx context.Context, cfg config, logger *observability.Logger) (store.Publisher, func()) {
	if cfg.busDSN == "" {
		logger.Info("event bus not configured (THEMIS_BUS_DATABASE_DSN empty); using logging publisher")
		return logPublisher{logger}, func() {}
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
	logger.Info("event bus connected (EB-04 Publisher)")
	return eventbus.NewPublisher(busPool), busPool.Close
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

func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// registrySubjectRef backs Evidence's SubjectRef port with the registry's
// ReleaseExists read query (EDR-KERNEL-01 D1; EDR-EVIDENCE-01 D5). In-process it
// queries the registry's own tables in the shared database; the registry owns and
// migrates them (run cmd/registry). Only ReleaseExists is exposed to the app.
type registrySubjectRef struct{ store *registrystore.Store }

func (v registrySubjectRef) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return v.store.ReleaseExists(ctx, releaseID)
}

type logPublisher struct{ logger *observability.Logger }

func (p logPublisher) Publish(_ context.Context, env event.Envelope) error {
	p.logger.Info("published envelope",
		observability.String("id", env.ID), observability.String("type", env.Type),
		observability.String("subject", env.Subject))
	return nil
}

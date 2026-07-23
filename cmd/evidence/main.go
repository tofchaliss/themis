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
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_EVIDENCE_ADDR", ":8081"),
		knownReleases:  splitNonEmpty(os.Getenv("THEMIS_EVIDENCE_KNOWN_RELEASES")),
		migrate:        os.Getenv("THEMIS_EVIDENCE_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_EVIDENCE_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_EVIDENCE_MIGRATIONS", "internal/evidence/adapters/store/migrations"),
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
	router.Mount("/api/v1", apiHandler)
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

	go relayLoop(pool, logger.Component("relay"))

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// relayLoop delivers outbox notes on a fixed cadence. The publisher is a logging
// stand-in until the Event Infrastructure (M5) event bus is available.
func relayLoop(pool *pgxpool.Pool, logger *observability.Logger) {
	relay := store.NewRelay(pool, logPublisher{logger}, 100)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := relay.DeliverPending(context.Background()); err != nil {
			logger.Error("relay failed", observability.Err(err))
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

func (p logPublisher) Publish(_ context.Context, n store.OutboxNote) error {
	p.logger.Info("published outbox note",
		observability.String("id", n.ID), observability.String("type", n.EventType))
	return nil
}

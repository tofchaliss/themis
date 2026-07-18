// Command registry runs the registry supporting context as an independent service:
// the REST API for registering the Product → Project → Release identity hierarchy and
// looking up releases (including the ReleaseExists query that backs Evidence's
// SubjectRef). Composition (adapters -> app ports) lives in
// internal/registry/adapters/wiring.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/platform/observability"
	"github.com/themis-project/themis/internal/registry/adapters/wiring"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string // THEMIS_REGISTRY_ADDR — listen address (default ":8082").
	migrate        bool   // THEMIS_REGISTRY_MIGRATE=1 — apply the registry migrations on startup.
	devPurge       bool   // THEMIS_REGISTRY_DEV_PURGE=1 — expose DELETE /dev/registry (dev only; never in production).
	migrationsPath string // THEMIS_REGISTRY_MIGRATIONS — path to the registry migrations dir.
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_REGISTRY_ADDR", ":8082"),
		migrate:        os.Getenv("THEMIS_REGISTRY_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_REGISTRY_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_REGISTRY_MIGRATIONS", "internal/registry/adapters/store/migrations"),
	}
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("registry"))
	if err != nil {
		log.Fatalf("registry: observability: %v", err)
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

	apiHandler, st := wiring.RegistryAPI(pool)

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Mount("/api/v1", apiHandler)
	if cfg.devPurge {
		router.Delete("/dev/registry", func(w http.ResponseWriter, r *http.Request) {
			if err := st.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/registry)")
	}

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
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

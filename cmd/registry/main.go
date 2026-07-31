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

	"github.com/themis-project/themis/internal/platform/auth"
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

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_REGISTRY_ADDR", ":8082"),
		migrate:        os.Getenv("THEMIS_REGISTRY_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_REGISTRY_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_REGISTRY_MIGRATIONS", "internal/registry/adapters/store/migrations"),

		authDSN:      os.Getenv("THEMIS_AUTH_DATABASE_DSN"),
		authRequired: os.Getenv("THEMIS_AUTH_REQUIRED") == "1",
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
	closeAuth := authedMount(ctx, router, cfg, logger, apiHandler)
	defer closeAuth()
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

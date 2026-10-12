// Command dashboard serves the Themis GUI: a static single-page dashboard plus a
// same-origin reverse proxy to the six node read APIs (EDR-GUI-01). It is a VIEW,
// not a context — it owns no truth, defines no domain, and every fact it renders
// is fetched live from an existing read API (the DASHBOARD-SPIKE.md wiring contract,
// D5). The proxy exists for two structural reasons (D1): the nodes set no CORS
// headers (correctly), and with auth enabled the node's X-API-Key must never reach
// browser JavaScript — see internal/dashboard/proxy.
//
// The one table it owns is its OWN sign-in directory (internal/dashboard/userstore, in
// the shared auth database — D3 amendment 2026-10-12): the GUI's username and password,
// which no bounded context has any business holding. Nothing a node could answer is
// stored here, so "a view, never a context" is unchanged.
//
// The static assets are embedded (go:embed, D8) so the deliverable stays one static
// binary, like every other node.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/dashboard/proxy"
	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/dashboard/userstore"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/health"
	"github.com/themis-project/themis/internal/platform/observability"
)

//go:embed static
var staticFS embed.FS

// config is read from the environment. Every option is documented here (the
// self-documented-config convention, CONVENTIONS R2).
type config struct {
	addr string // THEMIS_DASHBOARD_ADDR — listen address (default ":8090").

	// Node read-API base URLs the proxy forwards to. Defaults match the runbook ports.
	registryURL      string // THEMIS_REGISTRY_URL (default http://localhost:8082)
	evidenceURL      string // THEMIS_EVIDENCE_URL (default http://localhost:8081)
	knowledgeURL     string // THEMIS_KNOWLEDGE_URL (default http://localhost:8085)
	governanceURL    string // THEMIS_GOVERNANCE_URL (default http://localhost:8083)
	communicationURL string // THEMIS_COMMUNICATION_URL (default http://localhost:8084)
	intelligenceURL  string // THEMIS_INTELLIGENCE_URL (default http://localhost:8086)

	// apiKey — THEMIS_API_KEY. When set, the proxy adds it as X-API-Key on every
	// forwarded request (the NODE key, D4: it states "the dashboard may read", never
	// who is asking). Empty = no header (dev, auth off).
	apiKey string

	// assetsDir — THEMIS_DASHBOARD_ASSETS. When set, static files are served from
	// this directory instead of the embedded copy (edit-and-refresh during design
	// work, D8); empty = the embedded assets (production).
	assetsDir string

	// userName — THEMIS_DASHBOARD_USER. Display name shown in the topbar when auth is
	// OFF (default "operator"). With an auth DSN set, /whoami answers with the
	// authenticated session's operator instead (D2) and this value is unused.
	userName string

	// authDSN — THEMIS_AUTH_DATABASE_DSN. The inbound-edge auth switch, same as every
	// node (D3): set ⇒ the browser must sign in (login form → server-side session,
	// D12) and the proxy enforces operator scope + identity (D11/D13); unset ⇒ the
	// edge is open (dev) and the node logs AUTH DISABLED.
	authDSN string

	// authRequired — THEMIS_AUTH_REQUIRED. The production guard shared with every
	// node: "1" hard-fails startup when authDSN is empty, so this deployable can
	// never silently boot with an open edge.
	authRequired bool

	// migrate — THEMIS_DASHBOARD_MIGRATE=1. Apply the dashboard's OWN migrations (the
	// `dashboard_users` login table) against the auth DSN on startup, under the
	// dashboard's own golang-migrate bookkeeping table. Unset ⇒ no DDL is attempted;
	// password login then needs the table to already exist.
	migrate bool

	// migrationsPath — THEMIS_DASHBOARD_MIGRATIONS. Path to those migrations.
	migrationsPath string
}

func loadConfig() config {
	return config{
		addr:             envDefault("THEMIS_DASHBOARD_ADDR", ":8090"),
		registryURL:      envDefault("THEMIS_REGISTRY_URL", "http://localhost:8082"),
		evidenceURL:      envDefault("THEMIS_EVIDENCE_URL", "http://localhost:8081"),
		knowledgeURL:     envDefault("THEMIS_KNOWLEDGE_URL", "http://localhost:8085"),
		governanceURL:    envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		communicationURL: envDefault("THEMIS_COMMUNICATION_URL", "http://localhost:8084"),
		intelligenceURL:  envDefault("THEMIS_INTELLIGENCE_URL", "http://localhost:8086"),
		apiKey:           os.Getenv("THEMIS_API_KEY"),
		assetsDir:        os.Getenv("THEMIS_DASHBOARD_ASSETS"),
		userName:         envDefault("THEMIS_DASHBOARD_USER", "operator"),
		authDSN:          os.Getenv("THEMIS_AUTH_DATABASE_DSN"),
		authRequired:     os.Getenv("THEMIS_AUTH_REQUIRED") == "1",
		migrate:          os.Getenv("THEMIS_DASHBOARD_MIGRATE") == "1",
		migrationsPath:   envDefault("THEMIS_DASHBOARD_MIGRATIONS", userstore.DefaultMigrationsPath),
	}
}

// errAuthRequired is the boot refusal (D3): the production guard means "never boot with
// an open edge", and with no auth DSN the edge would be open.
var errAuthRequired = errors.New(
	"THEMIS_AUTH_REQUIRED=1 but THEMIS_AUTH_DATABASE_DSN is empty: the dashboard refuses to boot " +
		"with an open edge — set the auth DSN (login becomes mandatory) or unset the flag only on a " +
		"network where an open dashboard edge is an accepted, explicit choice")

// guardAuth is the boot-or-refuse decision, separated from main so the refusal is
// testable — a guard that only runs in production is a guard nobody has seen work.
func guardAuth(cfg config) error {
	if cfg.authRequired && cfg.authDSN == "" {
		return errAuthRequired
	}
	return nil
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("dashboard"))
	if err != nil {
		log.Fatalf("dashboard: observability: %v", err)
	}
	defer func() { _ = shutdownObs(context.Background()); _ = logger.Sync() }()

	if err := guardAuth(cfg); err != nil {
		logger.Error("refusing to start", observability.Err(err))
		os.Exit(1)
	}

	router := chi.NewRouter()
	router.Use(observability.RequestLogger(logger))
	router.Handle("/metrics", observability.Default().Handler())
	// Liveness + readiness (R6/F5). The dashboard owns no truth: its only table is its own
	// login directory in the shared auth DB, and a dashboard that cannot reach it must still
	// SERVE (API-key sign-in is unaffected), so it is deliberately not a readiness check —
	// /readyz with zero checks still distinguishes "serving" from "absent", the R6 gap here.
	router.Get("/healthz", health.Healthz())
	router.Get("/readyz", health.Readyz())

	p, err := proxy.New(proxy.Config{
		Targets: map[string]string{
			"registry":      cfg.registryURL,
			"evidence":      cfg.evidenceURL,
			"knowledge":     cfg.knowledgeURL,
			"governance":    cfg.governanceURL,
			"communication": cfg.communicationURL,
			"intelligence":  cfg.intelligenceURL,
		},
		APIKey: cfg.apiKey,
	})
	if err != nil {
		logger.Error("bad node URL", observability.Err(err))
		os.Exit(1)
	}

	assets, err := assetHandler(cfg.assetsDir)
	if err != nil {
		logger.Error("assets failed", observability.Err(err))
		os.Exit(1)
	}

	if cfg.authDSN != "" {
		// The authenticated edge (D2/D3/D11/D12/D13): login + server-side session,
		// scope + identity enforcement at the proxy, /whoami from the session.
		//
		// The dashboard's own login table lives in the SAME auth database as api_keys, so
		// one pool serves both stores — the key store the platform owns, and the
		// dashboard-local user directory D12 keeps out of it.
		if cfg.migrate {
			if merr := applyMigrations(cfg.authDSN, cfg.migrationsPath); merr != nil {
				logger.Error("dashboard migrate failed", observability.Err(merr))
				os.Exit(1)
			}
		}
		pool, perr := pgxpool.New(ctx, cfg.authDSN)
		if perr != nil {
			logger.Error("auth store", observability.Err(perr))
			os.Exit(1)
		}
		defer pool.Close()
		users := userstore.NewStore(pool)
		seeded, serr := users.EnsureAdminSeed(ctx)
		reportSeed(logger, seeded, serr)

		mgr := session.NewManager(session.KeyVerifier{Keys: auth.NewStore(pool)}, users, 0, nil)
		sh := session.Handler{Manager: mgr}
		mountAuthenticated(router, sh, p, assets)
		logger.Info("auth ENABLED — browser sessions over the shared auth store (EDR-GUI-01 D3)")
	} else {
		// The same honesty contract every node has: an open edge announces itself.
		logger.Info("AUTH DISABLED — the dashboard edge is open (set THEMIS_AUTH_DATABASE_DSN to require sign-in, EDR-GUI-01 D3)")
		mountOpen(router, p, assets, cfg.userName)
	}

	if cfg.apiKey != "" {
		logger.Info("proxy auth: X-API-Key injection ENABLED")
	} else {
		logger.Info("proxy auth: no API key set (auth-off deployment)")
	}
	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// The dashboard's OWN routes — the Admin tab's read and its one mutation. They are
// dashboard-local by nature: no node owns the GUI's login table, so there is nothing to
// proxy them to. They live under /api/ anyway so the SPA has one fetch convention, which is
// exactly why mounting order matters (see mountAuthenticated).
const (
	adminStatusRoute   = "/api/dashboard/admin/status"
	adminPasswordRoute = "/api/dashboard/admin/password"
)

// mountAuthenticated wires the authenticated edge. The ORDER is load-bearing: the two
// dashboard-local admin routes are registered BEFORE the `/api/*` proxy mount, so a
// password change can never be forwarded to a node (it would arrive as an unknown-node 404
// at best, and at worst would send a password to a service that has no business seeing one).
// It is a function so the mounting — not just the handlers — is testable: TestAdminRoutes…
// drives this router with a proxy spy and proves the spy is never reached.
func mountAuthenticated(router chi.Router, sh session.Handler, p http.Handler, assets http.Handler) {
	gate := proxy.Gate{Principal: sh.Principal, Reverify: sh.Reverify}

	router.Get("/login", sh.LoginPage)
	router.Post("/login", sh.Login)
	router.Post("/logout", sh.Logout)

	// Dashboard-local, admin-only, never proxied.
	router.With(sh.RequireAdmin).Get(adminStatusRoute, sh.AdminStatus)
	router.With(sh.RequireAdmin).Post(adminPasswordRoute, sh.ChangePassword)

	router.Handle("/api/*", gate.Wrap(p))
	router.Get("/whoami", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := sh.Principal(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"title": "authentication required"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user":      principal.Name,
			"scopes":    principal.Scopes,
			"can_write": principal.AuthorizeWrite(),
		})
	})
	router.Handle("/*", sh.RequireSession(assets))
}

// mountOpen wires the auth-off edge (dev / firewalled trial): no login, no session, and no
// password. The Admin status route is still mounted — BEFORE the proxy, same as above — so
// the Admin tab can say "authentication is disabled" instead of offering a form with nothing
// behind it. A tab that renders a password field against no password store is worse than a
// tab that explains itself.
func mountOpen(router chi.Router, p http.Handler, assets http.Handler, userName string) {
	router.Get(adminStatusRoute, session.DisabledAdminStatus)
	router.Post(adminPasswordRoute, session.DisabledAdminPassword)
	router.Handle("/api/*", p)
	router.Get("/whoami", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": userName, "can_write": true})
	})
	router.Handle("/*", assets)
}

// The three things startup can say about the login table. None of them contains the default
// password: the plaintext lives in userstore's seed constant and in INSTALLATION.md, and
// nowhere a log aggregator can reach.
const (
	seedCreatedMsg = "seeded the default dashboard admin account — sign in and change its password in the Admin tab before anything else"
	seedMissingMsg = "dashboard_users table is MISSING — password sign-in is unavailable until the dashboard migrations run (start this node once with THEMIS_DASHBOARD_MIGRATE=1); API-key sign-in is unaffected"
	seedFailedMsg  = "could not seed the dashboard admin account — password sign-in may be unavailable; API-key sign-in is unaffected"
)

// reportSeed turns the seed result into the one line startup logs, and never into a boot
// refusal: a dashboard that cannot reach its own login table can still serve the SPA to
// API-key operators, and refusing to start would take the GUI down over a table the
// operator can create with one flag.
func reportSeed(logger *observability.Logger, created bool, err error) {
	switch {
	case errors.Is(err, userstore.ErrTableMissing):
		logger.Warn(seedMissingMsg)
	case err != nil:
		logger.Warn(seedFailedMsg, observability.Err(err))
	case created:
		logger.Info(seedCreatedMsg)
	}
}

// migrationDSN returns dsn with the dashboard's migrations-table parameter attached.
//
// It MUST be a separate string from the pool DSN — the same trap Registry documents: putting
// `x-migrations-table` on the one shared DSN makes the migration succeed and then kills every
// runtime connection, because pgx forwards the unknown parameter to Postgres as a startup
// option (`FATAL: unrecognized configuration parameter`). golang-migrate reads it from the
// URL; pgx must never see it. The distinct table matters here because the `auth` database is
// also migrated by authadmin, and a shared `schema_migrations` would make whichever ran
// second read the other's version and skip its own CREATE TABLE.
func migrationDSN(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("dashboard: unparseable DSN: %w", err)
	}
	q := u.Query()
	q.Set("x-migrations-table", userstore.MigrationsTable)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// applyMigrations runs the dashboard's migrations from `path`, which DEFAULTS TO A RELATIVE
// directory (userstore.DefaultMigrationsPath) and so is resolved against the process's working
// directory — the repo root for a hand-started node, and `WorkingDirectory=` for the systemd
// unit. A path that does not resolve is the most likely way this fails on a non-repo
// deployment, so the error names the path it looked for and the variable that overrides it;
// golang-migrate's own "no such file" says neither.
func applyMigrations(dsn, path string) error {
	mdsn, err := migrationDSN(dsn)
	if err != nil {
		return err
	}
	if _, serr := os.Stat(path); serr != nil {
		abs, _ := filepath.Abs(path)
		return fmt.Errorf("dashboard: migrations directory %q (resolved to %q) is unreadable: %w — "+
			"set THEMIS_DASHBOARD_MIGRATIONS to an absolute path, or run this node with a working "+
			"directory the default resolves against", path, abs, serr)
	}
	m, err := migrate.New("file://"+path, mdsn)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// assetHandler serves the embedded static assets, or a directory override for
// design iteration (D8). Unknown paths fall back to index.html only at "/" — the
// app routes with URL hashes, so no history-API fallback is needed.
func assetHandler(override string) (http.Handler, error) {
	if override != "" {
		return http.FileServer(http.Dir(override)), nil
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	return http.FileServer(http.FS(sub)), nil
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

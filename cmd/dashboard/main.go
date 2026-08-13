// Command dashboard serves the Themis GUI: a static single-page dashboard plus a
// same-origin reverse proxy to the six node read APIs (EDR-GUI-01). It is a VIEW,
// not a context — it owns no database, defines no domain, and every fact it renders
// is fetched live from an existing read API (the DASHBOARD-SPIKE.md wiring contract,
// D5). The proxy exists for two structural reasons (D1): the nodes set no CORS
// headers (correctly), and with auth enabled the node's X-API-Key must never reach
// browser JavaScript — see internal/dashboard/proxy.
//
// The static assets are embedded (go:embed, D8) so the deliverable stays one static
// binary, like every other node.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/dashboard/proxy"
	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/platform/auth"
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
		authenticator, closeAuth, aerr := auth.Open(ctx, cfg.authDSN)
		if aerr != nil {
			logger.Error("auth store", observability.Err(aerr))
			os.Exit(1)
		}
		defer closeAuth()
		mgr := session.NewManager(session.KeyVerifier{Keys: authenticator.Keys}, 0, nil)
		sh := session.Handler{Manager: mgr}
		gate := proxy.Gate{Principal: sh.Principal, Reverify: sh.Reverify}

		router.Get("/login", sh.LoginPage)
		router.Post("/login", sh.Login)
		router.Post("/logout", sh.Logout)
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
		logger.Info("auth ENABLED — browser sessions over the shared auth store (EDR-GUI-01 D3)")
	} else {
		// The same honesty contract every node has: an open edge announces itself.
		logger.Info("AUTH DISABLED — the dashboard edge is open (set THEMIS_AUTH_DATABASE_DSN to require sign-in, EDR-GUI-01 D3)")
		router.Handle("/api/*", p)
		router.Get("/whoami", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"user": cfg.userName, "can_write": true})
		})
		router.Handle("/*", assets)
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

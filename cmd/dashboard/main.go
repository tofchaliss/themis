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

	// userName — THEMIS_DASHBOARD_USER. Display name shown in the topbar (default
	// "operator"). The Phase-1 stopgap identity: Phase 2 (D2/D12) replaces this with
	// the authenticated session's operator, answered through the same /whoami, and
	// the page needs no change.
	userName string

	// authRequired — THEMIS_AUTH_REQUIRED. The production guard shared with every
	// node: "1" means this deployable may never boot with an open edge. The Phase-1
	// dashboard HAS no authenticated edge (login is Phase 2, D3), so with the flag
	// set it refuses to boot at all — that is the guard working, making the Phase-1
	// exposure window an explicit operator choice instead of a silent default.
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
		authRequired:     os.Getenv("THEMIS_AUTH_REQUIRED") == "1",
	}
}

// errAuthRequired is the Phase-1 boot refusal (D3 amendment, grilled 2026-08-13).
var errAuthRequired = errors.New(
	"THEMIS_AUTH_REQUIRED=1 but the dashboard's authenticated edge (login/session) is not yet wired: " +
		"this deployable cannot honor the flag and refuses to boot open — unset the flag only on a " +
		"network where an open dashboard edge is an accepted, explicit choice")

// guardAuth is the boot-or-refuse decision, separated from main so the refusal is
// testable — a guard that only runs in production is a guard nobody has seen work.
func guardAuth(cfg config) error {
	if cfg.authRequired {
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
	// The same honesty contract every node has: an open edge announces itself.
	logger.Info("AUTH DISABLED — the dashboard edge is open (login/session lands in Phase 2, EDR-GUI-01 D3)")

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
	router.Handle("/api/*", p)

	// Who is looking at the page. Config-supplied in Phase 1; the seam the
	// authenticated session (D2/D12) answers through in Phase 2.
	router.Get("/whoami", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"user": cfg.userName})
	})

	assets, err := assetHandler(cfg.assetsDir)
	if err != nil {
		logger.Error("assets failed", observability.Err(err))
		os.Exit(1)
	}
	router.Handle("/*", assets)

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

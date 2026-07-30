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
	"github.com/themis-project/themis/internal/knowledge/app"
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

	nvdEnabled      bool          // THEMIS_NVD_ENABLED=1 — enable the scheduled NVD modified-since watch (enriches already-carded CVEs with authoritative CVSS/severity; default off).
	nvdURL          string        // THEMIS_NVD_URL — NVD 2.0 CVE API base URL (empty → the client default, services.nvd.nist.gov).
	nvdAPIKey       string        // THEMIS_NVD_API_KEY — NVD API key (higher rate limit; optional).
	nvdPollInterval time.Duration // THEMIS_NVD_POLL_INTERVAL — Go duration between watch polls (default 6h; falls back to 6h if unparseable).

	sigEnabled      bool          // THEMIS_EPSSKEV_ENABLED=1 — enable the scheduled exploit-signal enrichment sweep (EPSS/KEV/ExploitDB → already-carded CVEs; default off).
	epssURL         string        // THEMIS_EPSS_URL — FIRST.org EPSS gzip-CSV URL (default the current-scores feed; empty skips EPSS).
	kevURL          string        // THEMIS_KEV_URL — CISA KEV JSON catalog URL (default; empty skips KEV).
	exploitDBURL    string        // THEMIS_EXPLOITDB_URL — ExploitDB files_exploits.csv URL (default; empty skips ExploitDB).
	sigPollInterval time.Duration // THEMIS_EPSSKEV_POLL_INTERVAL — Go duration between enrichment sweeps (default 24h; falls back to 24h if unparseable).

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

		nvdEnabled:      os.Getenv("THEMIS_NVD_ENABLED") == "1",
		nvdURL:          os.Getenv("THEMIS_NVD_URL"),
		nvdAPIKey:       os.Getenv("THEMIS_NVD_API_KEY"),
		nvdPollInterval: parseDurationDefault(os.Getenv("THEMIS_NVD_POLL_INTERVAL"), 6*time.Hour),

		sigEnabled:      os.Getenv("THEMIS_EPSSKEV_ENABLED") == "1",
		epssURL:         envDefault("THEMIS_EPSS_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz"),
		kevURL:          envDefault("THEMIS_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
		exploitDBURL:    envDefault("THEMIS_EXPLOITDB_URL", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"),
		sigPollInterval: parseDurationDefault(os.Getenv("THEMIS_EPSSKEV_POLL_INTERVAL"), 24*time.Hour),

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

	kn := wiring.Wire(pool, cfg.evidenceURL, cfg.osvURL, publisher, wiring.NVDConfig{
		Enabled: cfg.nvdEnabled,
		BaseURL: cfg.nvdURL,
		APIKey:  cfg.nvdAPIKey,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}, wiring.SignalsConfig{
		Enabled:      cfg.sigEnabled,
		EPSSURL:      cfg.epssURL,
		KEVURL:       cfg.kevURL,
		ExploitDBURL: cfg.exploitDBURL,
		HTTP:         &http.Client{Timeout: 120 * time.Second},
	})

	go relayLoop(kn.Relay, logger.Component("relay"))

	// Scheduled NVD modified-since watch (D5): enriches already-carded CVEs with authoritative
	// CVSS/severity. Off unless THEMIS_NVD_ENABLED=1.
	if kn.Watch != nil {
		go watchLoop(kn.Watch, cfg.nvdPollInterval, logger.Component("watch"))
		logger.Info("nvd modified-since watch enabled", observability.String("interval", cfg.nvdPollInterval.String()))
	}

	// Scheduled exploit-signal enrichment (D5): folds EPSS/KEV/public-exploit onto already-carded
	// CVEs. Off unless THEMIS_EPSSKEV_ENABLED=1.
	if kn.Signals != nil {
		go signalLoop(kn.Signals, cfg.sigPollInterval, logger.Component("signals"))
		logger.Info("exploit-signal enrichment enabled", observability.String("interval", cfg.sigPollInterval.String()))
	}

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

// watchLoop runs the scheduled NVD modified-since watch: one poll shortly after startup, then
// every interval. It enriches already-carded CVEs with authoritative NVD CVSS/severity; a
// failure is logged and retried next tick (the watermark only advances on a clean pass).
func watchLoop(watch *app.WatchService, interval time.Duration, logger *observability.Logger) {
	poll := func() {
		n, err := watch.Poll(context.Background())
		if err != nil {
			logger.Error("nvd watch poll failed", observability.Err(err))
			return
		}
		if n > 0 {
			logger.Info("nvd watch enriched cards", observability.Int("folded", n))
		}
	}
	time.Sleep(15 * time.Second) // let the service settle before the first (up-to-120-day) poll
	poll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		poll()
	}
}

// signalLoop runs the scheduled exploit-signal enrichment: one sweep shortly after startup,
// then every interval. It folds EPSS/KEV/public-exploit onto already-carded CVEs; a failure is
// logged and retried next tick (the sweep is idempotent).
func signalLoop(sig *app.SignalEnrichmentService, interval time.Duration, logger *observability.Logger) {
	sweep := func() {
		n, err := sig.Enrich(context.Background())
		if err != nil {
			logger.Error("exploit-signal enrichment failed", observability.Err(err))
			return
		}
		if n > 0 {
			logger.Info("exploit-signal enrichment folded", observability.Int("folded", n))
		}
	}
	time.Sleep(20 * time.Second) // let the service settle; the bulk feeds are large
	sweep()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		sweep()
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

// parseDurationDefault parses a Go duration string, falling back to def when empty or invalid.
func parseDurationDefault(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
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

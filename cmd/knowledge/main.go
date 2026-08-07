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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/adapters/wiring"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string // THEMIS_KNOWLEDGE_ADDR — listen address (default ":8085"; NOT :8082, which is Registry).
	migrate        bool   // THEMIS_KNOWLEDGE_MIGRATE=1 — apply the knowledge migrations on startup.
	devPurge       bool   // THEMIS_KNOWLEDGE_DEV_PURGE=1 — expose DELETE /dev/knowledge (dev only).
	migrationsPath string // THEMIS_KNOWLEDGE_MIGRATIONS — path to the knowledge migrations dir.
	evidenceURL    string // THEMIS_EVIDENCE_URL — Evidence read-API base URL (inventory source; default "http://localhost:8081").
	osvURL         string // THEMIS_OSV_URL — OSV query base URL (lazy discovery; default "https://api.osv.dev").

	nvdEnabled       bool          // THEMIS_NVD_ENABLED=1 — enable the scheduled NVD modified-since watch (enriches already-carded CVEs with authoritative CVSS/severity; default off).
	nvdURL           string        // THEMIS_NVD_URL — NVD 2.0 CVE API base URL (empty → the client default, services.nvd.nist.gov).
	nvdAPIKey        string        // THEMIS_NVD_API_KEY — NVD API key (higher rate limit; optional).
	nvdDiscovery     bool          // THEMIS_NVD_DISCOVERY=1 — add NVD to correlation discovery: a per-component, CPE-product-gated keyword query so a CVE only NVD's CPE data covers still yields a finding (A2). Default off (external NVD call per component at correlation time; an NVD API key is strongly recommended for large inventories — NVD throttles).
	nvdStaleAfter    time.Duration // THEMIS_NVD_STALE_AFTER — how long a card's NVD facts stay fresh before the sweep revisits it (Go duration, default 168h). Revisiting is what catches revised scores and CVEs withdrawn upstream; an enrich-once sweep is correct on the day it runs and quietly stale months later.
	nvdBackfillLimit int           // THEMIS_NVD_BACKFILL_LIMIT — carded CVEs enriched per sweep (default 200). Cost is one small request per CVE, so this bounds a sweep to a predictable duration; a large estate drains over successive sweeps.
	nvdPollInterval  time.Duration // THEMIS_NVD_POLL_INTERVAL — Go duration between watch polls (default 6h; falls back to 6h if unparseable).
	// THEMIS_REATTRIBUTE_INTERVAL — Go duration between re-attribution sweeps (default 6h).
	// The sweep re-asks the discovery feeds about components already in the estate so cards
	// folded before fix-attribution existed gain it (KN-FIX-2). It is self-terminating: once
	// everything is attributed it finds nothing and writes nothing, so the cadence is cheap.
	reattributeInterval time.Duration

	sigEnabled      bool          // THEMIS_EPSSKEV_ENABLED=1 — enable the scheduled exploit-signal enrichment sweep (EPSS/KEV/ExploitDB → already-carded CVEs; default off).
	epssURL         string        // THEMIS_EPSS_URL — FIRST.org EPSS gzip-CSV URL (default the current-scores feed; empty skips EPSS).
	kevURL          string        // THEMIS_KEV_URL — CISA KEV JSON catalog URL (default; empty skips KEV).
	exploitDBURL    string        // THEMIS_EXPLOITDB_URL — ExploitDB files_exploits.csv URL (default; empty skips ExploitDB).
	sigPollInterval time.Duration // THEMIS_EPSSKEV_POLL_INTERVAL — Go duration between enrichment sweeps (default 24h; falls back to 24h if unparseable).

	redhatEnabled      bool          // THEMIS_REDHAT_ENABLED=1 — enable the scheduled Red Hat vendor feed (per-CVE vendor severity + not_affected applicability on already-carded CVEs; covers RHEL/Rocky/Alma; default off).
	redhatURL          string        // THEMIS_REDHAT_URL — Red Hat Security Data API base URL (empty → the public Hydra default; no API key needed).
	redhatPollInterval time.Duration // THEMIS_REDHAT_POLL_INTERVAL — Go duration between Red Hat sweeps (default 12h; falls back to 12h if unparseable).

	vexfeedEnabled      bool          // THEMIS_VEXFEED_ENABLED=1 — enable the generic CSAF-VEX vendor feed (per-CVE not_affected applicability on already-carded CVEs; default off).
	vexfeedURLs         []string      // THEMIS_VEXFEED_URLS — comma-separated CSAF-VEX directory base URLs (per-CVE files at /<year>/cve-<id>.json).
	vexfeedPollInterval time.Duration // THEMIS_VEXFEED_POLL_INTERVAL — Go duration between CSAF-VEX sweeps (default 12h; falls back to 12h if unparseable).

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database. When set, the relay publishes and the reader drains the Evidence stream; when empty, a logging publisher is used and the reader is disabled (single-context dev).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_KNOWLEDGE_ADDR", ":8085"),
		migrate:        os.Getenv("THEMIS_KNOWLEDGE_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_KNOWLEDGE_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_KNOWLEDGE_MIGRATIONS", "internal/knowledge/adapters/store/migrations"),
		evidenceURL:    envDefault("THEMIS_EVIDENCE_URL", "http://localhost:8081"),
		osvURL:         envDefault("THEMIS_OSV_URL", "https://api.osv.dev"),

		nvdEnabled:          os.Getenv("THEMIS_NVD_ENABLED") == "1",
		nvdURL:              os.Getenv("THEMIS_NVD_URL"),
		nvdAPIKey:           os.Getenv("THEMIS_NVD_API_KEY"),
		nvdDiscovery:        os.Getenv("THEMIS_NVD_DISCOVERY") == "1",
		nvdBackfillLimit:    envIntDefault("THEMIS_NVD_BACKFILL_LIMIT", app.DefaultBackfillLimit),
		nvdStaleAfter:       parseDurationDefault(os.Getenv("THEMIS_NVD_STALE_AFTER"), app.DefaultStaleAfter),
		nvdPollInterval:     parseDurationDefault(os.Getenv("THEMIS_NVD_POLL_INTERVAL"), 6*time.Hour),
		reattributeInterval: parseDurationDefault(os.Getenv("THEMIS_REATTRIBUTE_INTERVAL"), 6*time.Hour),

		sigEnabled:      os.Getenv("THEMIS_EPSSKEV_ENABLED") == "1",
		epssURL:         envDefault("THEMIS_EPSS_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz"),
		kevURL:          envDefault("THEMIS_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
		exploitDBURL:    envDefault("THEMIS_EXPLOITDB_URL", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"),
		sigPollInterval: parseDurationDefault(os.Getenv("THEMIS_EPSSKEV_POLL_INTERVAL"), 24*time.Hour),

		redhatEnabled:      os.Getenv("THEMIS_REDHAT_ENABLED") == "1",
		redhatURL:          os.Getenv("THEMIS_REDHAT_URL"),
		redhatPollInterval: parseDurationDefault(os.Getenv("THEMIS_REDHAT_POLL_INTERVAL"), 12*time.Hour),

		vexfeedEnabled:      os.Getenv("THEMIS_VEXFEED_ENABLED") == "1",
		vexfeedURLs:         splitCSV(os.Getenv("THEMIS_VEXFEED_URLS")),
		vexfeedPollInterval: parseDurationDefault(os.Getenv("THEMIS_VEXFEED_POLL_INTERVAL"), 12*time.Hour),

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
		Enabled:       cfg.nvdEnabled,
		BackfillLimit: cfg.nvdBackfillLimit,
		StaleAfter:    cfg.nvdStaleAfter,
		BaseURL:       cfg.nvdURL,
		APIKey:        cfg.nvdAPIKey,
		Discovery:     cfg.nvdDiscovery,
		// 180s, not 60s. A single 2000-record NVD page was measured at 5.2 MB / 83.6 seconds on
		// 2026-08-07 — server-side generation time, not throttling — so the old 60s ceiling
		// killed the request mid-body and failed the whole poll.
		HTTP: &http.Client{Timeout: 180 * time.Second},
	}, wiring.SignalsConfig{
		Enabled:      cfg.sigEnabled,
		EPSSURL:      cfg.epssURL,
		KEVURL:       cfg.kevURL,
		ExploitDBURL: cfg.exploitDBURL,
		HTTP:         &http.Client{Timeout: 120 * time.Second},
	}, wiring.RedHatConfig{
		Enabled: cfg.redhatEnabled,
		BaseURL: cfg.redhatURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}, wiring.VexfeedConfig{
		Enabled:  cfg.vexfeedEnabled,
		BaseURLs: cfg.vexfeedURLs,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	})

	go relayLoop(kn.Relay, logger.Component("relay"))

	// Re-attribution (KN-FIX-2). Always on: it needs no feed the node is not already using.
	if kn.Reattribute != nil {
		go reattributeLoop(kn.Reattribute, cfg.reattributeInterval, logger.Component("reattribute"))
	}

	// Scheduled NVD enrichment (D5/D5a): fetches each carded CVE by id and folds authoritative
	// CVSS/severity onto its card. Off unless THEMIS_NVD_ENABLED=1.
	if kn.Backfill != nil {
		go backfillLoop(kn.Backfill, kn.Health, cfg.nvdPollInterval, logger.Component("nvd"))
		logger.Info("nvd per-CVE enrichment enabled",
			observability.String("interval", cfg.nvdPollInterval.String()),
			observability.Int("cves_per_sweep", cfg.nvdBackfillLimit),
			observability.String("stale_after", cfg.nvdStaleAfter.String()))
	}

	// Scheduled exploit-signal enrichment (D5): folds EPSS/KEV/public-exploit onto already-carded
	// CVEs. Off unless THEMIS_EPSSKEV_ENABLED=1.
	if kn.Signals != nil {
		go signalLoop(kn.Signals, kn.Health, cfg.sigPollInterval, logger.Component("signals"))
		logger.Info("exploit-signal enrichment enabled", observability.String("interval", cfg.sigPollInterval.String()))
	}

	// Scheduled Red Hat vendor feed (D5, parity B3): folds vendor severity + not_affected
	// applicability onto already-carded CVEs (covers RHEL/Rocky/Alma). Off unless THEMIS_REDHAT_ENABLED=1.
	if kn.RedHat != nil {
		go redhatLoop(kn.RedHat, kn.Health, cfg.redhatPollInterval, logger.Component("redhat"))
		logger.Info("red hat vendor feed enabled", observability.String("interval", cfg.redhatPollInterval.String()))
	}

	// Scheduled generic CSAF-VEX vendor feed (D5, parity B4): folds not_affected applicability from
	// the configured vendor feeds onto already-carded CVEs. Off unless THEMIS_VEXFEED_ENABLED=1.
	if kn.Vexfeed != nil {
		go vexfeedLoop(kn.Vexfeed, kn.Health, cfg.vexfeedPollInterval, logger.Component("vexfeed"))
		logger.Info("csaf-vex vendor feed enabled",
			observability.Int("bases", len(cfg.vexfeedURLs)), observability.String("interval", cfg.vexfeedPollInterval.String()))
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
	// Operational metrics, OUTSIDE the authenticated /api/v1 group: this is data for the
	// platform's own scraper, carries no business content, and gating it would mean handing
	// scrape credentials to monitoring.
	router.Handle("/metrics", observability.Default().Handler())
	closeAuth := authedMount(ctx, router, cfg, logger, kn.Handler)
	defer closeAuth()
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

// recordFeed records a scheduled feed poll's outcome into feed-health (B1): a success when
// pollErr is nil, otherwise a failure, tagged with the source's intelligence tier. A recording
// error is logged, never fatal — health is observability, not the pipeline.
func recordFeed(health *app.FeedHealthService, source string, pollErr error, logger *observability.Logger) {
	var rerr error
	if pollErr != nil {
		rerr = health.RecordFailure(context.Background(), source, feed.TierFor(source))
	} else {
		rerr = health.RecordSuccess(context.Background(), source, feed.TierFor(source))
	}
	if rerr != nil {
		logger.Error("record feed health failed", observability.String("source", source), observability.Err(rerr))
	}
}

// watchLoop runs the scheduled NVD modified-since watch: one poll shortly after startup, then
// every interval. It enriches already-carded CVEs with authoritative NVD CVSS/severity; a
// failure is logged and retried next tick (the watermark only advances on a clean pass).
// reattributeLoop re-asks the discovery feeds about components already in the estate, so cards
// folded before fix-attribution existed gain it without waiting for a new SBOM (KN-FIX-2).
//
// It runs on the same cadence as the NVD sweep because it drains the same way: bounded per run,
// idempotent (the aggregate drops verbatim restatements), and self-terminating — once every card
// is attributed the query returns nothing and the sweep writes nothing. It is not gated behind a
// feature flag because it rides the always-on OSV discovery source, not an opt-in feed.
func reattributeLoop(rs *app.ReattributeService, interval time.Duration, logger *observability.Logger) {
	sweep := func() {
		n, err := rs.Sweep(context.Background())
		if err != nil {
			logger.Error("re-attribution sweep failed", observability.Err(err))
			return
		}
		// Logged on every sweep including zero: "everything is attributed" and "the sweep stopped
		// working" must not look alike (the same reasoning as NVD-WATCH-1).
		logger.Info("re-attribution sweep complete", observability.Int("folded", n))
	}
	sweep()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		sweep()
	}
}

// backfillLoop runs the per-CVE NVD enrichment sweep on a fixed cadence (D5a).
//
// Simpler than the window walk it replaces, because there is no window: each run asks the store
// which carded CVEs still lack an NVD Proposal, fetches those by id, and stops at the cap. There
// is no watermark to advance and therefore no way to skip — the queue IS the state, and a CVE
// stays on it until it is enriched.
func backfillLoop(bf *app.BackfillService, health *app.FeedHealthService, interval time.Duration, logger *observability.Logger) {
	sweep := func() {
		n, err := bf.Enrich(context.Background())
		if err != nil {
			logger.Error("nvd enrichment sweep failed", observability.Err(err))
			recordFeed(health, "nvd", err, logger)
			observability.Default().RecordFeedPoll("nvd", observability.FeedPollFailed)
			return
		}
		recordFeed(health, "nvd", nil, logger)
		// Logged on EVERY sweep including a zero fold: an estate with nothing left to enrich and
		// a feed that has stopped working must not look alike (NVD-WATCH-1).
		logger.Info("nvd enrichment sweep complete", observability.Int("folded", n))
		observability.Default().RecordFeedPoll("nvd", observability.FeedPollComplete)
		observability.Default().RecordFeedRecords("nvd", observability.FeedRecordsFolded, n)
	}
	time.Sleep(15 * time.Second) // let the service settle before the first sweep
	sweep()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		sweep()
	}
}

// signalLoop runs the scheduled exploit-signal enrichment: one sweep shortly after startup,
// then every interval. It folds EPSS/KEV/public-exploit onto already-carded CVEs; a failure is
// logged and retried next tick (the sweep is idempotent).
func signalLoop(sig *app.SignalEnrichmentService, health *app.FeedHealthService, interval time.Duration, logger *observability.Logger) {
	sweep := func() {
		n, err := sig.Enrich(context.Background())
		if err != nil {
			logger.Error("exploit-signal enrichment failed", observability.Err(err))
			recordFeed(health, "epsskev", err, logger)
			return
		}
		recordFeed(health, "epsskev", nil, logger)
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

// redhatLoop runs the scheduled Red Hat vendor feed: one sweep shortly after startup, then every
// interval. It folds vendor severity + not_affected applicability onto already-carded CVEs
// (relevance-bounded, per-CVE Hydra fetch); a failure is logged and retried next tick (the sweep
// is idempotent). A CVE Red Hat does not track is skipped inside the sweep, not an error.
func redhatLoop(rh *app.RedHatEnrichmentService, health *app.FeedHealthService, interval time.Duration, logger *observability.Logger) {
	sweep := func() {
		n, err := rh.Enrich(context.Background())
		if err != nil {
			logger.Error("red hat enrichment failed", observability.Err(err))
			recordFeed(health, "redhat", err, logger)
			return
		}
		recordFeed(health, "redhat", nil, logger)
		if n > 0 {
			logger.Info("red hat enrichment folded", observability.Int("folded", n))
		}
	}
	time.Sleep(25 * time.Second) // let the service settle; per-CVE fetches scale with the card set
	sweep()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		sweep()
	}
}

// vexfeedLoop runs the scheduled generic CSAF-VEX vendor feed: one sweep shortly after startup,
// then every interval. It folds not_affected applicability from the configured vendor feeds onto
// already-carded CVEs; a failure is logged and retried next tick (the sweep is idempotent).
func vexfeedLoop(vf *app.VexEnrichmentService, health *app.FeedHealthService, interval time.Duration, logger *observability.Logger) {
	sweep := func() {
		n, err := vf.Enrich(context.Background())
		if err != nil {
			logger.Error("csaf-vex enrichment failed", observability.Err(err))
			recordFeed(health, "vexfeed", err, logger)
			return
		}
		recordFeed(health, "vexfeed", nil, logger)
		if n > 0 {
			logger.Info("csaf-vex enrichment folded", observability.Int("folded", n))
		}
	}
	time.Sleep(30 * time.Second) // let the service settle; per-CVE fetches scale with the card set
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

// envIntDefault reads an int knob, falling back to def when unset or unparseable.
func envIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
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

// splitCSV splits a comma-separated env value into trimmed, non-empty entries.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type logPublisher struct{ logger *observability.Logger }

func (p logPublisher) Publish(_ context.Context, env event.Envelope) error {
	p.logger.Info("published envelope",
		observability.String("id", env.ID), observability.String("type", env.Type),
		observability.String("subject", env.Subject))
	return nil
}

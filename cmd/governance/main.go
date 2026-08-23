// Command governance runs the Governance bounded context as an independent service
// (EDR-GOVERNANCE-01 D13): the authority for Findings + Enterprise Positions. It serves the
// triage + read REST API, drains the transactional outbox to publish Position/lifecycle
// events, and accepts inbound Knowledge events (ComponentMatched / FaultlineEnriched /
// FaultlineSuperseded) that open-or-update Findings and raise re-evaluation proposals.
// Composition (adapters -> app ports) lives in internal/governance/adapters/wiring.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/adapters/intelligence"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/adapters/wiring"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/health"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn             string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr            string // THEMIS_GOVERNANCE_ADDR — listen address (default ":8083").
	migrate         bool   // THEMIS_GOVERNANCE_MIGRATE=1 — apply the governance migrations on startup.
	devPurge        bool   // THEMIS_GOVERNANCE_DEV_PURGE=1 — expose DELETE /dev/governance (dev only; never in production).
	migrationsPath  string // THEMIS_GOVERNANCE_MIGRATIONS — path to the governance migrations dir.
	aiEnabled       bool   // THEMIS_GOVERNANCE_AI_ENABLED=1 (and THEMIS_INTELLIGENCE_ENABLED!=0) — wire the real Intelligence client (D13 disable gate).
	intelligenceURL string // THEMIS_INTELLIGENCE_URL — Intelligence Gateway base URL (when AI enabled).
	// THEMIS_INTELLIGENCE_TIMEOUT — how long Governance waits for a recommendation (Go duration,
	// default 60s). It must be >= the Gateway's own per-invocation budget (THEMIS_LLM_TIMEOUT on
	// the Intelligence node), because whichever deadline is SHORTER decides. When this one fires
	// first, Governance hangs up, the Gateway sees its request context cancelled mid-provider-call
	// and reports `provider_error` — so a caller-side timeout is misread as an Intelligence fault.
	intelligenceTimeout time.Duration
	registryURL         string // THEMIS_REGISTRY_URL — Registry read-API base URL for the blast-radius multiplier (C2); empty ⇒ the multiplier defaults to 1.0 (fail-safe, no estate amplification).
	knowledgeURL        string // THEMIS_KNOWLEDGE_URL — Knowledge read-API base URL feeding the FindingAssessment Domain Projection (EDR-TRUST-01 T10); empty ⇒ the projection carries the Finding alone (fail-safe, no enrichment).
	evidenceURL         string // THEMIS_EVIDENCE_URL — Evidence read-API base URL for the compare read's evidence-presence guard (EDR-GOVERNANCE-01 D16); empty ⇒ GET /releases/{id}/compare/{candidate} refuses (fail-CLOSED — a compare that cannot verify evidence would over-claim "fixed"). Every other read is unaffected.
	blastRadiusCap      int    // THEMIS_BLAST_RADIUS_CAP — unique-customer count at which the blast multiplier saturates to 2.0× (C2). Default 10 (legacy `intelligence.blast_radius_cap` parity); values < 2 are normalized to the default.
	autoAccept          string // THEMIS_GOVERNANCE_AUTOACCEPT — the Governance-owned auto-accept policy (EDR-GOVERNANCE-01 D15). `observed_not_affected` (default) ships one rule: open + system-raised + not_affected + evidence class `observed` (re-derivable — the version-range verdict and upstream CVE withdrawal). `off` disables auto-accept entirely, so every suppression waits for a human. Vendor VEX (Asserted) is deliberately NOT auto-accepted under either setting.
	// THEMIS_EPSS_DRIFT_THRESHOLD — the EPSS rise that re-surfaces a SUPPRESSED Finding
	// (GOV-14b / D14). Default 0.20, ABSOLUTE not relative: 0.02 → 0.25 is a fringe CVE becoming
	// a likely one, while 0.60 → 0.75 is the same story told louder. This is the safety net under
	// `residual_priority` — zeroing a not_affected / accepted_risk Finding removes it from the
	// queue, which is only safe because this brings it back when the premise moves. An
	// out-of-range value falls back to the default; a misconfigured knob must not disable it.
	epssDriftThreshold float64
	mitigatedWeight    float64 // THEMIS_MITIGATED_WEIGHT — stance weight for `mitigated` in residual_priority (EDR-GOVERNANCE-01 D14). Default 0.5; must be in (0,1]. The other weights are structural and not configurable: not_affected/accepted_risk 0, deferred 0.9, everything open 1.0.

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database holding the event_log. When set, the outbox relay publishes to the real event bus (EB-04); when empty, a logging stand-in is used (single-context dev without the bus).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations to THEMIS_BUS_DATABASE_DSN on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).
}

func loadConfig() config {
	return config{
		dsn:                 os.Getenv("THEMIS_DATABASE_DSN"),
		addr:                envDefault("THEMIS_GOVERNANCE_ADDR", ":8083"),
		migrate:             os.Getenv("THEMIS_GOVERNANCE_MIGRATE") == "1",
		devPurge:            os.Getenv("THEMIS_GOVERNANCE_DEV_PURGE") == "1",
		migrationsPath:      envDefault("THEMIS_GOVERNANCE_MIGRATIONS", "internal/governance/adapters/store/migrations"),
		aiEnabled:           os.Getenv("THEMIS_GOVERNANCE_AI_ENABLED") == "1" && os.Getenv("THEMIS_INTELLIGENCE_ENABLED") != "0",
		intelligenceURL:     envDefault("THEMIS_INTELLIGENCE_URL", "http://localhost:8086"),
		intelligenceTimeout: envDurationDefault("THEMIS_INTELLIGENCE_TIMEOUT", 60*time.Second),
		registryURL:         envDefault("THEMIS_REGISTRY_URL", "http://localhost:8082"),
		knowledgeURL:        envDefault("THEMIS_KNOWLEDGE_URL", "http://localhost:8085"),
		evidenceURL:         envDefault("THEMIS_EVIDENCE_URL", "http://localhost:8081"),
		blastRadiusCap:      envIntDefault("THEMIS_BLAST_RADIUS_CAP", domain.DefaultBlastRadiusCap),
		autoAccept:          envDefault("THEMIS_GOVERNANCE_AUTOACCEPT", autoAcceptObservedNotAffected),
		mitigatedWeight:     envFloatDefault("THEMIS_MITIGATED_WEIGHT", domain.DefaultMitigatedWeight),
		epssDriftThreshold:  envFloatDefault("THEMIS_EPSS_DRIFT_THRESHOLD", domain.DefaultEPSSDriftThreshold),

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

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("governance"))
	if err != nil {
		log.Fatalf("governance: observability: %v", err)
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

	// Disable gate (D13): one wiring choice — the real Intelligence client enables AI,
	// the no-op advisor disables it. The pipeline is correct either way.
	var advisor app.PositionAdvisor = intelligence.NoopAdvisor{}
	if cfg.aiEnabled {
		advisor = intelligence.NewClient(cfg.intelligenceURL, &http.Client{Timeout: cfg.intelligenceTimeout})
		logger.Info("AI enrichment enabled", observability.String("intelligence_url", cfg.intelligenceURL))
	}

	busPool, closeBus := openBus(ctx, cfg, logger)
	defer closeBus()

	var publisher store.Publisher = logPublisher{logger}
	if busPool != nil {
		publisher = eventbus.NewPublisher(busPool)
	}

	gov := wiring.Wire(pool, publisher, advisor, cfg.registryURL, cfg.knowledgeURL, cfg.evidenceURL,
		cfg.blastRadiusCap, cfg.mitigatedWeight, cfg.epssDriftThreshold,
		autoAcceptPolicies(cfg.autoAccept, logger)...)

	go relayLoop(gov.Reconcile, logger.Component("reconcile"))

	// The bus reader drives Finding open/update + re-evaluation off the Knowledge stream
	// (EB-07/08). Without a bus it is disabled — inbound events then arrive only over the
	// /internal HTTP seam below (dev).
	if busPool != nil {
		reader := inbound.Subscription.NewReader(busPool, logger.Component("reader"),
			store.NewInboxConsumer(pool, gov.Consumer))
		go readerLoop(reader, logger.Component("reader"))
		logger.Info("knowledge-stream reader enabled")
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
	closeAuth := authedMount(ctx, router, cfg, logger, gov.Handler)
	defer closeAuth()

	// Inbound Knowledge-event intake. Until the Event Infrastructure (M5) bus reader lands,
	// the seam is fed over HTTP with the full kernel Envelope JSON (the reader will call the
	// same Consumer.Handle). A body carrying only {"type","payload"} still decodes — the
	// unset envelope fields are transport metadata the ACL does not read.
	router.Post("/internal/knowledge-events", func(w http.ResponseWriter, r *http.Request) {
		var env event.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := gov.Consumer.Handle(r.Context(), env); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if cfg.devPurge {
		router.Delete("/dev/governance", func(w http.ResponseWriter, r *http.Request) {
			if err := gov.Store.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/governance)")
	}

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// relayLoop drains the transactional outbox on a fixed cadence via the state-based
// reconciler (D12) — publishing Position/lifecycle events. The publisher is a logging
// stand-in until the Event Infrastructure (M5) event bus is available.
func relayLoop(recon *app.ReconcileService, logger *observability.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := recon.Reconcile(context.Background()); err != nil {
			logger.Error("reconcile failed", observability.Err(err))
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

// envDurationDefault reads a Go duration env var, falling back to def when unset or unparseable.
func envDurationDefault(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// envIntDefault reads an integer env var, falling back to def when unset, empty, or unparseable
// (the wiring layer further normalizes out-of-range values, so a bad value degrades to the
// default rather than failing startup).
func envIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Auto-accept policy names for THEMIS_GOVERNANCE_AUTOACCEPT (EDR-GOVERNANCE-01 D15).
const (
	autoAcceptObservedNotAffected = "observed_not_affected"
	autoAcceptOff                 = "off"
)

// autoAcceptPolicies resolves the configured Governance-owned auto-accept policy (D15).
//
// It is logged either way, and that is deliberate: which suppressions happen without a human is
// the kind of thing an operator must be able to read off a node's startup line rather than infer
// from behaviour. The empty-policy state is exactly what made the EDR-TRUST-01 T4 constitutional
// bar unobservable on the VM (TRUST-7) — "barred by the constitution" and "no policy configured"
// looked identical — so `off` now announces itself instead of being the silent default.
//
// An unrecognized value falls back to the default rather than failing startup, and says so. A
// typo must not silently disable governance automation, nor take a node down.
func autoAcceptPolicies(name string, logger *observability.Logger) []domain.PolicyRule {
	switch name {
	case autoAcceptOff:
		logger.Info("auto-accept DISABLED — every proposal, including provable not_affected, waits for a human",
			observability.String("policy", autoAcceptOff))
		return nil
	case autoAcceptObservedNotAffected:
	default:
		logger.Warn("unknown THEMIS_GOVERNANCE_AUTOACCEPT — falling back to the default policy",
			observability.String("given", name), observability.String("using", autoAcceptObservedNotAffected))
	}
	rule := domain.AutoAcceptObservedNotAffectedPolicy()
	logger.Info("auto-accept policy enabled: system-raised not_affected on observed evidence only "+
		"(vendor VEX is Asserted and still waits for a human)", observability.String("policy", rule.Name()))
	return []domain.PolicyRule{rule}
}

// envFloatDefault reads a float knob, falling back to def when unset or unparseable. Out-of-range
// values are rejected here as well as in the domain: a weight outside (0,1] would either suppress
// Findings that should still be triaged or inflate one past its intrinsic priority, and neither
// is worth failing startup over when a sane default exists.
func envFloatDefault(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			return f
		}
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

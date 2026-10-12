// Command evidence runs the Evidence bounded context as an independent service:
// the REST API plus a transactional-outbox relay loop. Composition (adapters ->
// app ports) lives in internal/evidence/adapters/wiring so the binary and the
// e2e tests share identical wiring.
package main

import (
	"context"
	"errors"
	"fmt"
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

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/adapters/wiring"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/health"
	"github.com/themis-project/themis/internal/platform/observability"
	registrystore "github.com/themis-project/themis/internal/registry/adapters/store"
	registryapp "github.com/themis-project/themis/internal/registry/app"
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

	// The single intake door (EDR-INTAKE-01).
	intakeMaxBytes     int64         // THEMIS_INTAKE_MAX_BYTES — request-body bound, checked before the body is buffered (D13). Default 67108864 (64 MiB).
	intakeInlineBudget time.Duration // THEMIS_INTAKE_INLINE_BUDGET — how long intake works before answering 202 with a receipt to come back to (D9). Default 5s.
	intakeReceiptTTL   time.Duration // THEMIS_INTAKE_RECEIPT_TTL — how long receipts are retained before the hourly sweep deletes them. Receipts are operational records, not evidence. Default 720h (30d).
	knowledgeURL       string        // THEMIS_KNOWLEDGE_URL — Knowledge read-API base URL, for a terminal receipt's `unresolved` next_check (D10). Empty ⇒ the check is omitted, never a broken URL.
	governanceURL      string        // THEMIS_GOVERNANCE_URL — Governance read-API base URL, for a terminal receipt's `posture` next_check (D10). Empty ⇒ omitted.
}

// loadConfig reads the environment, and FAILS rather than falling back when a value
// is present but unusable.
//
// The distinction is the whole of it: an unset duration means "take the documented
// default", and a misspelled one means the operator asked for something specific and
// did not get it. Silently serving the default there is how a node runs for weeks
// with a retention or budget nobody chose.
func loadConfig() (config, error) {
	maxBytes, err := envBytes("THEMIS_INTAKE_MAX_BYTES", evhttp.DefaultMaxBytes)
	if err != nil {
		return config{}, err
	}
	inlineBudget, err := envDuration("THEMIS_INTAKE_INLINE_BUDGET", evhttp.DefaultInlineBudget)
	if err != nil {
		return config{}, err
	}
	receiptTTL, err := envDuration("THEMIS_INTAKE_RECEIPT_TTL", evhttp.DefaultReceiptTTL)
	if err != nil {
		return config{}, err
	}
	cfg := newConfig()
	cfg.intakeMaxBytes = maxBytes
	cfg.intakeInlineBudget = inlineBudget
	cfg.intakeReceiptTTL = receiptTTL
	return cfg, nil
}

func newConfig() config {
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

		knowledgeURL:  os.Getenv("THEMIS_KNOWLEDGE_URL"),
		governanceURL: os.Getenv("THEMIS_GOVERNANCE_URL"),
	}
}

func main() {
	ctx := context.Background()
	cfg, cfgErr := loadConfig()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("evidence"))
	if err != nil {
		log.Fatalf("evidence: observability: %v", err)
	}
	defer func() { _ = shutdownObs(context.Background()); _ = logger.Sync() }()

	if cfgErr != nil {
		logger.Error("startup aborted: configuration is invalid", observability.Err(cfgErr))
		os.Exit(1)
	}

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

	var registryRead subjectref.Registry
	if len(cfg.knownReleases) > 0 {
		registryRead = subjectref.NewStub(cfg.knownReleases...)
		logger.Info("SubjectRef = dev stub", observability.Int("known_releases", len(cfg.knownReleases)))
	} else {
		registryRead = registryReader{store: registrystore.New(pool)}
		logger.Info("SubjectRef = registry-backed (registry.ReleaseExists)")
	}
	apiHandler, st, intake := wiring.EvidenceAPI(wiring.Config{
		Pool:     pool,
		Registry: registryRead,
		Report:   parseLogger{logger.Component("parser")},
		Logger:   logger.Component("intake"),
		Intake: evhttp.IntakeConfig{
			MaxBytes:      cfg.intakeMaxBytes,
			InlineBudget:  cfg.intakeInlineBudget,
			KnowledgeURL:  cfg.knowledgeURL,
			GovernanceURL: cfg.governanceURL,
		},
	})
	defer intake.Close()

	// A receipt advances in the process doing the work, so a process that died
	// mid-intake left one stuck non-terminal — and a client polling `status_url`
	// would wait on a goroutine that no longer exists. Closed out here, before the
	// first request, because the only process that can tell is the next one.
	if n, err := intake.RecoverInterruptedReceipts(ctx); err != nil {
		logger.Error("intake receipt recovery failed", observability.Err(err))
	} else if n > 0 {
		logger.Warn("intake receipts were interrupted by a restart and are now failed",
			observability.Int("receipts", n))
	}
	go receiptSweepLoop(st, cfg.intakeReceiptTTL, logger.Component("intake"))

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

// receiptSweepLoop deletes intake receipts past their TTL, hourly.
//
// Receipts are OPERATIONAL records — the record that someone tried, including the
// attempts that were refused — not evidence, which is why deleting them is a
// retention policy and not a hole in CON-0007's immutability. Nothing reachable from
// a receipt is removed with it.
func receiptSweepLoop(st *store.Store, ttl time.Duration, logger *observability.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		n, err := st.PurgeExpiredReceipts(context.Background(), time.Now().UTC().Add(-ttl))
		if err != nil {
			logger.Error("intake receipt sweep failed", observability.Err(err))
			continue
		}
		if n > 0 {
			logger.Info("intake receipts swept",
				observability.Int("deleted", n), observability.String("ttl", ttl.String()))
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

// envDuration reads a Go duration ("5s", "720h"). Unset takes the default; present
// but unparseable or non-positive is an ERROR, never a silent fallback.
func envDuration(key string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration (e.g. 5s, 720h): %w", key, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s=%q must be positive", key, raw)
	}
	return d, nil
}

// envBytes reads a byte count. Same rule: unset takes the default, unusable fails.
func envBytes(key string, def int64) (int64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a byte count: %w", key, raw, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s=%q must be positive; a border is protected by bounds, and there is no unlimited setting", key, raw)
	}
	return n, nil
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

// registryReader backs Evidence's SubjectRef port and intake's read-only release
// resolution with the registry's own read queries (EDR-KERNEL-01 D1;
// EDR-EVIDENCE-01 D5; EDR-INTAKE-01 D7). In-process it queries the registry's own
// tables in the shared database; the registry owns and migrates them (run
// cmd/registry).
//
// READS ONLY, and the composition root is the only place this may be assembled: a
// write from Evidence into Registry is neither an event nor a read, and intake
// resolving identity it could also create would let one typo in a product name
// silently fork the estate graph.
type registryReader struct{ store *registrystore.Store }

func (v registryReader) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return v.store.ReleaseExists(ctx, releaseID)
}

// The name half of the seam is THIN delegation plus one translation (EDR-INTAKE-01 B4).
// The registry owns the matching rule — names fold case, a version is exact, and a name
// that matches more than one row abstains — because that rule has to agree with the unique
// indexes the registry built, and a second copy of it here would be a copy that drifts.
//
// What this layer owns is the translation: an empty id means "not found", which the
// resolver reports as `unknown_release` naming the part that missed, and the registry's
// ambiguity sentinel becomes Evidence's own, so no registry error value crosses the seam.

// ProductIDByName resolves an EXACT product name, abstaining on anything but a single match.
func (v registryReader) ProductIDByName(ctx context.Context, name string) (string, error) {
	id, err := v.store.ProductIDByName(ctx, name)
	return id, translateAmbiguous(err)
}

// ProjectIDByName resolves an exact project name within a product, abstaining the same way.
func (v registryReader) ProjectIDByName(ctx context.Context, productID, name string) (string, error) {
	id, err := v.store.ProjectIDByName(ctx, productID, name)
	return id, translateAmbiguous(err)
}

// ReleaseIDByVersion resolves an exact version string within a project, abstaining the same
// way — it never picks the first of several, which is what it did before B4.
func (v registryReader) ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error) {
	id, err := v.store.ReleaseIDByVersion(ctx, projectID, version)
	return id, translateAmbiguous(err)
}

// translateAmbiguous restates the registry's abstention in Evidence's vocabulary. An error
// value is part of a package's surface, so handing the registry's sentinel to a subjectref
// consumer would make Evidence's read seam depend on the registry to say what "ambiguous"
// means — a cross-context import wearing a different hat. The composition root is where the
// two contexts legitimately meet, so the translation lives here and nowhere else.
func translateAmbiguous(err error) error {
	if errors.Is(err, registryapp.ErrAmbiguousName) {
		return subjectref.ErrAmbiguousName
	}
	return err
}

type logPublisher struct{ logger *observability.Logger }

func (p logPublisher) Publish(_ context.Context, env event.Envelope) error {
	p.logger.Info("published envelope",
		observability.String("id", env.ID), observability.String("type", env.Type),
		observability.String("subject", env.Subject))
	return nil
}

// parseLogger surfaces one SBOM parse's outcome (EDR-IDENTITY-01 D6). The app ring never logs
// (CONVENTIONS R1), so the counts and warnings leave through a port and land here.
//
// Logged on EVERY parse, including one with nothing to report: "no unresolved components" and
// "the parser stopped checking" must not look alike. A non-zero `warnings` is the headline —
// chiefly entries the document NAMED but did not IDENTIFY, which never reach the inventory and
// therefore can never be correlated. Those warnings were discarded at the call site until
// 2026-09-17, so a document that lost a component said nothing at all.
type parseLogger struct{ log *observability.Logger }

func (l parseLogger) Parsed(format string, components int, warnings []string) {
	l.log.Info("sbom parsed",
		observability.String("format", format),
		observability.Int("components", components),
		observability.Int("warnings", len(warnings)))
	for _, w := range warnings {
		l.log.Warn("sbom parse warning", observability.String("detail", w))
	}
}

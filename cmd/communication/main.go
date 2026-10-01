// Command communication runs the Communication bounded context as an independent service
// (EDR-COMMUNICATION-01 D12): the publication surface. It serves the human-triggered
// publish + read/preview REST API, consumes Governance Position events into the
// publishable-positions worklist, delivers recorded Publications on their channels (exactly-
// once via the durable pending status), drains the terminal-event outbox, and prunes payload
// storage past the retention window. Composition lives in
// internal/communication/adapters/wiring.
package main

import (
	"context"
	"encoding/json"
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

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/adapters/wiring"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/health"
	"github.com/themis-project/themis/internal/platform/observability"
)

// config is read from the environment. Every option is documented here (the
// self-documented-config convention); there is no separate config reference.
type config struct {
	dsn            string // THEMIS_DATABASE_DSN — Postgres DSN (required).
	addr           string // THEMIS_COMMUNICATION_ADDR — listen address (default ":8084").
	governanceURL  string // THEMIS_GOVERNANCE_URL — Governance read-API base URL (default "http://localhost:8083").
	registryURL    string // THEMIS_REGISTRY_URL — Registry read-API base URL (release rollups' name chain, D13.4 fail-closed; default "http://localhost:8082").
	migrate        bool   // THEMIS_COMMUNICATION_MIGRATE=1 — apply the communication migrations on startup.
	devPurge       bool   // THEMIS_COMMUNICATION_DEV_PURGE=1 — expose DELETE /dev/communication (dev only).
	migrationsPath string // THEMIS_COMMUNICATION_MIGRATIONS — path to the communication migrations dir.

	busDSN            string // THEMIS_BUS_DATABASE_DSN — DSN of the platform `bus` database holding the event_log. When set, the outbox relay publishes to the real event bus (EB-04); when empty, a logging stand-in is used (single-context dev without the bus).
	busMigrate        bool   // THEMIS_BUS_MIGRATE=1 — apply the bus migrations to THEMIS_BUS_DATABASE_DSN on startup (dev convenience).
	busMigrationsPath string // THEMIS_BUS_MIGRATIONS — path to the bus migrations dir (default internal/platform/eventbus/migrations).

	authDSN      string // THEMIS_AUTH_DATABASE_DSN — DSN of the shared `auth` database (api_keys). When set, inbound /api/v1 requests require a valid X-API-Key (EDR-SECURITY-01); when empty, auth is disabled (dev) unless THEMIS_AUTH_REQUIRED=1.
	authRequired bool   // THEMIS_AUTH_REQUIRED=1 — hard-fail startup when THEMIS_AUTH_DATABASE_DSN is empty (production guard so a node can never boot open).

	// Outward actions (EDR-DELIVERY-01 N-M1a). The event reader only RECORDS a delivery
	// intent; these knobs govern the separate per-channel workers that try to send it, and
	// are deliberately isolated from the event bus's own retry envelope even though the
	// defaults mirror it (100ms → 30s): a slow mail relay must be givable more patience
	// without also making the governance stream more patient.
	deliveryMaxAttempts   int           // THEMIS_DELIVERY_MAX_ATTEMPTS — tries before an intent is DEAD_LETTERED (default 5).
	deliveryBackoffBase   time.Duration // THEMIS_DELIVERY_BACKOFF_BASE_MS — first retry wait, doubled per attempt (default 100).
	deliveryBackoffCap    time.Duration // THEMIS_DELIVERY_BACKOFF_CAP_MS — ceiling on that wait (default 30000).
	deliveryWorkerTick    time.Duration // THEMIS_DELIVERY_WORKER_INTERVAL_MS — how often each worker looks for due intents (default 500).
	deliveryEnableJira    bool          // THEMIS_DELIVERY_ENABLE_JIRA — "0" disables the jira_issue worker; its intents still accumulate as PENDING (default 1).
	deliveryEnableEmail   bool          // THEMIS_DELIVERY_ENABLE_EMAIL — "0" disables the email worker (default 1).
	deliveryEnableCI      bool          // THEMIS_DELIVERY_ENABLE_CI=1 — start the ci_build worker. DEFAULT OFF: no ci_build intent can exist at N-M1a (owner decision 2026-10-01 — CI arrives in N-M2 and the Governance event does not change), so the worker would poll for a kind that cannot occur.
	deliveryFakeJiraMode  string        // THEMIS_DELIVERY_FAKE_JIRA_MODE — success | fail | flaky. N-M1a ships FAKE senders only (default success).
	deliveryFakeEmailMode string        // THEMIS_DELIVERY_FAKE_EMAIL_MODE — success | fail | flaky (default success).
	deliveryFakeCIMode    string        // THEMIS_DELIVERY_FAKE_CI_MODE — success | fail | flaky (default success).
	deliveryOperatorAPI   bool          // THEMIS_DELIVERY_OPERATOR_API=1 — serve the four /delivery/intents routes. OFF by default: the API addition is an outstanding must-ask (EDR-DELIVERY-01 D15). Recording, the workers and dead-lettering run either way.
}

func loadConfig() config {
	return config{
		dsn:            os.Getenv("THEMIS_DATABASE_DSN"),
		addr:           envDefault("THEMIS_COMMUNICATION_ADDR", ":8084"),
		governanceURL:  envDefault("THEMIS_GOVERNANCE_URL", "http://localhost:8083"),
		registryURL:    envDefault("THEMIS_REGISTRY_URL", "http://localhost:8082"),
		migrate:        os.Getenv("THEMIS_COMMUNICATION_MIGRATE") == "1",
		devPurge:       os.Getenv("THEMIS_COMMUNICATION_DEV_PURGE") == "1",
		migrationsPath: envDefault("THEMIS_COMMUNICATION_MIGRATIONS", "internal/communication/adapters/store/migrations"),

		busDSN:            os.Getenv("THEMIS_BUS_DATABASE_DSN"),
		busMigrate:        os.Getenv("THEMIS_BUS_MIGRATE") == "1",
		busMigrationsPath: envDefault("THEMIS_BUS_MIGRATIONS", eventbus.DefaultMigrationsPath),

		authDSN:      os.Getenv("THEMIS_AUTH_DATABASE_DSN"),
		authRequired: os.Getenv("THEMIS_AUTH_REQUIRED") == "1",

		deliveryMaxAttempts:   envInt("THEMIS_DELIVERY_MAX_ATTEMPTS", 5),
		deliveryBackoffBase:   time.Duration(envInt("THEMIS_DELIVERY_BACKOFF_BASE_MS", 100)) * time.Millisecond,
		deliveryBackoffCap:    time.Duration(envInt("THEMIS_DELIVERY_BACKOFF_CAP_MS", 30000)) * time.Millisecond,
		deliveryWorkerTick:    time.Duration(envInt("THEMIS_DELIVERY_WORKER_INTERVAL_MS", 500)) * time.Millisecond,
		deliveryEnableJira:  envBoolDefaultOn("THEMIS_DELIVERY_ENABLE_JIRA"),
		deliveryEnableEmail: envBoolDefaultOn("THEMIS_DELIVERY_ENABLE_EMAIL"),
		// CI is OFF by default — owner decision 2026-10-01: CI build requests stay switched off
		// in N-M1a and arrive in N-M2 (the CI build step), and the Governance event is NOT to
		// change. So no `ci_build` intent can be recorded at this milestone, and a worker polling
		// for a kind that cannot occur is pure confusion: an operator reading "jira,email,ci" in
		// the startup line would reasonably conclude CI was live and wait for builds. Setting
		// THEMIS_DELIVERY_ENABLE_CI=1 still starts it, which is what N-M2 will flip by default.
		deliveryEnableCI:      os.Getenv("THEMIS_DELIVERY_ENABLE_CI") == "1",
		deliveryFakeJiraMode:  os.Getenv("THEMIS_DELIVERY_FAKE_JIRA_MODE"),
		deliveryFakeEmailMode: os.Getenv("THEMIS_DELIVERY_FAKE_EMAIL_MODE"),
		deliveryFakeCIMode:    os.Getenv("THEMIS_DELIVERY_FAKE_CI_MODE"),
		deliveryOperatorAPI:   os.Getenv("THEMIS_DELIVERY_OPERATOR_API") == "1",
	}
}

// outwardConfig assembles the outward-actions wiring input from the parsed environment.
func (c config) outwardConfig() wiring.OutwardConfig {
	return wiring.OutwardConfig{
		Intents: app.DeliveryIntentConfig{
			MaxAttempts: c.deliveryMaxAttempts,
			Backoff:     domain.BackoffPolicy{Base: c.deliveryBackoffBase, Cap: c.deliveryBackoffCap},
			Destination: app.DefaultIntentDestination,
		},
		Interval: c.deliveryWorkerTick,
		EnableFor: map[domain.DeliveryKind]bool{
			domain.DeliveryJiraIssue: c.deliveryEnableJira,
			domain.DeliveryEmail:     c.deliveryEnableEmail,
			domain.DeliveryCIBuild:   c.deliveryEnableCI,
		},
		FakeModes: map[domain.DeliveryKind]delivery.FakeMode{
			domain.DeliveryJiraIssue: delivery.ParseFakeMode(c.deliveryFakeJiraMode),
			domain.DeliveryEmail:     delivery.ParseFakeMode(c.deliveryFakeEmailMode),
			domain.DeliveryCIBuild:   delivery.ParseFakeMode(c.deliveryFakeCIMode),
		},
		OperatorAPI: c.deliveryOperatorAPI,
	}
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	logger, shutdownObs, err := observability.Setup(ctx, observability.ConfigFromEnv("communication"))
	if err != nil {
		log.Fatalf("communication: observability: %v", err)
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

	comm := wiring.Wire(pool, cfg.governanceURL, cfg.registryURL,
		delivery.NewLogDeliverer(logger.Component("delivery")), delivery.PassThroughRedactor{}, publisher,
		cfg.outwardConfig(), logger)

	go workerLoop(comm, logger.Component("worker"))

	// Outward actions (N-M1a): one worker per enabled channel, each on its own goroutine and
	// its own ticker, isolated from the bus reader below. A refusing channel dead-letters its
	// own intents and touches nothing else.
	comm.IntentWorkers.Run(ctx)
	logDeliveryState(ctx, comm, cfg, logger.Component("delivery"))

	// The bus reader drives the publishable-positions worklist off the Governance stream
	// (EB-07/08). Without a bus it is disabled — Position events then arrive only over the
	// /internal HTTP seam below (dev).
	if busPool != nil {
		reader := inbound.Subscription.NewReader(busPool, logger.Component("reader"),
			store.NewInboxConsumer(pool, comm.Consumer))
		go readerLoop(reader, logger.Component("reader"))
		logger.Info("governance-stream reader enabled")
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
	closeAuth := authedMount(ctx, router, cfg, logger, comm.Handler)
	defer closeAuth()

	// Inbound Governance Position-event intake. Until the Event Infrastructure (M5) bus
	// reader lands, the seam is fed over HTTP with the full kernel Envelope JSON (the reader
	// will call the same Consumer.Handle). A body carrying only {"type","payload"} still
	// decodes — the unset envelope fields are transport metadata the ACL does not read.
	router.Post("/internal/governance-events", func(w http.ResponseWriter, r *http.Request) {
		var env event.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := comm.Consumer.Handle(r.Context(), env); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if cfg.devPurge {
		router.Delete("/dev/communication", func(w http.ResponseWriter, r *http.Request) {
			if err := comm.Store.Purge(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		logger.Info("DEV purge route enabled (DELETE /dev/communication)")
	}

	logger.Info("listening", observability.String("addr", cfg.addr))
	if err := http.ListenAndServe(cfg.addr, router); err != nil {
		logger.Error("server failed", observability.Err(err))
		os.Exit(1)
	}
}

// workerLoop runs the background workers on a fixed cadence: deliver pending Publications,
// drain the terminal-event outbox (the state-based reconciler), and prune payloads past the
// retention window.
// workerLoop drives the PUBLICATION machinery and has nothing to do with outward-action delivery
// intents. The two are easy to confuse because both say "delivery", so, explicitly:
//
//   - THIS loop: `comm.Delivery` (`app.DeliveryService`) pushes a materialized **Publication**
//     artifact to its channel, plus outbox reconcile and payload retention. It is the pre-N-M1a
//     Communication worker and is unchanged by this milestone.
//   - `comm.IntentWorkers` (`adapters/delivery`, started separately in main): one worker per
//     delivery KIND draining `delivery_intents` — the outward actions of N-M1a.
//
// They share no state, no table, no ticker and no backoff: a Publication push cannot delay an
// intent send and vice versa. Consolidating them would couple two schedules that want different
// cadences for different reasons (2s for a local push; a per-intent `next_attempt_at` computed
// from a retry policy), so the separation is deliberate rather than leftover.
func workerLoop(comm wiring.Communication, logger *observability.Logger) {
	deliverTick := time.NewTicker(2 * time.Second)
	pruneTick := time.NewTicker(1 * time.Hour)
	defer deliverTick.Stop()
	defer pruneTick.Stop()
	ctx := context.Background()
	for {
		select {
		case <-deliverTick.C:
			if _, err := comm.Delivery.DeliverPending(ctx); err != nil {
				logger.Error("deliver failed", observability.Err(err))
			}
			if _, err := comm.Reconcile.Reconcile(ctx); err != nil {
				logger.Error("reconcile failed", observability.Err(err))
			}
		case <-pruneTick.C:
			if n, err := comm.Retention.Prune(ctx); err != nil {
				logger.Error("prune failed", observability.Err(err))
			} else if n > 0 {
				logger.Info("pruned payloads", observability.Int("count", n))
			}
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

// envInt reads a positive integer knob, falling back to the default for anything unset,
// unparseable or non-positive — a zero attempt budget or a zero tick would stop outward
// delivery silently, which is the one failure mode this milestone exists to prevent.
func envInt(key string, def int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// envBoolDefaultOn reads a switch that is ON unless it is explicitly "0".
func envBoolDefaultOn(key string) bool { return os.Getenv(key) != "0" }

// logDeliveryState states the outward-actions posture at startup: which channels have a
// worker, and how many intents sit in each status. An operator reading one line has to be
// able to tell "nothing to send" from "nothing is sending" — a dead-letter backlog with no
// worker enabled looks exactly like a healthy idle node otherwise. It is a READ; a failure
// to take it never blocks startup.
func logDeliveryState(ctx context.Context, comm wiring.Communication, cfg config, logger *observability.Logger) {
	kinds := make([]string, 0, len(comm.IntentWorkers))
	for _, w := range comm.IntentWorkers {
		kinds = append(kinds, string(w.Kind()))
	}
	logger.Info("outward-action workers started (FAKE senders — no real Jira/SMTP/CI at N-M1a)",
		observability.String("kinds", strings.Join(kinds, ",")),
		observability.Int("max_attempts", cfg.deliveryMaxAttempts),
		observability.Duration("interval", cfg.deliveryWorkerTick))

	// State the DORMANT path once, here, rather than per event. An operator watching a fresh
	// deployment will see `email` intents appear on every acceptance and no `ci_build` ones ever,
	// and the reason is not a misconfiguration: governance.proposal_accepted.v1 does not state the
	// accepted proposal's evidence schema, so the harness-backed case cannot be recognized yet
	// (EDR-DELIVERY-01 "Honest limits — N-M1a"). Saying it per accepted proposal would log a line
	// whose content never varies, on the one path that is always taken.
	// CI is a decided NOT-YET, not an accident, so the node says which it is either way.
	if cfg.deliveryEnableCI {
		logger.Warn("ci_build worker started, but NO ci_build intent can be recorded at N-M1a: " +
			"governance.proposal_accepted states no evidence schema and is not changing (owner decision). " +
			"This worker will poll and find nothing until N-M2 — unset THEMIS_DELIVERY_ENABLE_CI unless you are testing it.")
	} else {
		logger.Info("ci_build is OFF for N-M1a by decision: an acceptance records the e-mail intent only. " +
			"CI build requests arrive in N-M2 (the CI build step).")
	}

	// Whether the operator has a window onto all this is worth one unambiguous line. Off, a
	// dead letter still happens and is still counted — it just cannot be retried over the API,
	// and an operator who does not know that would read a 501 as a broken node.
	if cfg.deliveryOperatorAPI {
		logger.Info("delivery-intent operator API ENABLED at /api/v1/delivery/intents (admin-only, reads included)")
	} else {
		logger.Info("delivery-intent operator API DISABLED (default): /api/v1/delivery/intents answers 501. " +
			"Set THEMIS_DELIVERY_OPERATOR_API=1 to serve it. Failures are still recorded and counted — " +
			"see the dead_letter line in scripts/vm-verify.sh — but cannot be retried or cancelled over HTTP.")
	}

	counts, err := comm.Intents.IntentCounts(ctx)
	if err != nil {
		logger.Warn("could not read delivery-intent counts", observability.Err(err))
		return
	}
	logger.Info("delivery intents",
		observability.Int("pending", counts[domain.IntentPending]),
		observability.Int("delivered", counts[domain.IntentDelivered]),
		observability.Int("dead_letter", counts[domain.IntentDeadLetter]),
		observability.Int("cancelled", counts[domain.IntentCancelled]))
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

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/adapter/api"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/adapter/assetgraph"
	"github.com/themis-project/themis/internal/adapter/epsskev"
	"github.com/themis-project/themis/internal/adapter/exploitdb"
	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/nvd"
	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/redhat"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	"github.com/themis-project/themis/internal/infrastructure/metrics"
	"github.com/themis-project/themis/internal/infrastructure/queue"
	"github.com/themis-project/themis/internal/usecase/correlation"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
	"github.com/themis-project/themis/internal/usecase/triage"
	"github.com/themis-project/themis/internal/usecase/vexgen"
	"github.com/themis-project/themis/internal/usecase/watch"
)

// APIConfig configures REST API mounting.
type APIConfig struct {
	Pool           dbPool
	AppConfig      config.Config
	InProcessQueue *queue.InProcessQueue
	CVEFeedSuccess *atomic.Value
	// Logger is the unified domain logging port (CR-7). When nil a NopLogger is used.
	Logger domain.Logger
}

type dbPool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// nvdRateLimit returns an NVD-compliant request rate (requests/second) for the
// shared NVD client. NVD's published limits are 5 requests per rolling 30s
// without an API key and 50 per 30s with one; a positive nvd.rate_limit_rps
// overrides. The previous default of 5 req/s (~150 req/30s) tripped NVD's
// Cloudflare throttle, returning HTTP 503 challenge pages for every backfill
// and watch fetch.
func nvdRateLimit(cfg config.NVDConfig) float64 {
	if cfg.RateLimitRPS > 0 {
		return cfg.RateLimitRPS
	}
	if cfg.APIKey != "" {
		return 1.5 // ≈45 req/30s — under the 50/30s keyed limit
	}
	return 0.15 // ≈4.5 req/30s — under the 5/30s unkeyed limit
}

// presentOrAbsent reports whether a secret is set without revealing its value,
// for safe startup logging.
func presentOrAbsent(secret string) string {
	if secret != "" {
		return "present"
	}
	return "absent"
}

// MountAPI wires adapter handlers onto the HTTP router.
func MountAPI(ctx context.Context, r chi.Router, cfg APIConfig) {
	appLog := domain.LoggerOrNop(cfg.Logger)
	feedHealth := store.NewPostgresFeedHealthStore(cfg.Pool)
	vulnCatalog := store.NewPostgresVulnerabilityCatalog(cfg.Pool)
	nvdRate := nvdRateLimit(cfg.AppConfig.NVD)
	nvdClient := nvd.NewClient(nvd.ClientConfig{
		APIKey: cfg.AppConfig.NVD.APIKey,
		// Capacity 1 — no burst that would immediately blow NVD's rolling window.
		RateLimiter: nvd.NewTokenBucket(nvdRate, 1),
	})
	// Make the live NVD config observable at startup (D-LOG-1) so operators can
	// confirm the API key and rate were actually loaded — without ever logging the
	// key value itself.
	appLog.Info("nvd client configured",
		domain.LogString("api_key", presentOrAbsent(cfg.AppConfig.NVD.APIKey)),
		domain.LogAny("rate_limit_rps", nvdRate),
		domain.LogString("poll_interval", cfg.AppConfig.NVD.PollInterval.String()))
	jobs := store.NewPostgresIngestionRepository(cfg.Pool)
	trustRepo := trust.NewPostgresRepository(cfg.Pool)
	audit := trust.NewPostgresAuditRecorder(cfg.Pool)
	gate := &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trustRepo, Audit: audit}
	enrichmentRepo := store.NewPostgresEnrichmentRepository(cfg.Pool)
	graphStore := assetgraph.NewPostgresStore(cfg.Pool)
	vendorVEXStore := vexfeed.NewPostgresAssertionStore(cfg.Pool)
	vendorMatcher := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{
		Logger: vexfeed.LoggerMismatch{Log: appLog},
	}}
	enrichmentSvc := &enrichment.Handler{
		Repo:        enrichmentRepo,
		Audit:       audit,
		Layer2:      graphStore,
		TeamNotify:  notify.EnqueueSender{Queue: cfg.InProcessQueue},
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorVEXStore},
		VendorMatch: vendorMatcher,
		Metrics:     metrics.EnrichmentMetrics{},
	}
	threatSignals := store.NewPostgresThreatSignalStore(cfg.Pool)
	exploitStore := store.NewPostgresExploitStore(cfg.Pool)
	signalSources := store.CombinedSignalReader{Threat: threatSignals, Exploit: exploitStore}
	dispatcher := &ingestion.AsyncDispatcher{Queue: cfg.InProcessQueue}
	epssKevClient := epsskev.NewClient(epsskev.ClientConfig{
		EPSSURL: cfg.AppConfig.EPSSKev.EPSSURL,
		KEVURL:  cfg.AppConfig.EPSSKev.KEVURL,
	})
	metrics.RegisterPhase2a()
	epssKevSvc := &epsskev.Service{
		Fetcher:      epssKevClient,
		Store:        threatSignals,
		ReEnrich:     dispatcher,
		OpenFindings: enrichmentRepo,
		Metrics:      metrics.EPSSKevMetrics{},
	}
	StartEPSSKevScheduler(ctx, epssKevSvc, cfg.AppConfig.EPSSKev.PollInterval, appLog, feedHealth)
	exploitDBClient := exploitdb.NewClient(exploitdb.ClientConfig{CSVURL: cfg.AppConfig.ExploitDB.CSVURL})
	exploitDBSvc := &exploitdb.Service{
		Source:       exploitDBClient,
		Store:        exploitStore,
		ReEnrich:     dispatcher,
		OpenFindings: enrichmentRepo,
		Metrics:      metrics.ExploitDBMetrics{},
	}
	StartExploitDBScheduler(ctx, exploitDBSvc, cfg.AppConfig.ExploitDB.PollInterval, appLog, feedHealth)
	vexHTTP := &vexfeed.HTTPFetcher{}
	// themis-feed-registry: resolve the feed set from built-in defaults + the user
	// vexfeed.feeds delta list. CR-4 classes are preserved — overlay feeds carry
	// true Red Hat CSAF VEX; correlation feeds are distro OSV + RHSA advisories.
	overlayFeeds, correlationFeeds, feedWarnings := ResolveVEXFeeds(cfg.AppConfig.VEXFeed, vexHTTP)
	for _, warn := range feedWarnings {
		appLog.Warn(warn)
	}
	vexFeedSvc := &vexfeed.Service{
		Feeds:    overlayFeeds,
		Store:    vendorVEXStore,
		ReEnrich: dispatcher,
		Logger:   vexfeed.LoggerSync{Log: appLog},
		Metrics:  metrics.VEXFeedMetrics{},
	}
	StartVEXFeedScheduler(ctx, vexFeedSvc, cfg.AppConfig.VEXFeed.PollInterval, appLog, feedHealth)
	// A background loader refreshes the in-memory correlation index from the
	// correlation-class feeds (Alpine/Rocky/Wolfi OSV + Red Hat CSAF advisories).
	distroSource := vexfeed.NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	StartCorrelationFeedScheduler(ctx, &vexfeed.CorrelationLoader{
		Feeds:  correlationFeeds,
		Source: distroSource,
		Logger: appLog,
	}, cfg.AppConfig.VEXFeed.PollInterval, appLog, feedHealth)
	notificationRules := store.NewPostgresNotificationConfigRepository(cfg.Pool)
	notifySvc := notify.NewService(notify.ServiceConfig{
		Rules: notificationRules,
		SMTP: notify.SMTPSettings{
			Host:     cfg.AppConfig.SMTP.Host,
			Port:     cfg.AppConfig.SMTP.Port,
			Username: cfg.AppConfig.SMTP.Username,
			Password: cfg.AppConfig.SMTP.Password,
			From:     cfg.AppConfig.SMTP.From,
			UseTLS:   cfg.AppConfig.SMTP.UseTLS,
		},
		MaxRetry:     cfg.AppConfig.Worker.MaxRetry,
		BaseDelay:    cfg.AppConfig.Worker.BaseDelay,
		RecordMetric: metrics.RecordNotification,
	})
	osvClient := osv.NewClient(osv.ClientConfig{
		RateLimiter: osv.NewTokenBucket(cfg.AppConfig.OSV.RateLimitRPS, cfg.AppConfig.OSV.RateLimitRPS),
	})
	// CR-2/CR-4: a single Correlator over CorrelationSource feeds — OSV.dev live
	// query plus the in-memory distro OSV index — is the one match path ingest
	// uses. Merge is distro-authoritative (CR-3) so a distro verdict outranks
	// OSV.dev for apk/rpm packages.
	correlator := correlation.NewCorrelator(appLog,
		&osv.ComponentFetcher{
			Client: osvClient,
			Logger: osv.LoggerCorrelation{Log: appLog},
		},
		distroSource,
	)
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       jobs,
		Trust:      trust.GateEvaluator{Gate: gate},
		Parser:     parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:       store.NewPostgresSBOMStore(cfg.Pool),
		Components: store.NewPostgresComponentStore(cfg.Pool),
		Catalog:    vulnCatalog,
		Fetcher:    correlator,
		Correlate:  store.NewPostgresCorrelationRepository(cfg.Pool),
		Enrichment: enrichmentSvc,
		Notify: metrics.InstrumentedNotifier{
			Inner:      notify.IngestionNotifier{Sender: notifySvc},
			ChannelTyp: "ingestion",
		},
	})
	ingestJobs := ingestion.JobHandler(pipeline, enrichmentSvc)
	signalsJobs := ingestion.SignalsJobHandler(enrichmentSvc, signalSources)
	notifyJobs := notify.JobHandler(notifySvc)
	cfg.InProcessQueue.SetHandler(metrics.InstrumentJobHandler(func(ctx context.Context, job domain.Job) error {
		switch job.Type {
		case domain.JobTypeNotify:
			return notifyJobs(ctx, job)
		case domain.JobTypeReEnrichSignals:
			return signalsJobs(ctx, job)
		case domain.JobTypeApplyVEXSBOM:
			var payload struct {
				SBOMDocumentID string `json:"sbom_document_id"`
			}
			if err := json.Unmarshal(job.Payload, &payload); err != nil {
				return fmt.Errorf("decode apply vex payload: %w", err)
			}
			if enrichmentSvc == nil {
				return fmt.Errorf("enrichment service unavailable")
			}
			return enrichmentSvc.ApplyVEX(ctx, payload.SBOMDocumentID)
		default:
			return ingestJobs(ctx, job)
		}
	}))

	triageRepo := store.NewPostgresTriageRepository(cfg.Pool)
	triageHandler := &triage.Handler{
		Repo:  triageRepo,
		VEX:   store.NewPostgresTriageVEXGenerator(cfg.Pool),
		Audit: audit,
	}
	vexExportRepo := store.NewPostgresVEXExportRepository(cfg.Pool)
	vexExportSvc := &vexgen.Handler{
		Repo:        vexExportRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorVEXStore},
		VendorMatch: vendorMatcher,
	}
	StartTriageExpiryScheduler(ctx, triageHandler, time.Hour)

	watchRepo := store.NewPostgresWatchRepository(cfg.Pool)
	watchSvc := &watch.Service{
		NVD: nvdClient,
		OSV: osvClient,
		// CR-2: a distro-only Correlator re-correlates catalog components against the
		// in-memory distro index each cycle (OSV.dev/NVD already covered by the bulk
		// fetch above — no duplicate network query).
		Correlator: correlation.NewCorrelator(appLog, distroSource),
		Repo:    watchRepo,
		Notify:  notify.EnqueueSender{Queue: cfg.InProcessQueue},
		Metrics: metrics.WatchRecorder{},
		OnSuccess: func(ts time.Time) {
			if cfg.CVEFeedSuccess != nil {
				cfg.CVEFeedSuccess.Store(ts)
			}
		},
	}
	StartWatchScheduler(ctx, watchSvc, cfg.AppConfig.NVD.PollInterval, appLog, feedHealth)

	// CR-5: backfill CVSS for apk/rpm catalog rows that arrived without it, from
	// the NVD by-CVE endpoint, then re-enrich so risk scores spread.
	StartCVSSBackfillScheduler(ctx, &enrichment.CVSSBackfillService{
		Fetcher:   nvdClient,
		Catalog:   vulnCatalog,
		ReEnrich:  dispatcher,
		OpenCount: enrichmentRepo,
		Metrics:   metrics.CVSSBackfillMetrics{},
		Logger:    appLog,
	}, cfg.AppConfig.NVD.PollInterval, appLog, feedHealth)

	// Red Hat VEX overlay (Option B): on-demand Security Data API per open RPM CVE
	// → vex_assertions (the working alternative to the empty CSAF directory crawler).
	// A "Not affected" verdict for the component's exact EL stream surfaces as a
	// visible, human-overridable overlay signal (vendor severity + rationale carried
	// in the justification); Themis never auto-rescopes severity.
	metrics.RegisterRedHatVEX()
	StartRedHatVEXScheduler(ctx, &enrichment.RedHatVEXService{
		Fetcher:  redhat.NewClient(redhat.ClientConfig{RateLimiter: nvd.NewTokenBucket(2, 2)}),
		Findings: enrichmentRepo,
		Store:    vendorVEXStore,
		ReEnrich: dispatcher,
		Metrics:  metrics.RedHatVEXMetrics{},
		Logger:   appLog,
	}, cfg.AppConfig.VEXFeed.PollInterval, appLog, feedHealth)

	handler := api.NewHandler(api.Dependencies{
		Ingestion:     pipeline,
		Jobs:          jobs,
		Dispatcher:    dispatcher,
		Catalog:       store.NewPostgresProductCatalogRepository(cfg.Pool),
		Scans:         store.NewPostgresScanQueryRepository(cfg.Pool),
		Components:    store.NewPostgresComponentCatalogRepository(cfg.Pool),
		Watch:         store.NewPostgresCVEWatchFindingRepository(cfg.Pool),
		Notifications: notificationRules,
		Scanners:      store.NewPostgresScannerConfigRepository(cfg.Pool),
		Triage:        triageHandler,
		TriageRepo:    triageRepo,
		Graph:         graphStore,
		VEXExport:     vexExportSvc,
		Status:        store.NewPostgresSystemStatusRepository(cfg.Pool),
		SBOMMgmt:      store.NewPostgresSBOMManagementRepository(cfg.Pool),
		ThreatSignals: threatSignals,
		FeedHealth:    feedHealth,
		Audit:         audit,
		MaxUpload:     cfg.AppConfig.Upload.MaxSizeBytes,
		TrustPolicy:   domain.TrustPolicy(cfg.AppConfig.Trust.DefaultPolicy),
	})

	api.Mount(r, api.MountConfig{
		Handler: handler,
		APIKeyAuth: apimiddleware.APIKeyAuth{
			Keys: store.NewPostgresAPIKeyRepository(cfg.Pool),
		},
		WebhookAuth: apimiddleware.WebhookAuth{
			Secret: cfg.AppConfig.Webhook.Secret,
		},
		MaxUploadSize: cfg.AppConfig.Upload.MaxSizeBytes,
		Middleware:    []func(http.Handler) http.Handler{metrics.StageSpanMiddleware},
	})
}

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

// MountAPI wires adapter handlers onto the HTTP router.
func MountAPI(ctx context.Context, r chi.Router, cfg APIConfig) {
	appLog := domain.LoggerOrNop(cfg.Logger)
	feedHealth := store.NewPostgresFeedHealthStore(cfg.Pool)
	vulnCatalog := store.NewPostgresVulnerabilityCatalog(cfg.Pool)
	nvdClient := nvd.NewClient(nvd.ClientConfig{
		APIKey:      cfg.AppConfig.NVD.APIKey,
		RateLimiter: nvd.NewTokenBucket(cfg.AppConfig.NVD.RateLimitRPS, cfg.AppConfig.NVD.RateLimitRPS),
	})
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
	// CR-4: the VEX overlay carries ONLY true Red Hat CSAF VEX (exploitability
	// context). Distro OSV vulnerability DBs move to the correlation source below.
	vexFeedSvc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{
			vexfeed.CSAFDirectoryFeedSource{Name_: "rhel", URL: cfg.AppConfig.VEXFeed.RHELVEXURL, Fetcher: vexHTTP},
		},
		Store:    vendorVEXStore,
		ReEnrich: dispatcher,
		Logger:   vexfeed.LoggerSync{Log: appLog},
		Metrics:  metrics.VEXFeedMetrics{},
	}
	StartVEXFeedScheduler(ctx, vexFeedSvc, cfg.AppConfig.VEXFeed.PollInterval, appLog, feedHealth)
	// CR-4: Alpine/Rocky/Wolfi OSV feeds are correlation sources (affected ranges +
	// severity + fixed), not VEX. A background loader refreshes the in-memory index.
	distroSource := vexfeed.NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	StartCorrelationFeedScheduler(ctx, &vexfeed.CorrelationLoader{
		Feeds: []vexfeed.FeedSource{
			vexfeed.ZipOSVFeedSource{Name_: "alpine", URL: cfg.AppConfig.VEXFeed.AlpineOSVURL, Fetcher: vexHTTP},
			vexfeed.ZipOSVFeedSource{Name_: "rocky", URL: cfg.AppConfig.VEXFeed.RockyOSVURL, Fetcher: vexHTTP},
			vexfeed.URLFeedSource{Name_: "wolfi", URL: cfg.AppConfig.VEXFeed.WolfiOSVURL, Kind: "osv", Fetcher: vexHTTP},
			// CR-4: Red Hat CSAF advisories as an rpm correlation source (NEVRA
			// fixed-version ranges), distinct from the true-VEX overlay above.
			vexfeed.CSAFDirectoryFeedSource{Name_: "rhel", URL: cfg.AppConfig.VEXFeed.RHELCSAFURL, Fetcher: vexHTTP},
		},
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

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
}

type dbPool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// MountAPI wires adapter handlers onto the HTTP router.
func MountAPI(ctx context.Context, r chi.Router, cfg APIConfig) {
	jobs := store.NewPostgresIngestionRepository(cfg.Pool)
	trustRepo := trust.NewPostgresRepository(cfg.Pool)
	audit := trust.NewPostgresAuditRecorder(cfg.Pool)
	gate := &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trustRepo, Audit: audit}
	enrichmentRepo := store.NewPostgresEnrichmentRepository(cfg.Pool)
	graphStore := assetgraph.NewPostgresStore(cfg.Pool)
	vendorVEXStore := vexfeed.NewPostgresAssertionStore(cfg.Pool)
	vendorMatcher := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{
		Logger: vexfeed.SlogMismatchLogger{},
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
	StartEPSSKevScheduler(ctx, epssKevSvc, cfg.AppConfig.EPSSKev.PollInterval)
	exploitDBClient := exploitdb.NewClient(exploitdb.ClientConfig{CSVURL: cfg.AppConfig.ExploitDB.CSVURL})
	exploitDBSvc := &exploitdb.Service{
		Source:       exploitDBClient,
		Store:        exploitStore,
		ReEnrich:     dispatcher,
		OpenFindings: enrichmentRepo,
		Metrics:      metrics.ExploitDBMetrics{},
	}
	StartExploitDBScheduler(ctx, exploitDBSvc, cfg.AppConfig.ExploitDB.PollInterval)
	vexHTTP := &vexfeed.HTTPFetcher{}
	vexFeedSvc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{
			vexfeed.CSAFDirectoryFeedSource{Name_: "rhel", URL: cfg.AppConfig.VEXFeed.RHELURL, Fetcher: vexHTTP},
			vexfeed.ZipOSVFeedSource{Name_: "alpine", URL: cfg.AppConfig.VEXFeed.AlpineOSVURL, Fetcher: vexHTTP},
			vexfeed.ZipOSVFeedSource{Name_: "rocky", URL: cfg.AppConfig.VEXFeed.RockyOSVURL, Fetcher: vexHTTP},
			vexfeed.URLFeedSource{Name_: "wolfi", URL: cfg.AppConfig.VEXFeed.WolfiOSVURL, Kind: "osv", Fetcher: vexHTTP},
		},
		Store:    vendorVEXStore,
		ReEnrich: dispatcher,
		Metrics:  metrics.VEXFeedMetrics{},
	}
	StartVEXFeedScheduler(ctx, vexFeedSvc, cfg.AppConfig.VEXFeed.PollInterval)
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
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:        jobs,
		Trust:       trust.GateEvaluator{Gate: gate},
		Parser:      parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:        store.NewPostgresSBOMStore(cfg.Pool),
		Components:  store.NewPostgresComponentStore(cfg.Pool),
		Catalog:     store.NewPostgresVulnerabilityCatalog(cfg.Pool),
		Fetcher: &osv.ComponentFetcher{
			Client: osvClient,
			Logger: osv.SlogCorrelationLogger{},
		},
		Correlate:   store.NewPostgresCorrelationRepository(cfg.Pool),
		Enrichment:  enrichmentSvc,
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
		NVD: nvd.NewClient(nvd.ClientConfig{
			APIKey:      cfg.AppConfig.NVD.APIKey,
			RateLimiter: nvd.NewTokenBucket(cfg.AppConfig.NVD.RateLimitRPS, cfg.AppConfig.NVD.RateLimitRPS),
		}),
		OSV: osvClient,
		Repo:    watchRepo,
		Notify:  notify.EnqueueSender{Queue: cfg.InProcessQueue},
		Metrics: metrics.WatchRecorder{},
		OnSuccess: func(ts time.Time) {
			if cfg.CVEFeedSuccess != nil {
				cfg.CVEFeedSuccess.Store(ts)
			}
		},
	}
	StartWatchScheduler(ctx, watchSvc, cfg.AppConfig.NVD.PollInterval)

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

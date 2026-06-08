package httpserver

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/api"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/nvd"
	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	"github.com/themis-project/themis/internal/infrastructure/metrics"
	"github.com/themis-project/themis/internal/infrastructure/queue"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
	"github.com/themis-project/themis/internal/usecase/triage"
	"github.com/themis-project/themis/internal/usecase/watch"
)

// APIConfig configures REST API mounting.
type APIConfig struct {
	Pool           *pgxpool.Pool
	AppConfig      config.Config
	InProcessQueue *queue.InProcessQueue
	CVEFeedSuccess *atomic.Value
}

// MountAPI wires adapter handlers onto the HTTP router.
func MountAPI(ctx context.Context, r chi.Router, cfg APIConfig) {
	jobs := store.NewPostgresIngestionRepository(cfg.Pool)
	trustRepo := trust.NewPostgresRepository(cfg.Pool)
	audit := trust.NewPostgresAuditRecorder(cfg.Pool)
	gate := &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trustRepo, Audit: audit}
	enrichmentRepo := store.NewPostgresEnrichmentRepository(cfg.Pool)
	enrichmentSvc := &enrichment.Handler{Repo: enrichmentRepo, Audit: audit}
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
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:        jobs,
		Trust:       trust.GateEvaluator{Gate: gate},
		Parser:      parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:        store.NewPostgresSBOMStore(cfg.Pool),
		Components:  store.NewPostgresComponentStore(cfg.Pool),
		Catalog:     store.NewPostgresVulnerabilityCatalog(cfg.Pool),
		Fetcher:     store.StaticVulnerabilityFetcher{},
		Correlate:   store.NewPostgresCorrelationRepository(cfg.Pool),
		Enrichment:  enrichmentSvc,
		Notify: metrics.InstrumentedNotifier{
			Inner:      notify.IngestionNotifier{Sender: notifySvc},
			ChannelTyp: "ingestion",
		},
	})
	ingestJobs := ingestion.JobHandler(pipeline, enrichmentSvc)
	notifyJobs := notify.JobHandler(notifySvc)
	cfg.InProcessQueue.SetHandler(metrics.InstrumentJobHandler(func(ctx context.Context, job domain.Job) error {
		if job.Type == domain.JobTypeNotify {
			return notifyJobs(ctx, job)
		}
		return ingestJobs(ctx, job)
	}))

	triageRepo := store.NewPostgresTriageRepository(cfg.Pool)
	triageHandler := &triage.Handler{
		Repo:  triageRepo,
		VEX:   store.NewPostgresTriageVEXGenerator(cfg.Pool),
		Audit: audit,
	}
	StartTriageExpiryScheduler(ctx, triageHandler, time.Hour)

	watchRepo := store.NewPostgresWatchRepository(cfg.Pool)
	watchSvc := &watch.Service{
		NVD: nvd.NewClient(nvd.ClientConfig{
			APIKey:      cfg.AppConfig.NVD.APIKey,
			RateLimiter: nvd.NewTokenBucket(cfg.AppConfig.NVD.RateLimitRPS, cfg.AppConfig.NVD.RateLimitRPS),
		}),
		OSV: osv.NewClient(osv.ClientConfig{
			RateLimiter: osv.NewTokenBucket(cfg.AppConfig.OSV.RateLimitRPS, cfg.AppConfig.OSV.RateLimitRPS),
		}),
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
		Dispatcher:    &ingestion.AsyncDispatcher{Queue: cfg.InProcessQueue},
		Catalog:       store.NewPostgresProductCatalogRepository(cfg.Pool),
		Scans:         store.NewPostgresScanQueryRepository(cfg.Pool),
		Components:    store.NewPostgresComponentCatalogRepository(cfg.Pool),
		Watch:         store.NewPostgresCVEWatchFindingRepository(cfg.Pool),
		Notifications: notificationRules,
		Scanners:      store.NewPostgresScannerConfigRepository(cfg.Pool),
		Triage:        triageHandler,
		TriageRepo:    triageRepo,
		MaxUpload:     cfg.AppConfig.Upload.MaxSizeBytes,
		TrustPolicy:   domain.TrustPolicy(cfg.AppConfig.Trust.DefaultPolicy),
	})

	r.Use(metrics.StageSpanMiddleware)
	api.Mount(r, api.MountConfig{
		Handler: handler,
		APIKeyAuth: apimiddleware.APIKeyAuth{
			Keys: store.NewPostgresAPIKeyRepository(cfg.Pool),
		},
		WebhookAuth: apimiddleware.WebhookAuth{
			Secret: cfg.AppConfig.Webhook.Secret,
		},
		MaxUploadSize: cfg.AppConfig.Upload.MaxSizeBytes,
	})
}

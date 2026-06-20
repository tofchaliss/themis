package httpserver

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	"github.com/themis-project/themis/internal/infrastructure/db"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

type bootHooks struct {
	connect             func(ctx context.Context, dsn string, maxPoolSize int32) (domain.DatabasePool, error)
	runMigrations       func(dsn, migrationsPath string) error
	verifySchemaVersion func(dsn, migrationsPath string) error
	verifySchemaShape   func(ctx context.Context, pool *pgxpool.Pool) error
}

var (
	dbConnect             = db.Connect
	dbRunMigrations       = db.RunMigrations
	dbVerifySchemaVersion = db.VerifySchemaVersion
	dbVerifySchemaShape   = db.VerifySchemaShape
	newInProcessQueue     = queue.NewInProcessQueue
)

// Application holds runtime dependencies started by Boot.
type Application struct {
	Config         config.Config
	Logger         *zap.Logger
	DB             domain.DatabasePool
	Workers        domain.WorkerPool
	HTTPServer     *Server
	CVEFeedSuccess atomic.Value
}

// BootOption configures Boot.
type BootOption func(*bootConfig)

type bootConfig struct {
	configPath     string
	migrationsPath string
	workerPool     domain.WorkerPool
	hooks          bootHooks
}

// WithConfigPath sets the YAML config file path.
func WithConfigPath(path string) BootOption {
	return func(cfg *bootConfig) {
		cfg.configPath = path
	}
}

// WithMigrationsPath sets the SQL migrations directory.
func WithMigrationsPath(path string) BootOption {
	return func(cfg *bootConfig) {
		cfg.migrationsPath = path
	}
}

// WithWorkerPool overrides the default worker pool implementation.
func WithWorkerPool(pool domain.WorkerPool) BootOption {
	return func(cfg *bootConfig) {
		cfg.workerPool = pool
	}
}

// Boot loads configuration and initializes runtime dependencies.
func Boot(ctx context.Context, logger *zap.Logger, opts ...BootOption) (*Application, error) {
	cfg := bootConfig{
		configPath:     "themis.yaml",
		migrationsPath: "migrations",
		hooks:          defaultBootHooks(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return bootWithConfig(ctx, logger, cfg)
}

func defaultBootHooks() bootHooks {
	return bootHooks{
		connect: func(ctx context.Context, dsn string, maxPoolSize int32) (domain.DatabasePool, error) {
			return dbConnect(ctx, dsn, maxPoolSize)
		},
		runMigrations:       dbRunMigrations,
		verifySchemaVersion: dbVerifySchemaVersion,
		verifySchemaShape:   dbVerifySchemaShape,
	}
}

func bootWithConfig(ctx context.Context, logger *zap.Logger, cfg bootConfig) (*Application, error) {
	appCfg, err := config.Load(cfg.configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	pool, err := cfg.hooks.connect(ctx, appCfg.Database.DSN, appCfg.Database.MaxPoolSize)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	if err := cfg.hooks.runMigrations(appCfg.Database.DSN, cfg.migrationsPath); err != nil {
		pool.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	if err := cfg.hooks.verifySchemaVersion(appCfg.Database.DSN, cfg.migrationsPath); err != nil {
		pool.Close()
		return nil, fmt.Errorf("verify schema version: %w", err)
	}

	if pgxPool, ok := pool.(*pgxpool.Pool); ok {
		if err := cfg.hooks.verifySchemaShape(ctx, pgxPool); err != nil {
			pool.Close()
			return nil, fmt.Errorf("verify schema shape: %w", err)
		}
	}

	workers := cfg.workerPool
	var inProcess *queue.InProcessQueue
	if workers == nil {
		pgxPool, ok := pool.(*pgxpool.Pool)
		if !ok {
			pool.Close()
			return nil, fmt.Errorf("database pool must be *pgxpool.Pool")
		}

		var err error
		inProcess, err = newInProcessQueue(queue.InProcessConfig{
			PoolSize:  appCfg.Worker.PoolSize,
			MaxRetry:  appCfg.Worker.MaxRetry,
			BaseDelay: appCfg.Worker.BaseDelay,
			Store:     queue.NewPostgresJobStore(pgxPool),
		})
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("create worker pool: %w", err)
		}
		workers = inProcess
	} else if q, ok := workers.(*queue.InProcessQueue); ok {
		inProcess = q
	}
	if err := workers.Start(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("start worker pool: %w", err)
	}

	app := &Application{
		Config:  appCfg,
		Logger:  logger,
		DB:      pool,
		Workers: workers,
	}

	addr := fmt.Sprintf(":%d", appCfg.Server.Port)
	app.HTTPServer = New(
		addr,
		logger,
		NewReadinessFromPool(pool, &app.CVEFeedSuccess),
		appCfg.Server.ReadTimeout,
		appCfg.Server.WriteTimeout,
	)

	if inProcess != nil {
		if mountPool, ok := pool.(dbPool); ok {
			watchRepo := store.NewPostgresWatchRepository(mountPool)
			if ts, err := watchRepo.GetLastSuccessTimestamp(ctx); err == nil {
				app.CVEFeedSuccess.Store(ts)
			} else {
				app.CVEFeedSuccess.Store(time.Now().UTC())
			}
			MountAPI(ctx, app.HTTPServer.Router(), APIConfig{
				Pool:           mountPool,
				AppConfig:      appCfg,
				InProcessQueue: inProcess,
				CVEFeedSuccess: &app.CVEFeedSuccess,
			})
		}
	}

	return app, nil
}

// Close releases runtime resources.
func (a *Application) Close(ctx context.Context) error {
	if err := shutdownHTTPServer(a.HTTPServer, ctx); err != nil {
		return err
	}
	if err := a.Workers.Stop(ctx); err != nil {
		return err
	}
	if a.DB != nil {
		a.DB.Close()
	}
	return nil
}

var shutdownHTTPServer = (*Server).Shutdown

var bootFn = Boot

// Run is the DI entry point used by cmd/themis. It wires infrastructure and blocks until shutdown.
func Run(ctx context.Context) error {
	configPath := os.Getenv("THEMIS_CONFIG_PATH")
	if configPath == "" {
		configPath = "themis.yaml"
	}

	logLevel := os.Getenv("THEMIS_LOG_LEVEL")
	if logLevel == "" {
		if cfg, err := config.Load(configPath); err == nil && cfg.Log.Level != "" {
			logLevel = cfg.Log.Level
		} else {
			logLevel = "info"
		}
	}

	logger, err := NewLoggerWithLevel("themis", logLevel)
	if err != nil {
		return err
	}
	defer func() { _ = logger.Sync() }()

	app, err := bootFn(ctx, logger, WithConfigPath(configPath))
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), app.Config.Server.ShutdownTimeout)
		defer cancel()
		_ = app.Close(shutdownCtx)
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.HTTPServer.Start()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	return waitForShutdown(ctx, logger, app, errCh, sigCh)
}

var waitForShutdown = func(
	ctx context.Context,
	logger *zap.Logger,
	app *Application,
	errCh <-chan error,
	sigCh <-chan os.Signal,
) error {
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), app.Config.Server.ShutdownTimeout)
		defer cancel()
		return app.Close(shutdownCtx)
	}

	return nil
}

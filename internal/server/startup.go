package server

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/themis-project/themis/internal/config"
	"github.com/themis-project/themis/internal/store"
)

// WorkerPool executes background jobs. Phase 1 uses an in-process implementation.
type WorkerPool interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// NoopWorkerPool is a placeholder until the queue package is wired in task group 4.
type NoopWorkerPool struct{}

// Start implements WorkerPool.
func (NoopWorkerPool) Start(context.Context) error { return nil }

// Stop implements WorkerPool.
func (NoopWorkerPool) Stop(context.Context) error { return nil }

type databasePool interface {
	Ping(ctx context.Context) error
	Close()
}

type bootHooks struct {
	connect             func(ctx context.Context, dsn string, maxPoolSize int32) (databasePool, error)
	runMigrations       func(dsn, migrationsPath string) error
	verifySchemaVersion func(dsn, migrationsPath string) error
}

var (
	storeConnect             = store.Connect
	storeRunMigrations       = store.RunMigrations
	storeVerifySchemaVersion = store.VerifySchemaVersion
)

// Application holds runtime dependencies started by Boot.
type Application struct {
	Config         config.Config
	Logger         *zap.Logger
	DB             databasePool
	Workers        WorkerPool
	HTTPServer     *Server
	CVEFeedSuccess atomic.Value
}

// BootOption configures Boot.
type BootOption func(*bootConfig)

type bootConfig struct {
	configPath     string
	migrationsPath string
	workerPool     WorkerPool
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
func WithWorkerPool(pool WorkerPool) BootOption {
	return func(cfg *bootConfig) {
		cfg.workerPool = pool
	}
}

// Boot loads configuration and initializes runtime dependencies.
func Boot(ctx context.Context, logger *zap.Logger, opts ...BootOption) (*Application, error) {
	cfg := bootConfig{
		configPath:     "themis.yaml",
		migrationsPath: "migrations",
		workerPool:     NoopWorkerPool{},
		hooks:          defaultBootHooks(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return bootWithConfig(ctx, logger, cfg)
}

func defaultBootHooks() bootHooks {
	return bootHooks{
		connect: func(ctx context.Context, dsn string, maxPoolSize int32) (databasePool, error) {
			return storeConnect(ctx, dsn, maxPoolSize)
		},
		runMigrations:       storeRunMigrations,
		verifySchemaVersion: storeVerifySchemaVersion,
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

	workers := cfg.workerPool
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
	app.CVEFeedSuccess.Store(time.Now().UTC())

	addr := fmt.Sprintf(":%d", appCfg.Server.Port)
	app.HTTPServer = New(
		addr,
		logger,
		NewReadinessFromPool(pool, &app.CVEFeedSuccess),
		appCfg.Server.ReadTimeout,
		appCfg.Server.WriteTimeout,
	)

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

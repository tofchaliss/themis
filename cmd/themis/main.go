package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/themis-project/themis/internal/logging"
	"github.com/themis-project/themis/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	logger, err := logging.New("themis")
	if err != nil {
		return err
	}
	defer func() { _ = logger.Sync() }()

	configPath := os.Getenv("THEMIS_CONFIG_PATH")
	if configPath == "" {
		configPath = "themis.yaml"
	}

	app, err := server.Boot(ctx, logger, server.WithConfigPath(configPath))
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

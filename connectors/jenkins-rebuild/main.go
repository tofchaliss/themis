// Command themis-rebuild-connector is the reference build connector of Themis for Jenkins.
// See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/themis-project/themis-rebuild-connector/internal/connector"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "themis-rebuild-connector:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "connector.json", "path of the configuration file")
	checkOnly := flag.Bool("check", false, "check the configuration and the credential, then exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := connector.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	secrets, err := cfg.LoadSecrets(os.Getenv)
	if err != nil {
		return err
	}
	store, err := connector.OpenFileStore(cfg.StoreDir)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	owner := fmt.Sprintf("%s-%d", host, os.Getpid())
	jenkins := connector.NewJenkins(cfg.Jenkins.URL, cfg.Jenkins.User, secrets.JenkinsToken, time.Duration(cfg.CallTimeout))
	reporter := connector.NewThemisReporter(cfg.Themis.CallbackURL, secrets.ThemisAPIKey, time.Duration(cfg.CallTimeout))
	c := connector.New(cfg, secrets.Signing, store, jenkins, reporter, owner, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// D33: ask the build system what the credential can reach, and do not start otherwise.
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.CallTimeout))
	err = c.CheckCredential(checkCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("not starting: %w", err)
	}
	if *checkOnly {
		log.Info("configuration and credential are in order", "jobs", cfg.AllowedJobs())
		return nil
	}

	go c.Run(ctx)
	srv := &http.Server{Addr: cfg.Listen, Handler: c.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("connector listening", "listen", cfg.Listen, "jobs", cfg.AllowedJobs(), "instance", owner)
	if cfg.TLSCertFile != "" {
		err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		log.Warn("serving plain http: put a TLS proxy in front, Themis sends rebuild requests to https only")
		err = srv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

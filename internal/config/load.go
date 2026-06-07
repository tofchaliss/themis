package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrMissingRequiredField indicates required configuration is absent.
var ErrMissingRequiredField = errors.New("missing required configuration field")

// Load reads configuration from an optional YAML file and environment variables.
// Environment variables override file values. Keys use the THEMIS_ prefix.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return Config{}, fmt.Errorf("read config file: %w", err)
			}
		} else if len(data) > 0 {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return Config{}, fmt.Errorf("parse config file: %w", err)
			}
		}
	}

	applyEnvOverrides(&cfg)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate checks required fields and value ranges.
func (c Config) Validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("%w: database.dsn", ErrMissingRequiredField)
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}
	if c.Database.MaxPoolSize <= 0 {
		return fmt.Errorf("database.max_pool_size must be positive, got %d", c.Database.MaxPoolSize)
	}
	if c.Worker.PoolSize <= 0 {
		return fmt.Errorf("worker.pool_size must be positive, got %d", c.Worker.PoolSize)
	}
	if c.Upload.MaxSizeBytes <= 0 {
		return fmt.Errorf("upload.max_size_bytes must be positive, got %d", c.Upload.MaxSizeBytes)
	}
	switch c.Trust.DefaultPolicy {
	case TrustPolicyStrict, TrustPolicyStandard, TrustPolicyPermissive:
	default:
		return fmt.Errorf("trust.default_policy must be strict, standard, or permissive, got %q", c.Trust.DefaultPolicy)
	}
	return nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("THEMIS_SERVER_PORT"); v != "" {
		cfg.Server.Port = intFromEnv(v)
	}
	if v := os.Getenv("THEMIS_SERVER_READ_TIMEOUT"); v != "" {
		cfg.Server.ReadTimeout = durationFromEnv(v)
	}
	if v := os.Getenv("THEMIS_SERVER_WRITE_TIMEOUT"); v != "" {
		cfg.Server.WriteTimeout = durationFromEnv(v)
	}
	if v := os.Getenv("THEMIS_SERVER_SHUTDOWN_TIMEOUT"); v != "" {
		cfg.Server.ShutdownTimeout = durationFromEnv(v)
	}

	if v := os.Getenv("THEMIS_DATABASE_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("THEMIS_DATABASE_MAX_POOL_SIZE"); v != "" {
		cfg.Database.MaxPoolSize = int32FromEnv(v)
	}

	if v := os.Getenv("THEMIS_WORKER_POOL_SIZE"); v != "" {
		cfg.Worker.PoolSize = intFromEnv(v)
	}
	if v := os.Getenv("THEMIS_WORKER_MAX_RETRY"); v != "" {
		cfg.Worker.MaxRetry = intFromEnv(v)
	}
	if v := os.Getenv("THEMIS_WORKER_BASE_DELAY"); v != "" {
		cfg.Worker.BaseDelay = durationFromEnv(v)
	}

	if v := os.Getenv("THEMIS_UPLOAD_MAX_SIZE_BYTES"); v != "" {
		cfg.Upload.MaxSizeBytes = int64FromEnv(v)
	}
	if v := os.Getenv("THEMIS_UPLOAD_TIMEOUT"); v != "" {
		cfg.Upload.Timeout = durationFromEnv(v)
	}

	if v := os.Getenv("THEMIS_NVD_API_KEY"); v != "" {
		cfg.NVD.APIKey = v
	}
	if v := os.Getenv("THEMIS_NVD_RATE_LIMIT_RPS"); v != "" {
		cfg.NVD.RateLimitRPS = float64FromEnv(v)
	}
	if v := os.Getenv("THEMIS_NVD_POLL_INTERVAL"); v != "" {
		cfg.NVD.PollInterval = durationFromEnv(v)
	}

	if v := os.Getenv("THEMIS_OSV_RATE_LIMIT_RPS"); v != "" {
		cfg.OSV.RateLimitRPS = float64FromEnv(v)
	}
	if v := os.Getenv("THEMIS_OSV_POLL_INTERVAL"); v != "" {
		cfg.OSV.PollInterval = durationFromEnv(v)
	}

	if v := os.Getenv("THEMIS_SMTP_HOST"); v != "" {
		cfg.SMTP.Host = v
	}
	if v := os.Getenv("THEMIS_SMTP_PORT"); v != "" {
		cfg.SMTP.Port = intFromEnv(v)
	}
	if v := os.Getenv("THEMIS_SMTP_USERNAME"); v != "" {
		cfg.SMTP.Username = v
	}
	if v := os.Getenv("THEMIS_SMTP_PASSWORD"); v != "" {
		cfg.SMTP.Password = v
	}
	if v := os.Getenv("THEMIS_SMTP_FROM"); v != "" {
		cfg.SMTP.From = v
	}
	if v := os.Getenv("THEMIS_SMTP_USE_TLS"); v != "" {
		cfg.SMTP.UseTLS = boolFromEnv(v)
	}

	if v := os.Getenv("THEMIS_TEAMS_WEBHOOK_URL"); v != "" {
		cfg.Teams.WebhookURL = v
	}

	if v := os.Getenv("THEMIS_TRUST_DEFAULT_POLICY"); v != "" {
		cfg.Trust.DefaultPolicy = TrustPolicyLevel(strings.ToLower(v))
	}
}

func intFromEnv(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func int32FromEnv(v string) int32 {
	return int32(intFromEnv(v))
}

func int64FromEnv(v string) int64 {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func float64FromEnv(v string) float64 {
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return n
}

func durationFromEnv(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return d
}

func boolFromEnv(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes"
}

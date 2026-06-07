package config

import "time"

// TrustPolicyLevel defines artifact trust enforcement for a product.
type TrustPolicyLevel string

const (
	TrustPolicyStrict     TrustPolicyLevel = "strict"
	TrustPolicyStandard   TrustPolicyLevel = "standard"
	TrustPolicyPermissive TrustPolicyLevel = "permissive"
)

// Config holds all runtime settings for Themis.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Worker   WorkerConfig   `yaml:"worker"`
	Upload   UploadConfig   `yaml:"upload"`
	NVD      NVDConfig      `yaml:"nvd"`
	OSV      OSVConfig      `yaml:"osv"`
	SMTP     SMTPConfig     `yaml:"smtp"`
	Teams    TeamsConfig    `yaml:"teams"`
	Trust    TrustConfig    `yaml:"trust"`
}

// ServerConfig controls the HTTP server.
type ServerConfig struct {
	Port            int           `yaml:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// DatabaseConfig controls PostgreSQL connectivity.
type DatabaseConfig struct {
	DSN         string `yaml:"dsn"`
	MaxPoolSize int32  `yaml:"max_pool_size"`
}

// WorkerConfig controls the in-process job queue worker pool.
type WorkerConfig struct {
	PoolSize  int           `yaml:"pool_size"`
	MaxRetry  int           `yaml:"max_retry"`
	BaseDelay time.Duration `yaml:"base_delay"`
}

// UploadConfig controls artifact upload limits.
type UploadConfig struct {
	MaxSizeBytes int64         `yaml:"max_size_bytes"`
	Timeout      time.Duration `yaml:"timeout"`
}

// NVDConfig controls NVD API polling.
type NVDConfig struct {
	APIKey       string        `yaml:"api_key"`
	RateLimitRPS float64       `yaml:"rate_limit_rps"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// OSVConfig controls OSV API polling.
type OSVConfig struct {
	RateLimitRPS float64       `yaml:"rate_limit_rps"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// SMTPConfig controls outbound email notifications.
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	UseTLS   bool   `yaml:"use_tls"`
}

// TeamsConfig controls Microsoft Teams webhook delivery.
type TeamsConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

// TrustConfig holds default trust policy settings.
type TrustConfig struct {
	DefaultPolicy TrustPolicyLevel `yaml:"default_policy"`
}

// Default returns a Config populated with Phase 1 defaults.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 15 * time.Second,
		},
		Database: DatabaseConfig{
			MaxPoolSize: 10,
		},
		Worker: WorkerConfig{
			PoolSize:  4,
			MaxRetry:  5,
			BaseDelay: time.Second,
		},
		Upload: UploadConfig{
			MaxSizeBytes: 50 * 1024 * 1024,
			Timeout:      5 * time.Minute,
		},
		NVD: NVDConfig{
			RateLimitRPS: 5,
			PollInterval: 6 * time.Hour,
		},
		OSV: OSVConfig{
			RateLimitRPS: 10,
			PollInterval: 6 * time.Hour,
		},
		SMTP: SMTPConfig{
			Port:   587,
			UseTLS: true,
		},
		Trust: TrustConfig{
			DefaultPolicy: TrustPolicyStandard,
		},
	}
}

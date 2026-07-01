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
	Server       ServerConfig       `yaml:"server"`
	Database     DatabaseConfig     `yaml:"database"`
	Worker       WorkerConfig       `yaml:"worker"`
	Upload       UploadConfig       `yaml:"upload"`
	NVD          NVDConfig          `yaml:"nvd"`
	OSV          OSVConfig          `yaml:"osv"`
	SMTP         SMTPConfig         `yaml:"smtp"`
	Teams        TeamsConfig        `yaml:"teams"`
	Trust        TrustConfig        `yaml:"trust"`
	Webhook      WebhookConfig      `yaml:"webhook"`
	EPSSKev      EPSSKevConfig      `yaml:"epsskev"`
	ExploitDB    ExploitDBConfig    `yaml:"exploitdb"`
	VEXFeed      VEXFeedConfig      `yaml:"vexfeed"`
	Intelligence IntelligenceConfig `yaml:"intelligence"`
	Log          LogConfig          `yaml:"log"`
	GitHub       GitHubConfig       `yaml:"github"`
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

// WebhookConfig controls CI webhook authentication.
type WebhookConfig struct {
	Secret string `yaml:"secret"`
}

// EPSSKevConfig controls EPSS and KEV feed sync.
type EPSSKevConfig struct {
	EPSSURL      string        `yaml:"epss_url"`
	KEVURL       string        `yaml:"kev_url"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// ExploitDBConfig controls ExploitDB CSV sync.
type ExploitDBConfig struct {
	CSVURL       string        `yaml:"csv_url"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// VEXFeedConfig controls vendor feed sync. CR-4 separates true vendor VEX (the
// exploitability overlay) from advisory/vulnerability-DB feeds (correlation):
//   - rhel_vex_url  → Red Hat CSAF VEX, applied as the VEX overlay
//   - rhel_csaf_url → Red Hat CSAF advisories, consumed as a correlation source
//   - *_osv_url     → distro OSV vulnerability DBs, consumed as correlation sources
//
// rhel_url is a deprecated alias for rhel_csaf_url (kept one release).
type VEXFeedConfig struct {
	RHELVEXURL   string        `yaml:"rhel_vex_url"`
	RHELCSAFURL  string        `yaml:"rhel_csaf_url"`
	RHELURL      string        `yaml:"rhel_url"` // deprecated: alias for rhel_csaf_url
	AlpineOSVURL string        `yaml:"alpine_osv_url"`
	RockyOSVURL  string        `yaml:"rocky_osv_url"`
	WolfiOSVURL  string        `yaml:"wolfi_osv_url"`
	PollInterval time.Duration `yaml:"poll_interval"`
	// Feeds is an optional user delta list merged over the built-in defaults by
	// name: add a custom feed, override a built-in's fields, or disable one
	// (`enabled: false`). Built-in names: rhel-vex (overlay), rhel-csaf, alpine,
	// rocky, wolfi (correlation). Existing configs that only set the *_url fields
	// keep working unchanged.
	Feeds []FeedConfig `yaml:"feeds"`
}

// FeedConfig is one entry in the `vexfeed.feeds` delta list. Name is required and is
// the merge key. The remaining fields override the matching built-in default, or
// define a new feed when the name is unknown. Enabled is a pointer so an unset flag
// (leave the default's state) is distinguishable from an explicit `false` (disable).
type FeedConfig struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`      // url | zip-osv | csaf-dir
	Class     string `yaml:"class"`     // correlation (default) | overlay
	URL       string `yaml:"url"`       // override / set the feed URL
	Kind      string `yaml:"kind"`      // for type=url: csaf | osv (default osv)
	Ecosystem string `yaml:"ecosystem"` // informational label for custom feeds
	Enabled   *bool  `yaml:"enabled"`   // nil = keep default; false = disable
}

// IntelligenceConfig controls blast-radius and enrichment tuning.
type IntelligenceConfig struct {
	BlastRadiusCap int `yaml:"blast_radius_cap"`
}

// LogConfig controls structured logging behaviour.
type LogConfig struct {
	Level string `yaml:"level"`
}

// GitHubConfig holds GitHub API credentials (GHSA adapter in Phase 2b).
type GitHubConfig struct {
	Token string `yaml:"token"`
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
			// 0 = auto: the wiring picks an NVD-compliant rate by key presence
			// (≈1.5 req/s with an API key, ≈0.15 req/s without). A positive value
			// here overrides. The old default of 5 req/s (~150 req/30s) tripped
			// NVD's Cloudflare throttle (HTTP 503).
			RateLimitRPS: 0,
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
		EPSSKev: EPSSKevConfig{
			EPSSURL:      "https://epss.cyentia.com/epss_scores-current.csv.gz",
			KEVURL:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			PollInterval: 24 * time.Hour,
		},
		ExploitDB: ExploitDBConfig{
			CSVURL:       "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
			PollInterval: 24 * time.Hour,
		},
		VEXFeed: VEXFeedConfig{
			RHELVEXURL:   "https://security.access.redhat.com/data/csaf/v2/vex/",
			RHELCSAFURL:  "https://security.access.redhat.com/data/csaf/v2/advisories/",
			AlpineOSVURL: "https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip",
			RockyOSVURL:  "https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip",
			WolfiOSVURL:  "https://packages.wolfi.dev/os/security.json",
			PollInterval: 24 * time.Hour,
		},
		Intelligence: IntelligenceConfig{
			BlastRadiusCap: 10,
		},
		Log: LogConfig{
			Level: "info",
		},
	}
}

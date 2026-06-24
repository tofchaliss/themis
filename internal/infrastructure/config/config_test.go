package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultValues(t *testing.T) {
	cfg := Default()

	if cfg.Server.Port != 8080 {
		t.Fatalf("Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Database.MaxPoolSize != 10 {
		t.Fatalf("Database.MaxPoolSize = %d, want 10", cfg.Database.MaxPoolSize)
	}
	if cfg.Worker.PoolSize != 4 {
		t.Fatalf("Worker.PoolSize = %d, want 4", cfg.Worker.PoolSize)
	}
	if cfg.Trust.DefaultPolicy != TrustPolicyStandard {
		t.Fatalf("Trust.DefaultPolicy = %q, want standard", cfg.Trust.DefaultPolicy)
	}
	if cfg.EPSSKev.PollInterval != 24*time.Hour {
		t.Fatalf("EPSSKev.PollInterval = %v, want 24h", cfg.EPSSKev.PollInterval)
	}
	if cfg.ExploitDB.CSVURL == "" || cfg.VEXFeed.RHELVEXURL == "" || cfg.VEXFeed.RHELCSAFURL == "" {
		t.Fatalf("expected feed defaults: exploitdb=%q rhel_vex=%q rhel_csaf=%q", cfg.ExploitDB.CSVURL, cfg.VEXFeed.RHELVEXURL, cfg.VEXFeed.RHELCSAFURL)
	}
	if cfg.Intelligence.BlastRadiusCap != 10 {
		t.Fatalf("Intelligence.BlastRadiusCap = %d, want 10", cfg.Intelligence.BlastRadiusCap)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("Log.Level = %q, want info", cfg.Log.Level)
	}
}

func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	content := `
server:
  port: 9090
database:
  dsn: postgres://user:pass@localhost:5432/themis
  max_pool_size: 20
trust:
  default_policy: strict
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Fatalf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Database.DSN != "postgres://user:pass@localhost:5432/themis" {
		t.Fatalf("unexpected DSN: %q", cfg.Database.DSN)
	}
	if cfg.Trust.DefaultPolicy != TrustPolicyStrict {
		t.Fatalf("Trust.DefaultPolicy = %q, want strict", cfg.Trust.DefaultPolicy)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	content := `
server:
  port: 9090
database:
  dsn: postgres://file@localhost:5432/themis
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("THEMIS_SERVER_PORT", "3000")
	t.Setenv("THEMIS_DATABASE_DSN", "postgres://env@localhost:5432/themis")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Port != 3000 {
		t.Fatalf("Server.Port = %d, want 3000", cfg.Server.Port)
	}
	if cfg.Database.DSN != "postgres://env@localhost:5432/themis" {
		t.Fatalf("unexpected DSN: %q", cfg.Database.DSN)
	}
}

func TestAllEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "themis.yaml")
	t.Setenv("THEMIS_DATABASE_DSN", "postgres://env@localhost/themis")
	t.Setenv("THEMIS_SERVER_PORT", "9001")
	t.Setenv("THEMIS_SERVER_READ_TIMEOUT", "11s")
	t.Setenv("THEMIS_SERVER_WRITE_TIMEOUT", "12s")
	t.Setenv("THEMIS_SERVER_SHUTDOWN_TIMEOUT", "13s")
	t.Setenv("THEMIS_DATABASE_MAX_POOL_SIZE", "15")
	t.Setenv("THEMIS_WORKER_POOL_SIZE", "6")
	t.Setenv("THEMIS_WORKER_MAX_RETRY", "7")
	t.Setenv("THEMIS_WORKER_BASE_DELAY", "2s")
	t.Setenv("THEMIS_UPLOAD_MAX_SIZE_BYTES", "2048")
	t.Setenv("THEMIS_UPLOAD_TIMEOUT", "3m")
	t.Setenv("THEMIS_NVD_API_KEY", "nvd-key")
	t.Setenv("THEMIS_NVD_RATE_LIMIT_RPS", "2.5")
	t.Setenv("THEMIS_NVD_POLL_INTERVAL", "1h")
	t.Setenv("THEMIS_OSV_RATE_LIMIT_RPS", "3.5")
	t.Setenv("THEMIS_OSV_POLL_INTERVAL", "2h")
	t.Setenv("THEMIS_SMTP_HOST", "smtp.example.com")
	t.Setenv("THEMIS_SMTP_PORT", "2525")
	t.Setenv("THEMIS_SMTP_USERNAME", "user")
	t.Setenv("THEMIS_SMTP_PASSWORD", "pass")
	t.Setenv("THEMIS_SMTP_FROM", "themis@example.com")
	t.Setenv("THEMIS_SMTP_USE_TLS", "false")
	t.Setenv("THEMIS_TEAMS_WEBHOOK_URL", "https://teams.example/webhook")
	t.Setenv("THEMIS_TRUST_DEFAULT_POLICY", "permissive")
	t.Setenv("THEMIS_EPSSKEV_EPSS_URL", "https://epss.example/scores.csv.gz")
	t.Setenv("THEMIS_EPSSKEV_KEV_URL", "https://cisa.example/kev.json")
	t.Setenv("THEMIS_EPSSKEV_POLL_INTERVAL", "12h")
	t.Setenv("THEMIS_EXPLOITDB_CSV_URL", "https://exploitdb.example/files.csv")
	t.Setenv("THEMIS_EXPLOITDB_POLL_INTERVAL", "6h")
	t.Setenv("THEMIS_VEXFEED_RHEL_URL", "https://redhat.example/csaf/")
	t.Setenv("THEMIS_VEXFEED_ALPINE_OSV_URL", "https://alpine.example/osv/")
	t.Setenv("THEMIS_VEXFEED_ROCKY_OSV_URL", "https://rocky.example/osv.json")
	t.Setenv("THEMIS_VEXFEED_WOLFI_OSV_URL", "https://wolfi.example/security.json")
	t.Setenv("THEMIS_VEXFEED_POLL_INTERVAL", "8h")
	t.Setenv("THEMIS_INTELLIGENCE_BLAST_RADIUS_CAP", "12")
	t.Setenv("THEMIS_LOG_LEVEL", "debug")
	t.Setenv("THEMIS_GITHUB_TOKEN", "gh-token")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Port != 9001 || cfg.Server.ReadTimeout != 11*time.Second {
		t.Fatalf("unexpected server config: %+v", cfg.Server)
	}
	if cfg.Database.MaxPoolSize != 15 {
		t.Fatalf("Database.MaxPoolSize = %d", cfg.Database.MaxPoolSize)
	}
	if cfg.Worker.PoolSize != 6 || cfg.Worker.MaxRetry != 7 || cfg.Worker.BaseDelay != 2*time.Second {
		t.Fatalf("unexpected worker config: %+v", cfg.Worker)
	}
	if cfg.Upload.MaxSizeBytes != 2048 || cfg.Upload.Timeout != 3*time.Minute {
		t.Fatalf("unexpected upload config: %+v", cfg.Upload)
	}
	if cfg.NVD.APIKey != "nvd-key" || cfg.NVD.RateLimitRPS != 2.5 {
		t.Fatalf("unexpected nvd config: %+v", cfg.NVD)
	}
	if cfg.OSV.RateLimitRPS != 3.5 {
		t.Fatalf("unexpected osv config: %+v", cfg.OSV)
	}
	if cfg.SMTP.Host != "smtp.example.com" || cfg.SMTP.UseTLS {
		t.Fatalf("unexpected smtp config: %+v", cfg.SMTP)
	}
	if cfg.Teams.WebhookURL != "https://teams.example/webhook" {
		t.Fatalf("Teams.WebhookURL = %q", cfg.Teams.WebhookURL)
	}
	if cfg.Trust.DefaultPolicy != TrustPolicyPermissive {
		t.Fatalf("Trust.DefaultPolicy = %q", cfg.Trust.DefaultPolicy)
	}
	if cfg.EPSSKev.EPSSURL != "https://epss.example/scores.csv.gz" || cfg.EPSSKev.PollInterval != 12*time.Hour {
		t.Fatalf("unexpected epsskev config: %+v", cfg.EPSSKev)
	}
	if cfg.ExploitDB.CSVURL != "https://exploitdb.example/files.csv" || cfg.ExploitDB.PollInterval != 6*time.Hour {
		t.Fatalf("unexpected exploitdb config: %+v", cfg.ExploitDB)
	}
	if cfg.VEXFeed.RHELURL != "https://redhat.example/csaf/" || cfg.VEXFeed.PollInterval != 8*time.Hour {
		t.Fatalf("unexpected vexfeed config: %+v", cfg.VEXFeed)
	}
	// CR-4: with no explicit rhel_csaf_url, the deprecated rhel_url folds into it.
	if cfg.VEXFeed.RHELCSAFURL != "https://redhat.example/csaf/" {
		t.Fatalf("rhel_url alias did not fold into rhel_csaf_url: %q", cfg.VEXFeed.RHELCSAFURL)
	}
	if cfg.Intelligence.BlastRadiusCap != 12 {
		t.Fatalf("Intelligence.BlastRadiusCap = %d", cfg.Intelligence.BlastRadiusCap)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.GitHub.Token != "gh-token" {
		t.Fatalf("GitHub.Token = %q", cfg.GitHub.Token)
	}
}

// TestVEXFeedExplicitCSAFAndVEXURLs covers the CR-4 env branches: an explicit
// rhel_csaf_url is NOT overridden by the deprecated rhel_url, and rhel_vex_url
// is independent.
func TestVEXFeedExplicitCSAFAndVEXURLs(t *testing.T) {
	t.Setenv("THEMIS_DATABASE_DSN", "postgres://u:p@localhost:5432/db")
	t.Setenv("THEMIS_VEXFEED_RHEL_VEX_URL", "https://redhat.example/vex/")
	t.Setenv("THEMIS_VEXFEED_RHEL_CSAF_URL", "https://redhat.example/advisories/")
	t.Setenv("THEMIS_VEXFEED_RHEL_URL", "https://legacy.example/csaf/")

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VEXFeed.RHELVEXURL != "https://redhat.example/vex/" {
		t.Fatalf("rhel_vex_url = %q", cfg.VEXFeed.RHELVEXURL)
	}
	if cfg.VEXFeed.RHELCSAFURL != "https://redhat.example/advisories/" {
		t.Fatalf("explicit rhel_csaf_url overridden by alias: %q", cfg.VEXFeed.RHELCSAFURL)
	}
}

func TestMissingRequiredDSN(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected error for missing DSN")
	}
	if !errors.Is(err, ErrMissingRequiredField) {
		t.Fatalf("expected ErrMissingRequiredField, got %v", err)
	}
}

func TestInvalidTrustPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	content := `
database:
  dsn: postgres://localhost/themis
trust:
  default_policy: invalid
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	if err := os.WriteFile(path, []byte(":\n  bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadUnreadableFile(t *testing.T) {
	path := t.TempDir()

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestLoadMissingFileUsesDefaultsAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "themis.yaml")
	t.Setenv("THEMIS_DATABASE_DSN", "postgres://env@localhost/themis")
	t.Setenv("THEMIS_SERVER_READ_TIMEOUT", "45s")
	t.Setenv("THEMIS_SMTP_USE_TLS", "false")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.ReadTimeout != 45*time.Second {
		t.Fatalf("ReadTimeout = %v, want 45s", cfg.Server.ReadTimeout)
	}
	if cfg.SMTP.UseTLS {
		t.Fatal("expected SMTP.UseTLS false from env")
	}
}

func TestEnvParsingHelpers(t *testing.T) {
	if got := intFromEnv("not-a-number"); got != 0 {
		t.Fatalf("intFromEnv invalid = %d, want 0", got)
	}
	if got := int32FromEnv("12"); got != 12 {
		t.Fatalf("int32FromEnv = %d", got)
	}
	if got := int64FromEnv("99"); got != 99 {
		t.Fatalf("int64FromEnv = %d", got)
	}
	if got := int64FromEnv("bad"); got != 0 {
		t.Fatalf("int64FromEnv invalid = %d, want 0", got)
	}
	if got := float64FromEnv("bad"); got != 0 {
		t.Fatalf("float64FromEnv invalid = %f, want 0", got)
	}
	if got := durationFromEnv("bad"); got != 0 {
		t.Fatalf("durationFromEnv invalid = %v, want 0", got)
	}
	if !boolFromEnv("true") || !boolFromEnv("1") || !boolFromEnv("yes") {
		t.Fatal("boolFromEnv expected true")
	}
	if boolFromEnv("false") {
		t.Fatal("boolFromEnv expected false")
	}
}

func TestValidateSuccess(t *testing.T) {
	cfg := Default()
	cfg.Database.DSN = "postgres://localhost/themis"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cfg := Default()
	cfg.Database.DSN = "postgres://localhost/themis"

	cfg.Server.Port = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected port validation error")
	}

	cfg = Default()
	cfg.Database.DSN = "postgres://localhost/themis"
	cfg.Database.MaxPoolSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected max pool validation error")
	}

	cfg = Default()
	cfg.Database.DSN = "postgres://localhost/themis"
	cfg.Worker.PoolSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected worker pool validation error")
	}

	cfg = Default()
	cfg.Database.DSN = "postgres://localhost/themis"
	cfg.Upload.MaxSizeBytes = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected upload validation error")
	}
}

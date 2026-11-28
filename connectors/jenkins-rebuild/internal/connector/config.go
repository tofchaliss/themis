// Package connector is the reference build connector of Themis (EDR-REBUILD-01 D8, step R5).
//
// It receives the signed request `themis.rebuild.requested.v1`, checks that the job the
// request names is allowed (D18, D31), starts that job in ONE build system (Jenkins) through
// its API, and tells Themis what became of the request (D28). It keeps a stored record per
// request, so that one request starts at most one build and no stored request is dropped in
// silence (D12, D37, D39). It owns no security decision: Themis decides, this program builds.
//
// It imports nothing from Themis. The contract between the two is the event and the status
// call, both plain HTTP and JSON.
package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Duration is a time.Duration written as text in the configuration ("24h", "90s").
type Duration time.Duration

// UnmarshalJSON reads "24h".
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("a duration is written as text, like \"24h\"")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// AllowEntry lists the jobs one Project of one Product may start (D18 item 1).
type AllowEntry struct {
	ProductID string   `json:"product_id"`
	ProjectID string   `json:"project_id"`
	Jobs      []string `json:"jobs"`
}

// ParamRule is the check of one job parameter (D31): its rule, its length limit, and for the
// rule "enum" its allowed values.
type ParamRule struct {
	Rule     string   `json:"rule"`
	MaxLen   int      `json:"max_len"`
	Required bool     `json:"required"`
	Values   []string `json:"values"`
}

// JobSchema names every parameter a job takes. A name not listed is refused, not dropped.
type JobSchema struct {
	Parameters map[string]ParamRule `json:"parameters"`
}

// Config is the connector's configuration file. Secrets are never in it: each one is named by
// the environment variable that holds it.
type Config struct {
	Listen           string `json:"listen"`
	StoreDir         string `json:"store_dir"`
	SigningSecretEnv string `json:"signing_secret_env"`
	Themis           struct {
		CallbackURL string `json:"callback_url"`
		APIKeyEnv   string `json:"api_key_env"`
	} `json:"themis"`
	Jenkins struct {
		URL      string `json:"url"`
		User     string `json:"user"`
		TokenEnv string `json:"token_env"`
		// AcceptBroadCredential is the one stated exception of D33 item 4: start although the
		// credential can see jobs outside the allow-list. It is logged at every start and
		// shown on /status.
		AcceptBroadCredential bool `json:"accept_broad_credential"`
	} `json:"jenkins"`
	MaxEventAge      Duration `json:"max_event_age"`
	ClaimTTL         Duration `json:"claim_ttl"`
	CallTimeout      Duration `json:"call_timeout"`
	RecoveryInterval Duration `json:"recovery_interval"`
	// Retention is how long a reported record is kept. It must be longer than MaxEventAge, so
	// that a repeated event is still recognised while it would still be accepted.
	Retention Duration `json:"retention"`
	// TLSCertFile and TLSKeyFile make the connector serve https itself. Without them it serves
	// http and must sit behind a TLS proxy: Themis sends a rebuild request to https only.
	TLSCertFile string               `json:"tls_cert_file"`
	TLSKeyFile  string               `json:"tls_key_file"`
	Allow       []AllowEntry         `json:"allow"`
	Jobs        map[string]JobSchema `json:"jobs"`
}

// Secrets are read from the environment at start and kept in memory only.
type Secrets struct {
	Signing      string
	ThemisAPIKey string
	JenkinsToken string
}

// Defaults of the timing values. The call to the build system is always shorter than the claim
// (D39 item 4).
const (
	DefaultMaxEventAge      = 24 * time.Hour
	DefaultClaimTTL         = 2 * time.Minute
	DefaultCallTimeout      = 30 * time.Second
	DefaultRecoveryInterval = 30 * time.Second
	DefaultRetention        = 30 * 24 * time.Hour
)

// LoadConfig reads and checks the configuration file.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(raw)
}

// ParseConfig reads and checks a configuration. An unknown field is an error: a mistyped
// allow-list must not be read as an empty one.
func ParseConfig(raw []byte) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("configuration: %w", err)
	}
	if cfg.MaxEventAge == 0 {
		cfg.MaxEventAge = Duration(DefaultMaxEventAge)
	}
	if cfg.ClaimTTL == 0 {
		cfg.ClaimTTL = Duration(DefaultClaimTTL)
	}
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = Duration(DefaultCallTimeout)
	}
	if cfg.RecoveryInterval == 0 {
		cfg.RecoveryInterval = Duration(DefaultRecoveryInterval)
	}
	if cfg.Retention == 0 {
		cfg.Retention = Duration(DefaultRetention)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8090"
	}
	return cfg, cfg.validate()
}

// validate refuses a configuration the connector must not start with (D18: the checks are
// required, not optional).
func (c Config) validate() error {
	switch {
	case c.StoreDir == "":
		return errors.New("configuration: store_dir is required (the stored records of D37 live there)")
	case c.SigningSecretEnv == "":
		return errors.New("configuration: signing_secret_env is required (an unsigned request is never acted on)")
	case c.Themis.APIKeyEnv == "":
		return errors.New("configuration: themis.api_key_env is required")
	case c.Jenkins.User == "" || c.Jenkins.TokenEnv == "":
		return errors.New("configuration: jenkins.user and jenkins.token_env are required")
	case time.Duration(c.CallTimeout) >= time.Duration(c.ClaimTTL):
		return errors.New("configuration: call_timeout must be shorter than claim_ttl (D39 item 4)")
	case time.Duration(c.Retention) <= time.Duration(c.MaxEventAge):
		return errors.New("configuration: retention must be longer than max_event_age")
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		return errors.New("configuration: tls_cert_file and tls_key_file are set together or not at all")
	}
	if err := secureURL("themis.callback_url", c.Themis.CallbackURL); err != nil {
		return err
	}
	if err := secureURL("jenkins.url", c.Jenkins.URL); err != nil {
		return err
	}
	if len(c.Allow) == 0 {
		return errors.New("configuration: allow is empty; the connector does not start without an allow-list of jobs (D18 item 1)")
	}
	for i, a := range c.Allow {
		if a.ProductID == "" || a.ProjectID == "" || len(a.Jobs) == 0 {
			return fmt.Errorf("configuration: allow[%d] needs product_id, project_id and at least one job", i)
		}
		for _, job := range a.Jobs {
			if _, err := jobPath(job); err != nil {
				return fmt.Errorf("configuration: allow[%d]: %w", i, err)
			}
			schema, ok := c.Jobs[job]
			if !ok {
				return fmt.Errorf("configuration: job %q is allowed but has no parameter schema under jobs (D31)", job)
			}
			for name, rule := range schema.Parameters {
				if !paramName.MatchString(name) || strings.HasPrefix(name, reservedPrefix) {
					return fmt.Errorf("configuration: job %q: parameter name %q is not allowed", job, name)
				}
				if err := rule.valid(); err != nil {
					return fmt.Errorf("configuration: job %q parameter %q: %w", job, name, err)
				}
			}
		}
	}
	return nil
}

// secureURL accepts https, and http only to the machine itself: a credential rides every call.
func secureURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("configuration: %s must be a URL", field)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("configuration: %s must be https (http is accepted for the loopback address only)", field)
}

// LoadSecrets reads the three secrets from the environment. A missing one is an error that
// names the variable and never a value.
func (c Config) LoadSecrets(getenv func(string) string) (Secrets, error) {
	s := Secrets{Signing: getenv(c.SigningSecretEnv), ThemisAPIKey: getenv(c.Themis.APIKeyEnv), JenkinsToken: getenv(c.Jenkins.TokenEnv)}
	for name, v := range map[string]string{c.SigningSecretEnv: s.Signing, c.Themis.APIKeyEnv: s.ThemisAPIKey, c.Jenkins.TokenEnv: s.JenkinsToken} {
		if v == "" {
			return Secrets{}, fmt.Errorf("the environment variable %s is empty", name)
		}
	}
	return s, nil
}

// AllowedJobs returns every job of the allow-list, sorted, once.
func (c Config) AllowedJobs() []string {
	seen := map[string]bool{}
	for _, a := range c.Allow {
		for _, j := range a.Jobs {
			seen[j] = true
		}
	}
	out := make([]string, 0, len(seen))
	for j := range seen {
		out = append(out, j)
	}
	sort.Strings(out)
	return out
}

// jobAllowed says whether the Project of the Product may start the job (D18 item 1).
func (c Config) jobAllowed(productID, projectID, job string) bool {
	for _, a := range c.Allow {
		if a.ProductID != productID || a.ProjectID != projectID {
			continue
		}
		for _, j := range a.Jobs {
			if j == job {
				return true
			}
		}
	}
	return false
}

package delivery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The REAL ci_rebuild sender (EDR-DELIVERY-01 M2-6 / N-M2g): it starts a Jenkins job with
// `buildWithParameters` over HTTP Basic auth (user + API token) — Jenkins's own documented
// remote-build path, which needs no plugin and no webhook back-channel. The parameters handed
// to the job are the intent's SNAPSHOT facts and nothing else: identity, the prior SBOM, the
// targeted set, the attempt index. No credential, no key, no model output.
//
// `http://` is refused at CONFIGURE time with the one loopback exception, exactly as the Jira
// sender refuses it and for the identical reason: the credential rides every request and
// base64 is an encoding, not protection. The refusal keeps the FAKE sender wired (NewDeliverers)
// and logs at ERROR naming the variable. There is no knob to relax it.

const defaultJenkinsTimeout = 15 * time.Second

// The parameter names the job receives. They are part of the contract with the job definition
// and therefore stable; a job reads them as ordinary string parameters.
const (
	ParamIntentID     = "THEMIS_INTENT_ID"
	ParamProductID    = "THEMIS_PRODUCT_ID"
	ParamProjectID    = "THEMIS_PROJECT_ID"
	ParamReleaseID    = "THEMIS_RELEASE_ID"
	ParamPriorSBOMID  = "THEMIS_PRIOR_SBOM_ID"
	ParamTargetedCVEs = "THEMIS_TARGETED_CVES"
	ParamAttempt      = "THEMIS_ATTEMPT"
)

// JenkinsConfig is the rebuild sender's configuration (M2-6).
type JenkinsConfig struct {
	// Enabled turns the real sender on. Off (the default) keeps the fake wired: no network.
	Enabled bool
	// BaseURL is where Jenkins is mounted, e.g. "https://ci.acme.example" or
	// "https://acme.example/jenkins" — the path is PRESERVED and every endpoint appended to it.
	BaseURL string
	// User is the Jenkins user the API token belongs to.
	User string
	// APIToken is that user's API token. SECRET — environment only.
	APIToken string
	// Job is the job to build. A folder path is given as Jenkins names it, "team/build-image".
	Job string
	// Timeout bounds one HTTP call (default 15s).
	Timeout time.Duration
}

func jenkinsFromEnv() JenkinsConfig {
	return JenkinsConfig{
		Enabled:  envBool("THEMIS_COMMUNICATION_JENKINS_ENABLED", false),
		BaseURL:  strings.TrimRight(getenv("THEMIS_COMMUNICATION_JENKINS_URL"), "/"),
		User:     getenv("THEMIS_COMMUNICATION_JENKINS_USER"),
		APIToken: getenv("THEMIS_COMMUNICATION_JENKINS_API_TOKEN"),
		Job:      strings.Trim(getenv("THEMIS_COMMUNICATION_JENKINS_JOB"), "/"),
		Timeout:  envDuration("THEMIS_COMMUNICATION_JENKINS_TIMEOUT", defaultJenkinsTimeout),
	}
}

func (c JenkinsConfig) withDefaults() JenkinsConfig {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.Job = strings.Trim(strings.TrimSpace(c.Job), "/")
	if c.Timeout <= 0 {
		c.Timeout = defaultJenkinsTimeout
	}
	return c
}

// missing lists the variables a complete configuration needs and this one lacks — NAMES only.
func (c JenkinsConfig) missing() []string {
	var out []string
	for _, k := range []struct{ name, value string }{
		{"THEMIS_COMMUNICATION_JENKINS_URL", c.BaseURL},
		{"THEMIS_COMMUNICATION_JENKINS_USER", c.User},
		{"THEMIS_COMMUNICATION_JENKINS_API_TOKEN", c.APIToken},
		{"THEMIS_COMMUNICATION_JENKINS_JOB", c.Job},
	} {
		if strings.TrimSpace(k.value) == "" {
			out = append(out, k.name)
		}
	}
	return out
}

// checkTransport refuses a clear-text base URL (loopback excepted) — the Jira rule, restated
// for this credential.
func (c JenkinsConfig) checkTransport() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_JENKINS_URL (%q) is not an absolute URL with a host "+
			"(expected e.g. https://ci.acme.example or https://acme.example/jenkins)", c.BaseURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("delivery: refusing to send the Jenkins API token to %q over clear-text http — "+
			"the credential rides every request (set THEMIS_COMMUNICATION_JENKINS_URL to https://…; "+
			"plain http is accepted only for a loopback host)", u.Host)
	default:
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_JENKINS_URL scheme %q is not supported (use https)", u.Scheme)
	}
}

// String renders the knobs for the startup line: the token's PRESENCE, never the token.
func (c JenkinsConfig) String() string {
	return fmt.Sprintf("enabled=%t url=%q user=%q job=%q api_token=%s timeout=%s",
		c.Enabled, c.BaseURL, c.User, c.Job, secretState(c.APIToken), c.Timeout)
}

// buildEndpoint is `<base>/job/<segment>/job/<segment>/buildWithParameters`, the folder form
// Jenkins uses for a nested job; a top-level job has one segment.
func (c JenkinsConfig) buildEndpoint() string {
	var b strings.Builder
	b.WriteString(c.BaseURL)
	for _, seg := range strings.Split(c.Job, "/") {
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(seg))
	}
	b.WriteString("/buildWithParameters")
	return b.String()
}

// RealJenkinsDeliverer starts one build per ci_rebuild intent.
type RealJenkinsDeliverer struct {
	cfg    JenkinsConfig
	http   *http.Client
	logger *observability.Logger
}

// NewRealJenkinsDeliverer builds the sender, refusing an incomplete or credential-exposing
// configuration AT CONFIGURE TIME (M1b-1 / M1b-2 applied to this sender).
func NewRealJenkinsDeliverer(cfg JenkinsConfig, logger *observability.Logger) (*RealJenkinsDeliverer, error) {
	cfg = cfg.withDefaults()
	if missing := cfg.missing(); len(missing) > 0 {
		return nil, fmt.Errorf("delivery: jenkins configuration incomplete, unset: %s", strings.Join(missing, ", "))
	}
	if err := cfg.checkTransport(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = observability.Nop()
	}
	return &RealJenkinsDeliverer{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}, logger: logger.Component("jenkins")}, nil
}

// DeliverIntent POSTs buildWithParameters for the intent's Release. Jenkins answers 201 with the
// queue item's URL in Location; that reference is recorded on the delivery outcome so an operator
// can find the build the intent started. A refused intent type or an unrendered intent is a
// configuration fault, not a transport failure.
//
// Honest limit: buildWithParameters is not idempotent. A retry after a timeout whose request
// actually landed queues a second build. The cost is a redundant build of the same Release with
// the same parameters — the callback carries the intent id, so the second evaluation is
// deduplicated downstream — and it is bounded by the delivery retry budget.
func (d *RealJenkinsDeliverer) DeliverIntent(ctx context.Context, in app.Intent) (Result, error) {
	if in.Type != app.IntentCIRebuild {
		return Result{Excerpt: "jenkins: wrong intent type"}, fmt.Errorf("jenkins: cannot deliver intent type %q", in.Type)
	}
	if len(in.PayloadBytes) == 0 {
		return Result{Excerpt: "jenkins: no materialized payload"}, ErrNoPayload
	}
	form := url.Values{}
	form.Set(ParamIntentID, in.ID)
	form.Set(ParamProductID, in.ProductID)
	form.Set(ParamProjectID, in.ProjectID)
	form.Set(ParamReleaseID, in.ReleaseID)
	form.Set(ParamPriorSBOMID, in.Snapshot[app.SnapshotPriorSBOMID])
	form.Set(ParamTargetedCVEs, in.Snapshot[app.SnapshotTargetedCVEs])
	form.Set(ParamAttempt, in.Snapshot[app.SnapshotAttempt])

	endpoint := d.cfg.buildEndpoint()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}
	req.SetBasicAuth(d.cfg.User, d.cfg.APIToken) // the ONLY place the token is put on a request
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.http.Do(req)
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, fmt.Errorf("jenkins: POST %s: %w", pathOf(endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, excerptLimit))
		return Result{StatusCode: resp.StatusCode, Excerpt: excerpt(string(detail))},
			fmt.Errorf("jenkins: POST %s: status %d: %s", pathOf(endpoint), resp.StatusCode, excerpt(string(detail)))
	}
	queue := resp.Header.Get("Location")
	d.logger.Info("rebuild queued",
		observability.String("intent_id", in.ID),
		observability.String("release_id", in.ReleaseID),
		observability.String("job", d.cfg.Job),
		observability.String("queue_item", queue),
		observability.String("attempt", in.Snapshot[app.SnapshotAttempt]))
	return Result{
		StatusCode: resp.StatusCode,
		Excerpt:    "jenkins: build queued",
		Metadata: map[string]string{
			"transport":  "jenkins",
			"job":        d.cfg.Job,
			"queue_item": queue,
		},
	}, nil
}

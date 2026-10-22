package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The webhook sender (EDR-REMEDIATION-01 D4): one HTTPS POST of the materialized Themis JSON
// document to the URL configured for the intent's audience name. One-way — there is no callback
// route and the receiver's answer decides nothing but this destination's health.
//
// Health (four states, domain.WebhookHealth) is recorded per destination around every send. A
// paused or disabled destination is not called: the attempt fails without a request and the
// intent follows the ordinary retry and dead-letter path, so an operator sees it in
// `deliveryctl list-deadletters` and re-enables the destination with
// `deliveryctl webhook-enable --destination <name>`.

const (
	defaultWebhookTimeout = 10 * time.Second
	// SignatureHeader carries `sha256=<hex HMAC of the body>` when the audience has a secret.
	SignatureHeader = "X-Themis-Signature"
)

// WebhookConfig is the webhook sender's configuration.
type WebhookConfig struct {
	// Enabled turns the real sender on. Off (the default) keeps the fake wired: no network.
	Enabled bool
	// Targets maps a governed audience name to its URL. The URL is configuration, never an
	// intent field: an intent names the audience only.
	Targets map[string]string
	// Secrets maps an audience to its signing secret (SECRET — environment only, from
	// THEMIS_COMMUNICATION_WEBHOOK_SECRET_<AUDIENCE>, the name upper-cased with - turned to _).
	Secrets map[string]string
	// Timeout bounds one POST (default 10s).
	Timeout time.Duration
}

// ParseWebhookPairs reads "name=value;name2=value2". Blank names or values are dropped.
func ParseWebhookPairs(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" || hasControlChars(name) || hasControlChars(value) {
			continue
		}
		out[name] = value
	}
	return out
}

// WebhookSecretEnv is the environment variable holding an audience's signing secret.
func WebhookSecretEnv(audience string) string {
	return "THEMIS_COMMUNICATION_WEBHOOK_SECRET_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(audience))
}

func webhookFromEnv() WebhookConfig {
	targets := ParseWebhookPairs(getenv("THEMIS_COMMUNICATION_WEBHOOK_TARGETS"))
	secrets := map[string]string{}
	for name := range targets {
		if v := os.Getenv(WebhookSecretEnv(name)); v != "" {
			secrets[name] = v
		}
	}
	return WebhookConfig{
		Enabled: envBool("THEMIS_COMMUNICATION_WEBHOOK_ENABLED", false),
		Targets: targets,
		Secrets: secrets,
		Timeout: envDuration("THEMIS_COMMUNICATION_WEBHOOK_TIMEOUT", defaultWebhookTimeout),
	}
}

// checkTargets refuses a target that is not https (loopback excepted), at configure time.
func (c WebhookConfig) checkTargets() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("delivery: webhook configuration incomplete, unset: THEMIS_COMMUNICATION_WEBHOOK_TARGETS")
	}
	for name, raw := range c.Targets {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("delivery: webhook target %q is not an absolute URL with a host", name)
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
		case "http":
			if !isLoopback(u.Hostname()) {
				return fmt.Errorf("delivery: refusing webhook target %q over clear-text http to %q (use https://…; plain http is accepted only for a loopback host)", name, u.Host)
			}
		default:
			return fmt.Errorf("delivery: webhook target %q scheme %q is not supported (use https)", name, u.Scheme)
		}
	}
	return nil
}

// String names the audiences and whether each has a secret — never a URL path or a secret,
// since an incoming-webhook URL is itself a credential.
func (c WebhookConfig) String() string {
	names := make([]string, 0, len(c.Targets))
	for n := range c.Targets {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		host := ""
		if u, err := url.Parse(c.Targets[n]); err == nil {
			host = u.Host
		}
		parts[i] = fmt.Sprintf("%s->%s(secret=%s)", n, host, secretState(c.Secrets[n]))
	}
	return fmt.Sprintf("enabled=%t targets=[%s] timeout=%s", c.Enabled, strings.Join(parts, " "), c.Timeout)
}

// RealWebhookDeliverer posts webhook intents.
type RealWebhookDeliverer struct {
	cfg    WebhookConfig
	http   *http.Client
	health app.WebhookHealthStore
	clock  func() time.Time
	logger *observability.Logger
}

// NewRealWebhookDeliverer builds the sender, refusing a clear-text or missing target at configure
// time. health may be nil (no health recorded — tests and dev only).
func NewRealWebhookDeliverer(cfg WebhookConfig, health app.WebhookHealthStore, logger *observability.Logger) (*RealWebhookDeliverer, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultWebhookTimeout
	}
	if err := cfg.checkTargets(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = observability.Nop()
	}
	return &RealWebhookDeliverer{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}, health: health,
		clock: func() time.Time { return time.Now().UTC() }, logger: logger.Component("webhook")}, nil
}

// Sign is the signature header value for a body under a secret.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// DeliverIntent posts the intent's JSON document and records the destination's health.
func (d *RealWebhookDeliverer) DeliverIntent(ctx context.Context, in app.Intent) (Result, error) {
	if in.Type != app.IntentWebhook {
		return Result{Excerpt: "webhook: wrong intent type"}, fmt.Errorf("webhook: cannot deliver intent type %q", in.Type)
	}
	if len(in.PayloadBytes) == 0 {
		return Result{Excerpt: "webhook: no materialized payload"}, ErrNoPayload
	}
	target, ok := d.cfg.Targets[in.Destination]
	if !ok {
		return Result{Excerpt: "webhook: unknown audience"}, fmt.Errorf("webhook: no target configured for audience %q (THEMIS_COMMUNICATION_WEBHOOK_TARGETS)", in.Destination)
	}
	now := d.clock()
	h := domain.NewWebhookHealth(in.Destination)
	if d.health != nil {
		var err error
		if h, err = d.health.WebhookHealth(ctx, in.Destination); err != nil {
			return Result{Excerpt: excerpt(err.Error())}, fmt.Errorf("webhook: read health of %q: %w", in.Destination, err)
		}
	}
	if !h.MaySend(now) {
		return Result{Excerpt: "webhook: destination " + string(h.State)},
			fmt.Errorf("webhook: destination %q is %s — not called (re-enable with deliveryctl webhook-enable)", in.Destination, h.State)
	}
	_, body := app.SplitPayload(in.PayloadBytes)
	res, sendErr := d.post(ctx, target, in.Destination, []byte(body))
	if d.health != nil {
		next := h.Succeeded(now)
		if sendErr != nil {
			next = h.Failed(now, excerpt(sendErr.Error()))
		}
		if err := d.health.SaveWebhookHealth(ctx, next, now); err != nil {
			d.logger.Error("webhook health not recorded", observability.String("destination", in.Destination), observability.Err(err))
		}
	}
	if sendErr != nil {
		return res, sendErr
	}
	d.logger.Info("webhook delivered", observability.String("intent_id", in.ID),
		observability.String("destination", in.Destination), observability.String("event", in.Snapshot[app.SnapshotWebhookEvent]))
	return res, nil
}

func (d *RealWebhookDeliverer) post(ctx context.Context, target, audience string, body []byte) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := d.cfg.Secrets[audience]; secret != "" {
		req.Header.Set(SignatureHeader, Sign(secret, body))
	}
	resp, err := d.http.Do(req)
	if err != nil {
		// The URL itself may be a credential (Slack/Teams): only the host is ever logged.
		return Result{Excerpt: "webhook: transport error"}, fmt.Errorf("webhook: POST to %s: %w", hostOf(target), redactURL(err, target))
	}
	defer func() { _ = resp.Body.Close() }()
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, excerptLimit))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{StatusCode: resp.StatusCode, Excerpt: excerpt(string(detail))},
			fmt.Errorf("webhook: POST to %s: status %d: %s", hostOf(target), resp.StatusCode, excerpt(string(detail)))
	}
	return Result{StatusCode: resp.StatusCode, Excerpt: "webhook: delivered",
		Metadata: map[string]string{"transport": "webhook", "audience": audience, "host": hostOf(target)}}, nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return "the configured target"
}

// redactURL strips the target URL out of a transport error, whose text net/http prefixes with it.
func redactURL(err error, target string) error {
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), target, hostOf(target)))
}

// FakeWebhookDeliverer stands in for the webhook sender; it is wired for app.IntentWebhook.
type FakeWebhookDeliverer struct{ fakeDeliverer }

// NewFakeWebhookDeliverer builds the stand-in; a nil logger falls back to a no-op logger.
func NewFakeWebhookDeliverer(logger *observability.Logger) *FakeWebhookDeliverer {
	return &FakeWebhookDeliverer{newFake("webhook", logger)}
}

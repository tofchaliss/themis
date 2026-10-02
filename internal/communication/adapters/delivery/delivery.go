// Package delivery holds the Communication context's outbound delivery channels and the
// redactor (D6). The channel-per-artifact-type push adapters (SMTP / Slack / webhook) and
// the export surface are reused from the PoC notify machinery downstream of a human trigger;
// this greenfield cut ships a logging deliverer + a pass-through redactor behind the app
// ports, so the exactly-once, idempotent, outcome-recorded delivery mechanics are exercised
// end-to-end while the concrete channels are wired in later.
//
// Since N-M1a it also holds the OUTWARD-DELIVERY WORKER (worker.go) and the senders it drives.
// There are two kinds behind one IntentDeliverer seam:
//
//   - the FAKE senders (here) make no network call of any kind: they log and return an outcome.
//     They are what the retry, backoff, dead-letter and operator mechanics were proved against
//     without a Jira instance, and they remain the DEFAULT — an outward action is a credentialed
//     act that leaves the estate, so it is opted into, never inherited.
//   - the REAL senders (jira.go, mail.go — N-M1b) are selected by NewDeliverers when their
//     channel is enabled AND its configuration is complete. Each is independent: a node may ship
//     tickets and log its mail, or the reverse.
//
// Neither kind ever RENDERS. The bytes a sender transmits were materialized at enqueue and stored
// on the intent (D-N-3), so every retry delivers the same snapshot however far the estate has
// moved since — and an intent that carries no payload is refused (ErrNoPayload), not improvised.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// LogDeliverer records deliveries via the shared structured logger (console + OpenTelemetry).
// It stands in for the concrete channel push adapters (email / Slack / webhook / export)
// until they are wired from the PoC notify machinery; delivery is idempotent per Publication.
type LogDeliverer struct {
	logger *observability.Logger
}

// NewLogDeliverer builds a logging deliverer; a nil logger falls back to a no-op logger.
func NewLogDeliverer(logger *observability.Logger) LogDeliverer {
	if logger == nil {
		logger = observability.Nop()
	}
	return LogDeliverer{logger: logger}
}

// Deliver "delivers" the artifact by logging it — a safe default channel.
func (d LogDeliverer) Deliver(_ context.Context, pub domain.Publication, payload []byte) error {
	d.logger.Info("delivered publication",
		observability.String("id", string(pub.ID())),
		observability.String("type", string(pub.Type())),
		observability.String("channel", pub.Channel()),
		observability.Int("bytes", len(payload)),
	)
	return nil
}

// PassThroughRedactor performs no redaction. Real per-channel redaction rules (the PoC's
// redact) are applied when the concrete channels are wired; the port is here so external
// delivery always goes through a redaction step (D6).
type PassThroughRedactor struct{}

// Redact returns the payload unchanged.
func (PassThroughRedactor) Redact(payload []byte) []byte { return payload }

// Result is what one send attempt came back with. StatusCode is 0 for a channel that has none
// (and for a transport failure); Metadata is recorded on the intent as the delivery outcome —
// a ticket key, a message id — and never carries payload content.
type Result struct {
	StatusCode int
	Excerpt    string
	Metadata   map[string]string
}

// IntentDeliverer sends ONE delivery intent to its governed destination. Implementations must
// be idempotent per intent id: the transport is at-least-once and an intent may be retried
// after a timeout whose send actually landed.
type IntentDeliverer interface {
	DeliverIntent(ctx context.Context, in app.Intent) (Result, error)
}

// errFakeFailure is the default error a programmed fake failure returns.
var errFakeFailure = errors.New("delivery: fake transport failure")

// fakeDeliverer is the shared body of the two fakes: it counts calls, can be told to fail the
// first N of them, and logs through the shared logger (R1). What it never does is talk to a
// network — which is the property N-M1a needs, not a convenience.
type fakeDeliverer struct {
	kind      string
	logger    *observability.Logger
	mu        sync.Mutex
	calls     int
	failFirst int
	failErr   error
}

func newFake(kind string, logger *observability.Logger) fakeDeliverer {
	if logger == nil {
		logger = observability.Nop()
	}
	return fakeDeliverer{kind: kind, logger: logger.Component("fake-" + kind)}
}

// FailFirst programs the fake to fail its first n attempts with err (nil err = a generic
// transport failure). Tests use it to drive the retry/backoff/dead-letter paths.
func (d *fakeDeliverer) FailFirst(n int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failFirst, d.failErr = n, err
}

// Calls reports how many send attempts the fake has seen.
func (d *fakeDeliverer) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// DeliverIntent logs the attempt and returns the programmed outcome. The log carries the
// intent id, the governed destination and the originating event id — the three things an
// operator correlates by — and NEVER the payload bytes or the snapshot: a delivery body is
// outward content, and telemetry is not an outward channel (R1 redaction).
func (d *fakeDeliverer) DeliverIntent(_ context.Context, in app.Intent) (Result, error) {
	d.mu.Lock()
	d.calls++
	n, failFirst, failErr := d.calls, d.failFirst, d.failErr
	d.mu.Unlock()

	fields := []observability.Field{
		observability.String("intent_id", in.ID),
		observability.String("intent_type", string(in.Type)),
		observability.String("destination", in.Destination),
		observability.String("origin_event_id", in.OriginEventID),
		observability.Int("attempt", in.Attempts+1),
	}
	if n <= failFirst {
		if failErr == nil {
			failErr = errFakeFailure
		}
		d.logger.Warn("fake delivery failed", append(fields, observability.Err(failErr))...)
		return Result{Excerpt: "fake " + d.kind + ": refused"}, failErr
	}
	d.logger.Info("fake delivery accepted", fields...)
	return Result{
		StatusCode: 200,
		Excerpt:    "fake " + d.kind + ": accepted",
		Metadata: map[string]string{
			"transport": "fake",
			"channel":   d.kind,
			"reference": d.kind + "-" + in.ID,
		},
	}, nil
}

// FakeJiraDeliverer stands in for the issue-tracker sender (N-M1b). It is wired for
// app.IntentJiraIssue.
type FakeJiraDeliverer struct{ fakeDeliverer }

// NewFakeJiraDeliverer builds the Jira stand-in; a nil logger falls back to a no-op logger.
func NewFakeJiraDeliverer(logger *observability.Logger) *FakeJiraDeliverer {
	return &FakeJiraDeliverer{newFake("jira", logger)}
}

// FakeMailDeliverer stands in for the mail sender (N-M1b). It is wired for app.IntentEmail.
type FakeMailDeliverer struct{ fakeDeliverer }

// NewFakeMailDeliverer builds the mail stand-in; a nil logger falls back to a no-op logger.
func NewFakeMailDeliverer(logger *observability.Logger) *FakeMailDeliverer {
	return &FakeMailDeliverer{newFake("mail", logger)}
}

// ErrNoPayload is returned by a REAL sender handed an intent whose payload was never
// materialized. It refuses instead of rendering one now, which is the whole of D-N-3: the bytes
// that go out are the bytes that were snapshotted at enqueue, or nothing goes out. An N-M1a row
// (payload columns empty) therefore dead-letters under a real sender and is visible to an
// operator, rather than being sent as a body nobody recorded.
var ErrNoPayload = errors.New("delivery: intent carries no materialized payload")

// NewDeliverers picks one deliverer per intent type: the REAL sender when its channel is enabled
// AND its configuration is complete, the fake otherwise.
//
// An enabled-but-incomplete channel falls back to the fake and says so at ERROR, naming the knobs
// that are missing and never their values. That combination is deliberate: a node must keep
// draining its queue (an undrained queue hides every other outward obligation behind the first
// misconfiguration), but "I am sending to Jira" and "I am logging instead" must never be
// indistinguishable in the log.
func NewDeliverers(cfg Config, logger *observability.Logger) map[app.IntentType]IntentDeliverer {
	if logger == nil {
		logger = observability.Nop()
	}
	out := map[app.IntentType]IntentDeliverer{
		app.IntentJiraIssue: NewFakeJiraDeliverer(logger),
		app.IntentEmail:     NewFakeMailDeliverer(logger),
	}
	if cfg.Jira.Enabled {
		jira, err := NewRealJiraDeliverer(cfg.Jira, logger)
		if err != nil {
			logger.Error("jira delivery is ENABLED but its configuration is incomplete — the FAKE sender stays wired, so NOTHING will reach Jira",
				observability.Err(err))
		} else {
			out[app.IntentJiraIssue] = jira
			logger.Info("real jira sender wired", observability.String("config", cfg.Jira.String()))
		}
	}
	if cfg.Mail.Enabled {
		mail, err := NewRealMailDeliverer(cfg.Mail, logger)
		if err != nil {
			logger.Error("mail delivery is ENABLED but its configuration is incomplete — the FAKE sender stays wired, so NO mail will be sent",
				observability.Err(err))
		} else {
			out[app.IntentEmail] = mail
			logger.Info("real mail sender wired", observability.String("config", cfg.Mail.String()))
		}
	}
	return out
}

// Config controls the outward-delivery workers. Every field is documented here and mirrored in
// deploy/node.env.example (R2); ConfigFromEnv is the one place the environment is read.
type Config struct {
	// Enabled gates the WHOLE outward path: with it off (the default) no worker runs AND the
	// event reader records no intents. Off is the safe default because a node that cannot send
	// must not silently accumulate a queue, and because an outward action is a credentialed
	// act an operator opts into.
	Enabled bool
	// Workers is how many sends run concurrently within one pass.
	Workers int
	// Batch is how many due intents one pass claims.
	Batch int
	// MaxAttempts is how many attempts an intent gets before it dead-letters.
	MaxAttempts int
	// BackoffInitial is the delay after the first failed attempt; it doubles per attempt.
	BackoffInitial time.Duration
	// BackoffMax caps the doubling.
	BackoffMax time.Duration
	// DeadLetterAudience is the governed audience told that a delivery gave up.
	DeadLetterAudience string
	// Interval is the worker loop's cadence.
	Interval time.Duration

	// Jira configures the REAL issue-tracker sender (N-M1b). Off by default; with it off the
	// fake sender stays wired and no network call is made.
	Jira JiraConfig
	// Mail configures the REAL SMTP sender (N-M1b). Off by default, independently of Jira — a
	// node may ship tickets and still log its mail, or the reverse.
	Mail MailConfig
}

// Documented defaults for every knob (and the fallback for any out-of-range value — a
// misconfigured number must not disable the mechanism it configures).
const (
	defaultWorkers        = 2
	defaultBatch          = 50
	defaultMaxAttempts    = 3
	defaultBackoffInitial = 1 * time.Second
	defaultBackoffMax     = 30 * time.Second
	defaultInterval       = 5 * time.Second
)

// ConfigFromEnv reads the outward-delivery options:
//
//	THEMIS_COMMUNICATION_DELIVERY_ENABLED           "1" to record intents and run the workers (default off)
//	THEMIS_COMMUNICATION_DELIVERY_WORKERS           concurrent sends per pass (default 2)
//	THEMIS_COMMUNICATION_DELIVERY_BATCH             due intents claimed per pass (default 50)
//	THEMIS_COMMUNICATION_DELIVERY_MAX_ATTEMPTS      attempts before dead-letter (default 3)
//	THEMIS_COMMUNICATION_DELIVERY_BACKOFF_INITIAL   delay after the first failure (default 1s)
//	THEMIS_COMMUNICATION_DELIVERY_BACKOFF_MAX       cap on the doubling (default 30s)
//	THEMIS_COMMUNICATION_DELIVERY_INTERVAL          worker loop cadence (default 5s)
//	THEMIS_COMMUNICATION_DEADLETTER_AUDIENCE        audience told a delivery gave up (default "operations")
//
// The real senders are read by jiraFromEnv / mailFromEnv (see jira.go / mail.go), both OFF by
// default. Every SECRET among their knobs — the Jira API token, the SMTP password — is read from
// the environment and from nowhere else: no configuration file in this repository holds one, and
// none may (R2).
func ConfigFromEnv() Config {
	return Config{
		Enabled:            os.Getenv("THEMIS_COMMUNICATION_DELIVERY_ENABLED") == "1",
		Jira:               jiraFromEnv(),
		Mail:               mailFromEnv(),
		Workers:            envInt("THEMIS_COMMUNICATION_DELIVERY_WORKERS", defaultWorkers),
		Batch:              envInt("THEMIS_COMMUNICATION_DELIVERY_BATCH", defaultBatch),
		MaxAttempts:        envInt("THEMIS_COMMUNICATION_DELIVERY_MAX_ATTEMPTS", defaultMaxAttempts),
		BackoffInitial:     envDuration("THEMIS_COMMUNICATION_DELIVERY_BACKOFF_INITIAL", defaultBackoffInitial),
		BackoffMax:         envDuration("THEMIS_COMMUNICATION_DELIVERY_BACKOFF_MAX", defaultBackoffMax),
		Interval:           envDuration("THEMIS_COMMUNICATION_DELIVERY_INTERVAL", defaultInterval),
		DeadLetterAudience: os.Getenv("THEMIS_COMMUNICATION_DEADLETTER_AUDIENCE"),
	}
}

// withDefaults replaces any non-positive knob with its default, so a typo'd value degrades to
// the documented behaviour instead of a worker that claims zero rows forever.
func (c Config) withDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = defaultWorkers
	}
	if c.Batch <= 0 {
		c.Batch = defaultBatch
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultMaxAttempts
	}
	if c.BackoffInitial <= 0 {
		c.BackoffInitial = defaultBackoffInitial
	}
	if c.BackoffMax < c.BackoffInitial {
		c.BackoffMax = maxDuration(defaultBackoffMax, c.BackoffInitial)
	}
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	return c
}

// String renders the knobs for the startup log — an operator reading one line should be able
// to tell what the node will do. It prints whether each credential is SET, never its value: a
// startup line is telemetry, and telemetry is not a place a token may appear even once.
func (c Config) String() string {
	return fmt.Sprintf("enabled=%t workers=%d batch=%d max_attempts=%d backoff=%s..%s interval=%s deadletter_audience=%q jira=[%s] mail=[%s]",
		c.Enabled, c.Workers, c.Batch, c.MaxAttempts, c.BackoffInitial, c.BackoffMax, c.Interval, c.DeadLetterAudience,
		c.Jira, c.Mail)
}

// envBool reads a "1"/"0" switch; anything unset or unrecognized falls back to def.
func envBool(key string, def bool) bool {
	switch os.Getenv(key) {
	case "1":
		return true
	case "0":
		return false
	default:
		return def
	}
}

// secretState reports whether a secret is configured, for a log line that must never carry its
// value.
func secretState(secret string) string {
	if secret == "" {
		return "unset"
	}
	return "set"
}

// isLoopback reports whether a host is on this machine. It is the ONE exception both real senders
// make to "a credential never crosses an unencrypted channel" — the Jira token over plain http,
// the SMTP password without STARTTLS — and it is not a convenience. A loopback socket does not
// leave the machine, which is why net/smtp's own PLAIN mechanism draws the line in exactly the
// same place; and it is what keeps an httptest server or a local relay usable in a development
// deployment without a knob that could be set in a production one by mistake.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sanitizeHeaderValue folds CR and LF out of a value destined for a message header.
//
// A header is ONE line by definition, so a value carrying a newline does not produce a malformed
// header — it produces ADDITIONAL headers, or an early end of the header block that turns the rest
// into body. That is header injection, and the fact that every input here is operator-supplied or
// Themis-minted is a reason it has not happened, not a reason it cannot: a pasted address, a
// hand-edited env file, or an N-M1a payload whose subject was never folded all reach this point as
// strings. Folding is applied at the boundary where the harm would occur, so no caller has to
// remember.
func sanitizeHeaderValue(value string) string {
	// CRLF folds to ONE space rather than two, so the folded line reads the way the author meant it
	// to; a lone CR or LF folds to a space the same way.
	value = strings.ReplaceAll(value, "\r\n", " ")
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, value)
}

// hasControlChars reports whether a configured address carries a control character. Unlike a header
// value, which is folded, an ADDRESS is refused: a recipient nobody can read as an address is a
// configuration mistake, and silently repairing it would send security mail to an address the
// operator never checked.
func hasControlChars(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// getenv reads a knob and trims it: a value pasted into a systemd unit or an env file arrives
// with the whitespace the operator could not see.
func getenv(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func envInt(key string, def int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func envDuration(key string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(os.Getenv(key))
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// Package delivery holds the Communication context's outbound delivery channels and the
// redactor (D6). The channel-per-artifact-type push adapters (SMTP / Slack / webhook) and
// the export surface are reused from the PoC notify machinery downstream of a human trigger;
// this greenfield cut ships a logging deliverer + a pass-through redactor behind the app
// ports, so the exactly-once, idempotent, outcome-recorded delivery mechanics are exercised
// end-to-end while the concrete channels are wired in later.
//
// Since N-M1a it also holds the OUTWARD-DELIVERY WORKER (worker.go) and the FAKE senders the
// worker drives. The fakes make no network call of any kind: they log and return an outcome.
// That is deliberate for this step — the retry, backoff, dead-letter and operator mechanics
// are what N-M1a has to get right, and they are provable without a Jira instance. The real
// Jira and mail senders arrive in N-M1b behind the same IntentDeliverer seam.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
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
func ConfigFromEnv() Config {
	return Config{
		Enabled:            os.Getenv("THEMIS_COMMUNICATION_DELIVERY_ENABLED") == "1",
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
// to tell what the node will do.
func (c Config) String() string {
	return fmt.Sprintf("enabled=%t workers=%d batch=%d max_attempts=%d backoff=%s..%s interval=%s deadletter_audience=%q",
		c.Enabled, c.Workers, c.Batch, c.MaxAttempts, c.BackoffInitial, c.BackoffMax, c.Interval, c.DeadLetterAudience)
}

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

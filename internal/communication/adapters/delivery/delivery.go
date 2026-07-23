// Package delivery holds the Communication context's outbound delivery channels and the
// redactor (D6). The channel-per-artifact-type push adapters (SMTP / Slack / webhook) and
// the export surface are reused from the PoC notify machinery downstream of a human trigger;
// this greenfield cut ships a logging deliverer + a pass-through redactor behind the app
// ports, so the exactly-once, idempotent, outcome-recorded delivery mechanics are exercised
// end-to-end while the concrete channels are wired in later.
package delivery

import (
	"context"

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

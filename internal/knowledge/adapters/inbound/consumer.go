// Package inbound is the Knowledge context's anti-corruption layer for the Evidence seam:
// it decodes Evidence's EvidenceRegistered wire event into the app's inbound contract and
// dispatches it to the non-owning coordinator, which runs correlation. It never imports
// Evidence — the event JSON is the only contract (D5/D6). Unrelated event types are ignored
// so the same bus can carry events Knowledge does not consume.
package inbound

import (
	"context"
	"encoding/json"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/platform/eventbus"
)

// eventEvidenceRegistered is the Evidence integration-event type Knowledge consumes. Evidence
// stamps the event_type as "EvidenceRegistered" (its schema_ref is evidence.registered.v1);
// this is the wire contract, not a shared package.
const eventEvidenceRegistered = "EvidenceRegistered"

// Subscription declares Knowledge's bus binding (EB-07 / D7): it consumes the Evidence stream
// and dispatches on the single EvidenceRegistered fact. Composition binds this to a platform
// Reader over the inbox-wrapped Consumer.
var Subscription = eventbus.Subscription{
	Consumer: "knowledge",
	Stream:   "evidence",
	Interest: []string{eventEvidenceRegistered},
}

// Consumer translates raw Evidence events into coordinator calls.
type Consumer struct {
	coord *app.Coordinator
}

// NewConsumer wires the inbound consumer over the correlation coordinator.
func NewConsumer(coord *app.Coordinator) *Consumer { return &Consumer{coord: coord} }

// Handle decodes and dispatches one Evidence event carried by the kernel Envelope. It reads
// the event type + payload from the Envelope (M5 EB-02); the rest of the envelope metadata is
// transport concern. An unrecognized type is ignored (returns nil); a malformed payload for a
// recognized type is a real error (surfaced so the event is retried, not silently dropped).
func (c *Consumer) Handle(ctx context.Context, env event.Envelope) error {
	switch env.Type {
	case eventEvidenceRegistered:
		var dto evidenceRegisteredDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return err
		}
		return c.coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{
			EvidenceID: dto.EvidenceID,
			ReleaseID:  dto.SubjectReleaseID,
			Kind:       dto.Kind,
		})
	default:
		return nil // not a Knowledge-consumed event — ignore
	}
}

// Prepare decodes the envelope and runs the coordinator's READ phase OUTSIDE the inbox
// transaction, returning the write-only apply func (nil for an ignored/irrelevant envelope).
// It satisfies the store.Preparer optional interface so the InboxConsumer keeps the slow
// per-component discovery I/O out of its transaction — a long-open write transaction would pin
// the cluster xmin and starve the bus reader's gap-free watermark (EDR-EVENTBUS-01 D7). A
// malformed payload for a recognized type is surfaced so the event is retried, not dropped.
func (c *Consumer) Prepare(ctx context.Context, env event.Envelope) (func(context.Context) error, error) {
	switch env.Type {
	case eventEvidenceRegistered:
		var dto evidenceRegisteredDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return nil, err
		}
		return c.coord.PrepareEvidenceRegistered(ctx, app.EvidenceRegistered{
			EvidenceID: dto.EvidenceID,
			ReleaseID:  dto.SubjectReleaseID,
			Kind:       dto.Kind,
		})
	default:
		return nil, nil // not a Knowledge-consumed event — no-op
	}
}

// evidenceRegisteredDTO mirrors Evidence's evidence.registered.v1 payload (snake_case — it
// marshals a dedicated integration DTO). Only the fields correlation needs are decoded.
type evidenceRegisteredDTO struct {
	EvidenceID       string `json:"evidence_id"`
	Kind             string `json:"kind"`
	SubjectReleaseID string `json:"subject_release_id"`
}

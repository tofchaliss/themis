package event

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

//go:embed envelope.schema.json
var schemaJSON []byte

// Envelope is the integration-event envelope: the stable, behavior-free contract that
// wraps every domain event crossing a bounded-context boundary (BCK-0046). It carries
// identity, routing, and correlation metadata; the domain-specific payload is an
// opaque JSON document owned by the publishing context. The outbox runner + bus that
// carry envelopes are Event Infrastructure (M5), not the kernel.
type Envelope struct {
	ID            string          `json:"id"`                // unique event id
	Type          string          `json:"type"`              // event type, e.g. "evidence.registered"
	OccurredAt    time.Time       `json:"occurred_at"`       // when the source state transition completed
	SourceContext string          `json:"source_context"`    // publishing context, e.g. "evidence"
	Subject       string          `json:"subject"`           // subject / aggregate reference
	SchemaRef     string          `json:"schema_ref"`        // identifier of the payload's schema
	CorrelationID string          `json:"correlation_id"`    // ties the event to a workflow across nodes
	Payload       json.RawMessage `json:"payload,omitempty"` // opaque domain payload, owned by the source
}

// NewEnvelope validates and constructs an Envelope. All metadata fields are required;
// the payload is optional (thin events carry key headers only — EDR-EVIDENCE-01 D6).
// occurredAt is normalized to UTC.
func NewEnvelope(id, typ, sourceContext, subject, schemaRef, correlationID string, occurredAt time.Time, payload json.RawMessage) (Envelope, error) {
	switch {
	case strings.TrimSpace(id) == "":
		return Envelope{}, errors.New("event: empty id")
	case strings.TrimSpace(typ) == "":
		return Envelope{}, errors.New("event: empty type")
	case strings.TrimSpace(sourceContext) == "":
		return Envelope{}, errors.New("event: empty source context")
	case strings.TrimSpace(subject) == "":
		return Envelope{}, errors.New("event: empty subject")
	case strings.TrimSpace(schemaRef) == "":
		return Envelope{}, errors.New("event: empty schema ref")
	case strings.TrimSpace(correlationID) == "":
		return Envelope{}, errors.New("event: empty correlation id")
	case occurredAt.IsZero():
		return Envelope{}, errors.New("event: zero occurred-at")
	}
	return Envelope{
		ID:            id,
		Type:          typ,
		OccurredAt:    occurredAt.UTC(),
		SourceContext: sourceContext,
		Subject:       subject,
		SchemaRef:     schemaRef,
		CorrelationID: correlationID,
		Payload:       payload,
	}, nil
}

// Schema returns the JSON schema (Draft 2020-12) describing the envelope's wire form.
// Consumers (e.g. Event Infrastructure, M5) validate serialized envelopes against it.
func Schema() []byte { return schemaJSON }

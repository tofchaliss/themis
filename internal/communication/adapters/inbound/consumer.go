// Package inbound is the Communication context's anti-corruption layer for the Governance
// seam: it decodes Governance's wire events and drives two things — the publishable-positions
// worklist (Positions only, DOM-0025) and the outward-action delivery intents (N-M1a). It
// never auto-materializes (D4) and never imports Governance — the event JSON is the only
// contract. Unrelated event types are ignored so the same bus can carry events Communication
// does not consume.
//
// What this ACL must NOT do is as load-bearing as what it does: on a delivery-relevant event
// it RECORDS an intent and returns. It never calls Jira, a mail relay or a CI system, so no
// outward system's availability can stall the governance stream, fail an envelope, or make
// the reader retry a fact it has already applied (D-N-2).
package inbound

import (
	"context"
	"encoding/json"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/eventbus"
)

// Governance integration-event type identifiers Communication consumes (mirrors
// EDR-GOVERNANCE-01 D8). These are the wire contract, not a shared package.
const (
	eventPositionEstablished = "governance.position_established"
	eventPositionRevised     = "governance.position_revised"
	eventFindingOpened       = "governance.finding_opened"
	eventProposalAccepted    = "governance.proposal_accepted"
)

// harnessExecutionSchema is the evidence schema whose presence on an accepted proposal turns
// the acceptance into a CI build as well as a mail (EDR-HARNESS-01 D-I-5).
const harnessExecutionSchema = "harness-execution/v1"

// Subscription declares Communication's bus binding (EB-07 / D7): it consumes the Governance
// stream and dispatches only on the facts below — the two Position facts that drive the
// worklist, and the two lifecycle facts that call for an outward action (N-M1a). Composition
// binds this to a platform Reader over the inbox-wrapped Consumer; the interest filter drops
// the rest of what Governance emits.
var Subscription = eventbus.Subscription{
	Consumer: "communication",
	Stream:   "governance",
	Interest: []string{eventPositionEstablished, eventPositionRevised, eventFindingOpened, eventProposalAccepted},
}

// Consumer translates raw Governance events into publishable-queue updates and delivery
// intents.
type Consumer struct {
	svc     *app.PublicationService
	intents *app.DeliveryIntentService // outward actions (N-M1a); nil = not configured
}

// NewConsumer wires the inbound consumer over the publication service.
func NewConsumer(svc *app.PublicationService) *Consumer { return &Consumer{svc: svc} }

// WithDeliveryIntents wires the outward-action recorder and returns the consumer for
// chaining — kept out of the constructor so existing call sites keep compiling; production
// wiring always sets it. Left nil, the lifecycle events are ignored and no intent is ever
// recorded, which is the correct behaviour for a node that does no outward delivery.
func (c *Consumer) WithDeliveryIntents(svc *app.DeliveryIntentService) *Consumer {
	c.intents = svc
	return c
}

// Handle decodes and dispatches one Governance event carried by the kernel Envelope. It
// reads the event type + payload from the Envelope (M5 EB-02); the rest of the envelope
// metadata is transport concern, not the ACL's — except the envelope ID, which is the
// delivery intent's dedup identity. A PositionEstablished marks the Position ready to
// publish; a PositionRevised marks it stale (re-publish needed — D5). A FindingOpened or
// ProposalAccepted records outward-action intents. An unrecognized type is ignored (returns
// nil); a malformed payload for a recognized type is a real error (surfaced so the event is
// retried, not silently dropped).
func (c *Consumer) Handle(ctx context.Context, env event.Envelope) error {
	switch env.Type {
	case eventPositionEstablished:
		snap, err := decodeSnapshot(env.Payload)
		if err != nil {
			return err
		}
		return c.svc.RecordPublishable(ctx, snap, false)
	case eventPositionRevised:
		snap, err := decodeSnapshot(env.Payload)
		if err != nil {
			return err
		}
		return c.svc.RecordPublishable(ctx, snap, true)
	case eventFindingOpened:
		return c.handleFindingOpened(ctx, env)
	case eventProposalAccepted:
		return c.handleProposalAccepted(ctx, env)
	default:
		return nil // not a Communication-consumed event — ignore
	}
}

func (c *Consumer) handleFindingOpened(ctx context.Context, env event.Envelope) error {
	var dto findingOpenedDTO
	if err := json.Unmarshal(env.Payload, &dto); err != nil {
		return err
	}
	if c.intents == nil {
		return nil
	}
	_, err := c.intents.RecordFindingOpened(ctx, domain.DeliveryOrigin{
		EventID:     originID(env, dto.FindingID, dto.OccurredAt),
		EventType:   env.Type,
		EventTime:   eventTime(env, dto.OccurredAt),
		FindingID:   dto.FindingID,
		ReleaseID:   dto.ReleaseID,
		FaultlineID: dto.FaultlineID,
		CVE:         dto.CVE,
	})
	return err
}

func (c *Consumer) handleProposalAccepted(ctx context.Context, env event.Envelope) error {
	var dto proposalAcceptedDTO
	if err := json.Unmarshal(env.Payload, &dto); err != nil {
		return err
	}
	if c.intents == nil {
		return nil
	}
	_, err := c.intents.RecordProposalAccepted(ctx, domain.DeliveryOrigin{
		EventID:         originID(env, dto.FindingID, dto.OccurredAt),
		EventType:       env.Type,
		EventTime:       eventTime(env, dto.OccurredAt),
		FindingID:       dto.FindingID,
		ProposalID:      dto.ProposalID,
		PositionVersion: dto.PositionVersion,
	}, dto.EvidenceSchema == harnessExecutionSchema)
	return err
}

// positionEventDTO mirrors Governance's PositionEstablished / PositionRevised JSON (its
// domain event structs are marshaled without tags, so keys are the exported field names —
// decoding is case-insensitive).
type positionEventDTO struct {
	FindingID   string `json:"FindingID"`
	ReleaseID   string `json:"ReleaseID"`
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
	Version     int    `json:"Version"`
	Stance      string `json:"Stance"`
}

// findingOpenedDTO mirrors governance.finding_opened.v1.
type findingOpenedDTO struct {
	FindingID   string    `json:"FindingID"`
	ReleaseID   string    `json:"ReleaseID"`
	FaultlineID string    `json:"FaultlineID"`
	CVE         string    `json:"CVE"`
	OccurredAt  time.Time `json:"OccurredAt"`
}

// proposalAcceptedDTO mirrors governance.proposal_accepted.v1, plus one OPTIONAL field.
//
// HONEST LIMIT, RECORDED HERE BECAUSE THE FIELD LOOKS LOAD-BEARING AND IS NOT YET.
// EvidenceSchema is what decides whether an acceptance also fires a CI build, and the frozen
// v1 payload does not carry it (its schema is `additionalProperties: false` over exactly
// FindingID, ProposalID, PositionVersion, OccurredAt). N-M1a changes no existing event
// schema, so on a real estate this field is always absent and only the e-mail intent is
// recorded. The structure is here, tested, and starts working the day Governance's event
// states the proposal's evidence schema — which is M2's job, where the CI payload gains the
// artifact members it would need anyway. The alternative, asking Governance over HTTP what a
// finished event meant, would put a cross-context read on the event path to recover a fact
// the producer already knew.
type proposalAcceptedDTO struct {
	FindingID       string    `json:"FindingID"`
	ProposalID      string    `json:"ProposalID"`
	PositionVersion int       `json:"PositionVersion"`
	OccurredAt      time.Time `json:"OccurredAt"`
	EvidenceSchema  string    `json:"EvidenceSchema"`
}

// eventTime prefers the envelope's occurred-at (the transport's own stamp) and falls back to
// the payload's, which is what the dev `/internal/governance-events` seam supplies.
func eventTime(env event.Envelope, payloadTime time.Time) time.Time {
	if !env.OccurredAt.IsZero() {
		return env.OccurredAt
	}
	return payloadTime
}

// originID is the delivery intent's dedup identity. The envelope id is it whenever there is
// one — the bus assigns it, and the publisher is idempotent on it, so a replay or a
// redelivery lands on the same key. The dev HTTP seam posts envelopes with no id at all,
// and using an empty string there would collapse every event of a type onto ONE intent; the
// subject + occurred-at surrogate keeps distinct facts distinct without inventing an
// identity that the bus would later disagree with.
func originID(env event.Envelope, subject string, occurredAt time.Time) string {
	if env.ID != "" {
		return env.ID
	}
	return env.Type + ":" + subject + "@" + occurredAt.UTC().Format(time.RFC3339Nano)
}

func decodeSnapshot(payload []byte) (domain.PositionSnapshot, error) {
	var dto positionEventDTO
	if err := json.Unmarshal(payload, &dto); err != nil {
		return domain.PositionSnapshot{}, err
	}
	return domain.PositionSnapshot{
		FindingID: dto.FindingID,
		Version:   dto.Version,
		Stance:    domain.Stance(dto.Stance),
		Lineage: domain.Lineage{
			ReleaseID:   dto.ReleaseID,
			FindingID:   dto.FindingID,
			FaultlineID: dto.FaultlineID,
			CVE:         dto.CVE,
		},
	}, nil
}

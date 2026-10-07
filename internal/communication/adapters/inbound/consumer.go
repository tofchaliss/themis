// Package inbound is the Communication context's anti-corruption layer for the Governance
// seam: it decodes Governance's Position wire events (PositionEstablished / PositionRevised)
// and updates the publishable-positions worklist — Positions only (DOM-0025). It never
// auto-materializes (D4) and never imports Governance — the event JSON is the only contract.
// Unrelated event types are ignored so the same bus can carry events Communication does not
// consume.
//
// Since N-M1a it also records OUTWARD-DELIVERY INTENTS (EDR-DELIVERY-01 Revision 3): a
// Finding opened on a Release asks for a remediation ticket, an accepted proposal asks for a
// decision mail. The reader's entire outward job is to PERSIST the intent inside the inbox
// unit of work — it holds no Jira client, no mail client and no HTTP client, so no external
// system can block, slow or stall the bus reader path. Sending happens later, in the delivery
// worker.
package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

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
	// eventFindingOpened is the TEMPORARY PROXY for "this Release's vulnerabilities are
	// ready" (EDR-DELIVERY-01 RC-1 / D-N-8): the intended trigger is a dedicated
	// valuation-complete signal, which does not exist yet. The deviation is recorded rather
	// than hidden — a ticket raised per opened Finding is deduplicated to one intent per
	// EVENT, not to one per Release, so a Release with twelve Findings currently asks for
	// twelve tickets. That is the honest cost of the proxy and is why the proxy is temporary.
	eventFindingOpened = "governance.finding_opened"
	// eventProposalAccepted is a DECISION about exposure — told to the governed audience.
	eventProposalAccepted = "governance.proposal_accepted"
)

// Subscription declares Communication's bus binding (EB-07 / D7): it consumes the Governance
// stream and dispatches only on the four facts below — the two Position facts drive the
// publishable worklist (Positions only, DOM-0025) and the two delivery triggers drive outward
// delivery intents (N-M1a). Composition binds this to a platform Reader over the inbox-wrapped
// Consumer; the interest filter drops the other lifecycle events Governance also emits.
var Subscription = eventbus.Subscription{
	Consumer: "communication",
	Stream:   "governance",
	Interest: []string{
		eventPositionEstablished, eventPositionRevised,
		eventFindingOpened, eventProposalAccepted,
	},
}

// Consumer translates raw Governance events into publishable-queue updates and, when the
// outward-delivery intake is wired, into delivery intents.
type Consumer struct {
	svc     *app.PublicationService
	intents *app.DeliveryIntentService
}

// NewConsumer wires the inbound consumer over the publication service. Outward delivery is
// off until WithIntents is called.
func NewConsumer(svc *app.PublicationService) *Consumer { return &Consumer{svc: svc} }

// WithIntents attaches the delivery-intent intake, turning on the N-M1a mappings
// (finding_opened → remediation ticket, proposal_accepted → decision mail). Without it the
// consumer records no intents at all: outward delivery is opt-in per node
// (THEMIS_COMMUNICATION_DELIVERY_ENABLED), and a node that cannot SEND must not accumulate a
// queue nobody drains.
func (c *Consumer) WithIntents(intents *app.DeliveryIntentService) *Consumer {
	c.intents = intents
	return c
}

// Handle decodes and dispatches one Governance event carried by the kernel Envelope. It
// reads the event type + payload from the Envelope (M5 EB-02); the rest of the envelope
// metadata is transport concern, not the ACL's. A PositionEstablished marks the Position
// ready to publish; a PositionRevised marks it stale (re-publish needed — D5). An
// unrecognized type is ignored (returns nil); a malformed payload for a recognized type is a
// real error (surfaced so the event is retried, not silently dropped).
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
		return c.recordJiraIntent(ctx, env)
	case eventProposalAccepted:
		return c.recordDecisionMailIntent(ctx, env)
	default:
		return nil // not a Communication-consumed event — ignore
	}
}

// recordJiraIntent persists the remediation-ticket intent for the Release the Finding belongs
// to. The envelope id is the idempotence key, so a redelivery of the same event yields no
// second intent. A Finding whose event names no Release records NOTHING: an outward action
// with an indeterminate subject fails closed (RC-7).
//
// Product and project are left empty: the finding_opened contract does not carry them, and
// resolving them would mean a Registry read on the reader path — which is exactly what this
// reader must never do.
//
// An envelope carrying NO id (only the dev `/internal/governance-events` seam, which accepts a
// bare {type,payload}) has no deduplication key, so each POST records an intent. Bus-delivered
// envelopes always have one — the kernel requires it.
func (c *Consumer) recordJiraIntent(ctx context.Context, env event.Envelope) error {
	if c.intents == nil {
		return nil // outward delivery not wired on this node
	}
	var dto findingOpenedDTO
	if err := json.Unmarshal(env.Payload, &dto); err != nil {
		return err
	}
	_, err := c.intents.EnqueueJiraForRelease(ctx, lineageOf(env), env.ID, dto.ReleaseID, "", "",
		map[string]string{"finding_id": dto.FindingID, "faultline_id": dto.FaultlineID, "cve": dto.CVE})
	if errors.Is(err, app.ErrNoSubject) {
		return nil // nothing to track a fix for; not a transport failure, so do not retry
	}
	return err
}

// recordDecisionMailIntent persists the decision-notification intent for an accepted proposal.
// The accepted-proposal contract carries no Release, so the intent records the Finding and the
// proposal and leaves the Release empty rather than guessing it over a read seam.
func (c *Consumer) recordDecisionMailIntent(ctx context.Context, env event.Envelope) error {
	if c.intents == nil {
		return nil // outward delivery not wired on this node
	}
	var dto proposalAcceptedDTO
	if err := json.Unmarshal(env.Payload, &dto); err != nil {
		return err
	}
	_, err := c.intents.EnqueueDecisionMail(ctx, lineageOf(env), env.ID, dto.ProposalID, dto.FindingID, "", "",
		map[string]string{"position_version": strconv.Itoa(dto.PositionVersion)})
	if errors.Is(err, app.ErrNoSubject) {
		return nil // no decision subject to notify about
	}
	return err
}

// lineageOf records the originating envelope's identity on the intent, so an outward effect
// can always be traced back to the fact that caused it.
func lineageOf(env event.Envelope) app.IntentLineage {
	return app.IntentLineage{
		SourceContext: env.SourceContext,
		EventType:     env.Type,
		EventID:       env.ID,
		EventTime:     env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}
}

// findingOpenedDTO mirrors governance.finding_opened.v1 (keys are the exported field names —
// Governance marshals its domain event structs without tags).
type findingOpenedDTO struct {
	FindingID   string `json:"FindingID"`
	ReleaseID   string `json:"ReleaseID"`
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
}

// proposalAcceptedDTO mirrors governance.proposal_accepted.v1.
type proposalAcceptedDTO struct {
	FindingID       string `json:"FindingID"`
	ProposalID      string `json:"ProposalID"`
	PositionVersion int    `json:"PositionVersion"`
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

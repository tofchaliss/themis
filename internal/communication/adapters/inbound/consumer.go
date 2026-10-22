// Package inbound is the Communication context's anti-corruption layer for the Governance
// seam: it decodes Governance's Position wire events (PositionEstablished / PositionRevised)
// and updates the publishable-positions worklist — Positions only (DOM-0025). It never
// auto-materializes (D4) and never imports Governance — the event JSON is the only contract.
// Unrelated event types are ignored so the same bus can carry events Communication does not
// consume.
//
// Since N-M1a it also records OUTWARD-DELIVERY INTENTS (EDR-DELIVERY-01 Revision 3): a
// Release evaluated after a NEW SBOM asks for a remediation ticket (N-M2c, Revision 4 M2-1..M2-3),
// an accepted proposal asks for a decision mail, and the evaluation also tells the governed
// audience by mail (N-M2f). The reader's entire outward job is to PERSIST the intent inside the inbox
// unit of work — it holds no Jira client, no mail client and no HTTP client, so no external
// system can block, slow or stall the bus reader path. Sending happens later, in the delivery
// worker.
package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

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
	// eventReleaseEvaluated is RC-1's "release posture evaluated" signal (EDR-DELIVERY-01
	// Revision 4, M2-2): one event per Release evaluation, carrying product and project. It
	// replaced the `governance.finding_opened` proxy of M1a-3 in N-M2c — that proxy fired once
	// per Finding, so a Release with twelve Findings asked for twelve tickets. Only an evaluation
	// caused by a NEW SBOM asks for a ticket: a re-discovery sweep changes the posture but builds
	// nothing, and ticketing it would spend the rebuild loop's attempts on nothing (M2-3).
	eventReleaseEvaluated = "governance.release_evaluated"
	// causeNewSBOM restates the one value of the closed `cause` vocabulary this consumer acts
	// on. The wire contract is the only thing shared with Governance.
	causeNewSBOM = "new_sbom"
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
		eventReleaseEvaluated, eventProposalAccepted,
	},
}

// Consumer translates raw Governance events into publishable-queue updates and, when the
// outward-delivery intake is wired, into delivery intents.
type Consumer struct {
	svc     *app.PublicationService
	intents *app.DeliveryIntentService
	loop    *app.RebuildLoop // the rebuild loop (N-M2i); nil = no cycles, no rebuilds
}

// NewConsumer wires the inbound consumer over the publication service. Outward delivery is
// off until WithIntents is called.
func NewConsumer(svc *app.PublicationService) *Consumer { return &Consumer{svc: svc} }

// WithIntents attaches the delivery-intent intake, turning on the delivery mappings
// (release_evaluated/new_sbom → remediation ticket, proposal_accepted → decision mail). Without it the
// consumer records no intents at all: outward delivery is opt-in per node
// (THEMIS_COMMUNICATION_DELIVERY_ENABLED), and a node that cannot SEND must not accumulate a
// queue nobody drains.
func (c *Consumer) WithIntents(intents *app.DeliveryIntentService) *Consumer {
	c.intents = intents
	return c
}

// WithRebuildLoop attaches the rebuild loop (EDR-DELIVERY-01 M2-8 / N-M2i): a new_sbom
// evaluation then opens, advances or stops the Release's cycle, the ticket and the mail carry
// the loop's decision, and a continuing cycle asks the build system for the next rebuild.
func (c *Consumer) WithRebuildLoop(loop *app.RebuildLoop) *Consumer {
	c.loop = loop
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
	case eventReleaseEvaluated:
		return c.recordJiraIntent(ctx, env)
	case eventProposalAccepted:
		return c.recordDecisionMailIntent(ctx, env)
	default:
		return nil // not a Communication-consumed event — ignore
	}
}

// recordJiraIntent persists the remediation-ticket intent for an evaluated Release. The
// envelope id is the idempotence key, so a redelivery of the same event yields no second
// intent — and because one Release evaluation is one event, this is what realizes RC-2's
// one-ticket-per-Release. An evaluation whose cause is not a new SBOM records NOTHING and
// reports no error: the sweep re-evaluated an unchanged build, and there is no rebuild to ask
// for (M2-3). An event naming no Release records nothing either: an outward action with an
// indeterminate subject fails closed (RC-7).
//
// Product and project come from the event itself — Governance resolved them when it evaluated
// the Release — so the reader still performs no Registry read (M1a-1).
//
// An envelope carrying NO id (only the dev `/internal/governance-events` seam, which accepts a
// bare {type,payload}) has no deduplication key, so each POST records an intent. Bus-delivered
// envelopes always have one — the kernel requires it.
func (c *Consumer) recordJiraIntent(ctx context.Context, env event.Envelope) error {
	if c.intents == nil {
		return nil // outward delivery not wired on this node
	}
	var dto releaseEvaluatedDTO
	if err := json.Unmarshal(env.Payload, &dto); err != nil {
		return err
	}
	if dto.Cause != causeNewSBOM {
		return nil // re-discovery: a posture change with nothing built — no ticket (M2-3)
	}
	if strings.TrimSpace(dto.ReleaseID) == "" {
		return nil // nothing to track a fix for; not a transport failure, so do not retry
	}
	snapshot := map[string]string{"sbom_id": dto.SBOMID, "cause": dto.Cause}
	dto.UploadOutcome.snapshot(snapshot)
	// The loop decides FIRST (M2-8 steps 3 and 5): the cycle is opened, advanced or stopped, and
	// its decision is stamped on the ticket and the mail below — a person reads what the loop
	// did where the posture is. The rebuild itself is asked for LAST, after both are recorded.
	var outcome app.RebuildOutcome
	if c.loop != nil {
		var err error
		if outcome, err = c.loop.Evaluate(ctx, dto.ReleaseID, dto.SBOMID, env.ID); err != nil {
			return err
		}
		for k, v := range outcome.Snapshot(c.loop.MaxAttempts()) {
			snapshot[k] = v
		}
	}
	if _, err := c.intents.EnqueueJiraForRelease(ctx, lineageOf(env), env.ID, dto.ReleaseID, dto.ProductID, dto.ProjectID, snapshot); err != nil {
		return err
	}
	// The mail to the governed audience rides the SAME event (M2-8 step 4 / N-M2f): the ticket
	// and the mail are two channels for one fact, deduplicated per (event, type). It is enqueued
	// after the ticket so a Release that reaches the mail already has its ticket intent.
	if _, err := c.intents.EnqueueEvaluationMail(ctx, lineageOf(env), env.ID, dto.ReleaseID, dto.ProductID, dto.ProjectID, "", snapshot); err != nil {
		return err
	}
	if c.loop == nil {
		return nil
	}
	_, _, err := c.loop.Raise(ctx, lineageOf(env), env.ID, outcome, dto.ProductID, dto.ProjectID)
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

// releaseEvaluatedDTO mirrors governance.release_evaluated.v1 (EDR-DELIVERY-01 M2-2; this one
// IS tagged on the producer side, snake_case). The severity counts are not read: the ticket
// body is rendered from the posture read API at intent time, not from the event.
type releaseEvaluatedDTO struct {
	ProductID     string            `json:"product_id"`
	ProjectID     string            `json:"project_id"`
	ReleaseID     string            `json:"release_id"`
	SBOMID        string            `json:"sbom_id"`
	Cause         string            `json:"cause"`
	UploadOutcome *uploadOutcomeDTO `json:"upload_outcome,omitempty"`
}

// uploadOutcomeDTO mirrors governance.release_evaluated.v1's upload_outcome (EDR-REMEDIATION-01 D3).
type uploadOutcomeDTO struct {
	New             int      `json:"new"`
	Reappeared      int      `json:"reappeared"`
	NoLongerPresent int      `json:"no_longer_present"`
	Unchanged       int      `json:"unchanged"`
	NotJudged       int      `json:"not_judged"`
	NewCVEs         []string `json:"new_cves"`
	ReappearedCVEs  []string `json:"reappeared_cves"`
	GoneCVEs        []string `json:"no_longer_present_cves"`
	HasBaseline     bool     `json:"has_baseline"`
}

// snapshot copies the outcome onto an intent's snapshot.
func (o *uploadOutcomeDTO) snapshot(into map[string]string) {
	if o == nil {
		return
	}
	into[app.SnapshotOutcomeNew] = strconv.Itoa(o.New)
	into[app.SnapshotOutcomeReappeared] = strconv.Itoa(o.Reappeared)
	into[app.SnapshotOutcomeNoLongerPresent] = strconv.Itoa(o.NoLongerPresent)
	into[app.SnapshotOutcomeUnchanged] = strconv.Itoa(o.Unchanged)
	into[app.SnapshotOutcomeNotJudged] = strconv.Itoa(o.NotJudged)
	into[app.SnapshotOutcomeNewCVEs] = strings.Join(o.NewCVEs, ",")
	into[app.SnapshotOutcomeReappearedCVEs] = strings.Join(o.ReappearedCVEs, ",")
	into[app.SnapshotOutcomeGoneCVEs] = strings.Join(o.GoneCVEs, ",")
	into[app.SnapshotOutcomeHasBaseline] = strconv.FormatBool(o.HasBaseline)
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

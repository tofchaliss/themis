package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild triggers and decisions (EDR-REBUILD-01 D3, D9, D27, D29; step R2 part 2).
//
// A trigger is written by the store IN THE SAME TRANSACTION as the event that causes it: the
// release_evaluated note of a new SBOM, or the fix_available note. So a trigger exists exactly
// when its event does, and its id is that event's id. This worker judges each open trigger off
// that transaction, with the judgement of part 1, and closes it in one transaction with what
// follows: a decision and its event (outcome recommend or request), or only the reason
// (outcome none). It starts no build. Nothing consumes the two events until a later step.
//
// Step R2a adds the build profile (D10, D16): a decision carries the profile that applies to
// the Release, frozen, with its scope, revision and digest. With no profile there is no
// request: the decision is a recommendation whose reason says so.

// The two rebuild events. One carries a recommendation for a person (mode ask), the other a
// request (mode auto). Both carry a domain.RebuildDecision.
const (
	EventRebuildRecommended = "governance.rebuild_recommended"
	EventRebuildRequested   = "governance.rebuild_requested"
)

// DefaultRebuildTriggerInterval is how often the worker looks for open triggers.
const DefaultRebuildTriggerInterval = 30 * time.Second

// rebuildTriggerBatch bounds one pass.
const rebuildTriggerBatch = 50

// RebuildDecisionsDefaultLimit and RebuildDecisionsMaxLimit bound the list read.
const (
	RebuildDecisionsDefaultLimit = 20
	RebuildDecisionsMaxLimit     = 200
)

// ErrRebuildFixVerdictsUnread is why a trigger is not judged yet: Knowledge could not be
// asked. The read of part 1 answers anyway (every fix unknown); a trigger must not, because
// "nothing counts" would then be recorded for a Release that was never really judged.
var ErrRebuildFixVerdictsUnread = errors.New("governance: the fix verdicts of this release could not be read")

// ErrRebuildDecisionsUnavailable is returned when the decision read is not wired.
var ErrRebuildDecisionsUnavailable = errors.New("governance: rebuild decisions not configured")

// ReleaseBuildProfile is the build profile that applies to one Release, as Registry resolves
// it (EDR-REBUILD-01 D10, D16): the Release's own, else its Project's.
type ReleaseBuildProfile struct {
	// Found is false when neither states one. The other fields are then empty.
	Found bool
	// Profile is the stored JSON object, byte for byte.
	Profile  []byte
	Scope    string
	Revision int
	SHA256   string
}

// BuildProfileReader reads it from Registry. It fails closed: an error, never "none" for a
// profile that could not be read.
type BuildProfileReader interface {
	ReleaseBuildProfile(ctx context.Context, releaseID string) (ReleaseBuildProfile, error)
}

// RebuildTrigger is one recorded trigger.
type RebuildTrigger struct {
	// ID is the queue row's own identity; it means nothing outside the queue.
	ID int64
	// TriggerID with Source is the causing event's identity (D27).
	TriggerID  string
	Source     string
	Type       string
	ReleaseID  string
	ReceivedAt time.Time
}

// RebuildTriggerResult is how a trigger was closed.
type RebuildTriggerResult struct {
	// Outcome is none, recommend or request.
	Outcome string
	// Reason is set with outcome none (domain.RebuildNone*).
	Reason        string
	EffectiveMode string
	ModeSetBy     string
	Considered    int
	Targeted      int
	SettledAt     time.Time
	// PointsTo is the decision id of the standing recommendation, set with outcome unchanged
	// (D41 item 2).
	PointsTo string
	// EndStanding is the decision id of the standing recommendation this result ends, and
	// EndState the state it gets: superseded or withdrawn (D41 item 3, D44 item 3).
	EndStanding string
	EndState    string
	// Retrigger is the decision id of an approved recommendation whose open cycle keeps this
	// trigger from making a new one. The Release is judged again when that cycle closes (D44
	// item 7).
	Retrigger string
}

// ErrRebuildStandingChanged is returned by a write that rested on the standing recommendation
// of a Release when that recommendation changed first (another trigger, an approval, the
// expiry). Nothing was written; the trigger stays open and is judged again (D44 item 5).
var ErrRebuildStandingChanged = errors.New("governance: the standing rebuild recommendation changed; the trigger is judged again")

// RebuildRecommendation is a recommendation with its state (D44).
type RebuildRecommendation struct {
	Decision domain.RebuildDecision
	// State is one of domain.RebuildRec*, as stored. A standing one may already be past its
	// time by the clock; domain.RebuildRecommendationExpired says so.
	State   string
	StateAt time.Time
	// SupersededBy is the decision id of the recommendation that replaced this one.
	SupersededBy string
	// Approval is set in state approved. CycleClosed says that Governance heard its rebuild
	// cycle close.
	Approval    *domain.RebuildApproval
	CycleClosed bool
}

// RebuildRecommendationStatus is what a trigger needs to know of a Release: the recommendation
// that is standing, and the approved one whose cycle is not known to be closed.
type RebuildRecommendationStatus struct {
	Standing     *RebuildRecommendation
	ApprovedOpen *RebuildRecommendation
}

// RebuildTriggerRecord is a trigger as the list read serves it: closed or still open, with its
// decision when it ended in one.
type RebuildTriggerRecord struct {
	RebuildTrigger
	// Settled is false while the trigger waits to be judged; Result is then empty.
	Settled  bool
	Result   RebuildTriggerResult
	Decision *domain.RebuildDecision
}

// RebuildTriggerStore is the persistence seam.
type RebuildTriggerStore interface {
	// PendingRebuildTriggers lists open triggers, oldest first, bounded.
	PendingRebuildTriggers(ctx context.Context, limit int) ([]RebuildTrigger, error)
	// SettleRebuildTrigger closes the trigger with res and, when decision is not nil, stores
	// the decision and appends note to the outbox, all in ONE transaction. A trigger another
	// pass already closed is left alone and nothing is written.
	SettleRebuildTrigger(ctx context.Context, trig RebuildTrigger, res RebuildTriggerResult, decision *domain.RebuildDecision, note OutboxNote) error
	// RebuildTriggerRecords lists the triggers of one Release, newest first, bounded.
	RebuildTriggerRecords(ctx context.Context, releaseID string, limit int) ([]RebuildTriggerRecord, error)
	// RebuildRecommendationStatus reads the standing and the approved-open recommendation.
	RebuildRecommendationStatus(ctx context.Context, releaseID string) (RebuildRecommendationStatus, error)
	// ExpireRebuildRecommendation moves a standing recommendation to expired and appends note
	// to the outbox in ONE transaction. moved is false when it was no longer standing; nothing
	// is written then (D46 item 1: one expiry, one event).
	ExpireRebuildRecommendation(ctx context.Context, decisionID string, at time.Time, note OutboxNote) (moved bool, err error)
}

// EventRebuildRecommendationExpired tells that a recommendation ran out unanswered (D26).
const EventRebuildRecommendationExpired = "governance.rebuild_recommendation_expired"

// expireRebuildRecommendation records the expiry of rec once, with its event.
func expireRebuildRecommendation(ctx context.Context, store interface {
	ExpireRebuildRecommendation(ctx context.Context, decisionID string, at time.Time, note OutboxNote) (bool, error)
}, rec RebuildRecommendation, now time.Time) (bool, error) {
	return store.ExpireRebuildRecommendation(ctx, rec.Decision.DecisionID, now, OutboxNote{
		EventType: EventRebuildRecommendationExpired, OccurredAt: now,
		Event: domain.NewRebuildRecommendationExpired(rec.Decision, now),
	})
}

// RebuildTriggerWorker judges open triggers.
type RebuildTriggerWorker struct {
	store    RebuildTriggerStore
	eval     *RebuildEvaluationService
	profiles BuildProfileReader
	ids      IDGenerator
	clock    Clock
	log      EvaluationLog
	// waiting holds the open triggers whose failure was already reported, so that a Release
	// that cannot be judged is said once and not on every pass. Process-local: a restart says
	// it once more.
	waiting map[int64]struct{}
}

// NewRebuildTriggerWorker wires the worker. log may be nil.
func NewRebuildTriggerWorker(store RebuildTriggerStore, eval *RebuildEvaluationService, profiles BuildProfileReader, ids IDGenerator, clock Clock, log EvaluationLog) *RebuildTriggerWorker {
	return &RebuildTriggerWorker{store: store, eval: eval, profiles: profiles, ids: ids, clock: clock, log: log, waiting: map[int64]struct{}{}}
}

// RunEvery judges on a cadence until ctx is cancelled.
func (w *RebuildTriggerWorker) RunEvery(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Tick(ctx)
		}
	}
}

// Tick performs one pass and reports how many triggers it closed. A trigger that cannot be
// judged now stays open for the next pass; one failing Release does not hold back the others.
func (w *RebuildTriggerWorker) Tick(ctx context.Context) (settled int) {
	pending, err := w.store.PendingRebuildTriggers(ctx, rebuildTriggerBatch)
	if err != nil {
		w.report("rebuild triggers could not be listed", "", err)
		return 0
	}
	for _, trig := range pending {
		if ctx.Err() != nil {
			return settled
		}
		if err := w.settle(ctx, trig); err != nil {
			if _, said := w.waiting[trig.ID]; !said {
				w.waiting[trig.ID] = struct{}{}
				w.report("rebuild trigger not judged yet; it stays open and is tried again", trig.ReleaseID, err)
			}
			continue
		}
		delete(w.waiting, trig.ID)
		settled++
	}
	return settled
}

func (w *RebuildTriggerWorker) settle(ctx context.Context, trig RebuildTrigger) error {
	now := w.clock.Now().UTC().Truncate(time.Microsecond)
	ev, err := w.eval.Evaluate(ctx, trig.ReleaseID)
	if err == nil && !ev.FixVerdictsRead {
		err = ErrRebuildFixVerdictsUnread
	}
	// The build profile is read only when something would be asked for (D10). A profile that
	// cannot be read keeps the trigger open, like any other unreadable fact: it must not read
	// as "no profile".
	var profile ReleaseBuildProfile
	if err == nil && ev.Outcome != domain.RebuildOutcomeNone {
		profile, err = w.profiles.ReleaseBuildProfile(ctx, ev.Policy.ReleaseID)
	}
	if err != nil {
		if now.Sub(trig.ReceivedAt) < domain.RebuildTriggerMaxAge {
			return err
		}
		// Too old to be worth judging: close it unjudged and say so.
		w.report("rebuild trigger closed unjudged after the wait limit", trig.ReleaseID, err)
		return w.store.SettleRebuildTrigger(ctx, trig, RebuildTriggerResult{
			Outcome: domain.RebuildOutcomeNone, Reason: domain.RebuildNoneGaveUp, SettledAt: now,
		}, nil, OutboxNote{})
	}
	// The standing recommendation of the Release, and the approved one whose cycle may still
	// be open (D41, D44). A standing one past its time is expired first, with its event; the
	// rest of the judgement then sees no standing recommendation (D44 items 1 and 2).
	status, err := w.store.RebuildRecommendationStatus(ctx, trig.ReleaseID)
	if err != nil {
		return err
	}
	standing := status.Standing
	if standing != nil && domain.RebuildRecommendationExpired(standing.Decision.DecidedAt, now) {
		if _, err := expireRebuildRecommendation(ctx, w.store, *standing, now); err != nil {
			return err
		}
		standing = nil
	}
	res := RebuildTriggerResult{
		Outcome: ev.Outcome, EffectiveMode: string(ev.Policy.EffectiveMode), ModeSetBy: ev.Policy.EffectiveSetBy,
		Considered: ev.Considered, Targeted: len(ev.Targeted), SettledAt: now,
	}
	if standing != nil {
		// Whatever follows ends it, except an equal result (below).
		res.EndStanding, res.EndState = standing.Decision.DecisionID, domain.RebuildRecWithdrawn
	}
	if ev.Outcome == domain.RebuildOutcomeNone {
		res.Reason = domain.RebuildNoneReason(ev.Policy.EffectiveMode)
		return w.store.SettleRebuildTrigger(ctx, trig, res, nil, OutboxNote{})
	}
	decision := newRebuildDecision(w.ids.NewID(), trig, ev, now)
	// No profile, no request (D10 item 6): the decision is then a recommendation that says so.
	decision.Outcome, decision.RecommendReason = domain.RebuildOutcomeWithProfile(ev.Outcome, profile.Found)
	if profile.Found {
		decision.Build = append([]byte{}, profile.Profile...)
		decision.BuildProfile = &domain.RebuildDecisionBuildProfile{Scope: profile.Scope, Revision: profile.Revision, SHA256: profile.SHA256}
	}
	res.Outcome = decision.Outcome
	if decision.Outcome == domain.RebuildOutcomeRequest {
		// Mode auto: the request goes out directly; a standing recommendation is withdrawn.
		return w.store.SettleRebuildTrigger(ctx, trig, res, &decision,
			OutboxNote{EventType: EventRebuildRequested, Event: decision, OccurredAt: now})
	}
	switch open := status.ApprovedOpen; {
	case standing != nil && domain.SameRebuildRecommendation(standing.Decision, decision):
		// The same ask as the standing one: nothing new, nobody is told again (D41 item 2).
		res.Outcome, res.PointsTo = domain.RebuildOutcomeUnchanged, standing.Decision.DecisionID
		res.EndStanding, res.EndState = "", ""
		return w.store.SettleRebuildTrigger(ctx, trig, res, nil, OutboxNote{})
	case standing != nil:
		// A different ask: the standing one is superseded and the new one says so (D45 item 4).
		res.EndState, decision.Supersedes = domain.RebuildRecSuperseded, standing.Decision.DecisionID
	case open != nil && open.Approval != nil && domain.RebuildApprovedHolds(open.Approval.ApprovedAt, now):
		// A recommendation was approved and its cycle is not known to be closed: no new one
		// now. The Release is judged again when the cycle closes (D44 item 7).
		res.Outcome, res.Reason, res.Retrigger = domain.RebuildOutcomeNone, domain.RebuildNoneCycleOpen, open.Decision.DecisionID
		return w.store.SettleRebuildTrigger(ctx, trig, res, nil, OutboxNote{})
	}
	return w.store.SettleRebuildTrigger(ctx, trig, res, &decision,
		OutboxNote{EventType: EventRebuildRecommended, Event: decision, OccurredAt: now})
}

func (w *RebuildTriggerWorker) report(msg, releaseID string, err error) {
	if w.log != nil {
		w.log.Error(msg, releaseID, err)
	}
}

// newRebuildDecision freezes a judgement as a decision (D29).
func newRebuildDecision(id string, trig RebuildTrigger, ev RebuildEvaluation, at time.Time) domain.RebuildDecision {
	pol := ev.Policy
	p := pol.InForce.Policy
	// A copy, never nil: the frozen record must not share the judgement's map, and the wire
	// shape is an object even when nothing was skipped.
	skipped := map[string]int{}
	for reason, n := range ev.Skipped {
		skipped[reason] = n
	}
	return domain.RebuildDecision{
		DecisionID: id, ReleaseID: pol.ReleaseID, ProductID: pol.ProductID, ProjectID: pol.ProjectID,
		TriggerID: trig.TriggerID, TriggerSource: trig.Source, TriggerType: trig.Type,
		Outcome:       ev.Outcome,
		EffectiveMode: string(pol.EffectiveMode), EffectiveModeSetBy: pol.EffectiveSetBy,
		InstallationMode: string(pol.InstallationMode),
		Tag:              pol.Tag.Tag, TagLevel: pol.Tag.Level,
		Policy: domain.RebuildDecisionPolicy{
			ScopeKind: pol.InForce.ScopeKind, ScopeID: pol.InForce.ScopeID, Version: pol.InForce.Version,
			FixRequired: p.FixRequired, SeverityFloor: p.SeverityFloor,
			CountKnownExploited: p.CountKnownExploited, SkipDecided: p.SkipDecided, CarrierOnly: p.CarrierOnly,
			CoolDownSeconds: int64(p.CoolDown / time.Second), Mode: string(p.Mode),
		},
		Considered: ev.Considered, Skipped: skipped,
		Targeted: rebuildDecisionEntries(ev.Targeted), OtherStream: rebuildDecisionEntries(ev.OtherStream),
		DecidedAt: at,
	}
}

func rebuildDecisionEntries(entries []RebuildEvaluationEntry) []domain.RebuildDecisionEntry {
	out := make([]domain.RebuildDecisionEntry, 0, len(entries))
	for _, e := range entries {
		// A copy, never nil: with fix_required off an entry can count with no fix named.
		fixed := append([]string{}, e.FixedVersions...)
		out = append(out, domain.RebuildDecisionEntry{
			FindingID: string(e.FindingID), CVE: e.CVE, PURL: e.PURL,
			CurrentVersion: e.CurrentVersion, FixedVersions: fixed, FixSource: e.FixSource,
			Severity: e.Severity, Score: e.Score, ScoreSource: e.ScoreSource,
			KnownExploited:  e.KnownExploited,
			ClaimClass:      domain.RebuildClaimClassName(e.ClaimClass),
			Position:        domain.RebuildPositionName(e.Position),
			AssessmentState: e.AssessmentState, CountedBecause: e.CountedBecause,
		})
	}
	return out
}

// RebuildDecisionReader serves the triggers and decisions of one Release.
type RebuildDecisionReader struct {
	store RebuildTriggerStore
}

// NewRebuildDecisionReader wires the read.
func NewRebuildDecisionReader(store RebuildTriggerStore) *RebuildDecisionReader {
	return &RebuildDecisionReader{store: store}
}

// ForRelease lists the triggers of the Release, newest first. A non-positive limit takes the
// default and a limit above the cap is clamped.
func (r *RebuildDecisionReader) ForRelease(ctx context.Context, releaseID string, limit int) ([]RebuildTriggerRecord, error) {
	if r == nil || r.store == nil {
		return nil, ErrRebuildDecisionsUnavailable
	}
	if limit <= 0 {
		limit = RebuildDecisionsDefaultLimit
	}
	if limit > RebuildDecisionsMaxLimit {
		limit = RebuildDecisionsMaxLimit
	}
	return r.store.RebuildTriggerRecords(ctx, releaseID, limit)
}

// RebuildTriggerRecorder records what a closed rebuild cycle means for Governance.
type RebuildTriggerRecorder interface {
	// RecordRebuildTrigger stores an open trigger. The same (source, id) twice stores one.
	RecordRebuildTrigger(ctx context.Context, triggerID, source, triggerType, releaseID string) error
	// MarkRebuildCyclesClosed notes on the approved recommendations among decisionIDs that
	// their cycle closed, which ends their hold on new recommendations (D44 item 7). retrigger
	// says whether a trigger was kept back by one of them.
	MarkRebuildCyclesClosed(ctx context.Context, decisionIDs []string) (retrigger bool, err error)
}

// InboundRebuildCycleClosed is communication.rebuild_cycle_closed as the Coordinator takes it:
// EventID is the envelope id and becomes the trigger id, so a redelivered event is one trigger.
type InboundRebuildCycleClosed struct {
	EventID   string
	ReleaseID string
	// DecisionID is the decision the cycle was opened from, and Joined the decisions that
	// arrived while it was open.
	DecisionID string
	Joined     []string
}

// rebuildCycleSource is the trigger source of a closed cycle: the context that said so.
const rebuildCycleSource = "communication"

// WithRebuildTriggers wires where a closed rebuild cycle is recorded (D21).
func (c *Coordinator) WithRebuildTriggers(r RebuildTriggerRecorder) *Coordinator {
	c.rebuildTriggers = r
	return c
}

// OnRebuildCycleClosed ends the hold of the approved recommendations the cycle carried, and
// records the closure as a trigger when something waited for it: a decision that joined the
// cycle (D21), or a trigger an approved recommendation kept back (D44 item 7). A closure nobody
// waited for records no trigger; a set that cannot be fixed would otherwise be asked for again
// without end. A Coordinator with no recorder, or an event that names no Release or carries no
// id, records nothing and is not an error: there is nothing to retry.
func (c *Coordinator) OnRebuildCycleClosed(ctx context.Context, in InboundRebuildCycleClosed) error {
	if c.rebuildTriggers == nil || strings.TrimSpace(in.ReleaseID) == "" || strings.TrimSpace(in.EventID) == "" {
		return nil
	}
	ids := make([]string, 0, len(in.Joined)+1)
	for _, id := range append([]string{in.DecisionID}, in.Joined...) {
		if strings.TrimSpace(id) != "" {
			ids = append(ids, id)
		}
	}
	retrigger, err := c.rebuildTriggers.MarkRebuildCyclesClosed(ctx, ids)
	if err != nil {
		return err
	}
	if len(in.Joined) == 0 && !retrigger {
		return nil
	}
	return c.rebuildTriggers.RecordRebuildTrigger(ctx, in.EventID, rebuildCycleSource, domain.RebuildTriggerCycleClosed, in.ReleaseID)
}

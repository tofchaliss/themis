package app

import (
	"context"
	"errors"
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
}

// RebuildTriggerWorker judges open triggers.
type RebuildTriggerWorker struct {
	store RebuildTriggerStore
	eval  *RebuildEvaluationService
	ids   IDGenerator
	clock Clock
	log   EvaluationLog
	// waiting holds the open triggers whose failure was already reported, so that a Release
	// that cannot be judged is said once and not on every pass. Process-local: a restart says
	// it once more.
	waiting map[int64]struct{}
}

// NewRebuildTriggerWorker wires the worker. log may be nil.
func NewRebuildTriggerWorker(store RebuildTriggerStore, eval *RebuildEvaluationService, ids IDGenerator, clock Clock, log EvaluationLog) *RebuildTriggerWorker {
	return &RebuildTriggerWorker{store: store, eval: eval, ids: ids, clock: clock, log: log, waiting: map[int64]struct{}{}}
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
	res := RebuildTriggerResult{
		Outcome: ev.Outcome, EffectiveMode: string(ev.Policy.EffectiveMode), ModeSetBy: ev.Policy.EffectiveSetBy,
		Considered: ev.Considered, Targeted: len(ev.Targeted), SettledAt: now,
	}
	if ev.Outcome == domain.RebuildOutcomeNone {
		res.Reason = domain.RebuildNoneReason(ev.Policy.EffectiveMode)
		return w.store.SettleRebuildTrigger(ctx, trig, res, nil, OutboxNote{})
	}
	decision := newRebuildDecision(w.ids.NewID(), trig, ev, now)
	eventType := EventRebuildRecommended
	if ev.Outcome == domain.RebuildOutcomeRequest {
		eventType = EventRebuildRequested
	}
	return w.store.SettleRebuildTrigger(ctx, trig, res, &decision,
		OutboxNote{EventType: eventType, Event: decision, OccurredAt: now})
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

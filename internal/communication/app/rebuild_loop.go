package app

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// The rebuild loop (EDR-DELIVERY-01 M2-8 / N-M2i), Communication's: a new SBOM's evaluation
// that leaves Critical or High Findings OPENS a cycle and asks for a rebuild; every later
// new_sbom evaluation of the same Release is COMPARED against the set captured at cycle start
// (M2-5, domain.TargetedSet); the loop continues, succeeds, or is exhausted — and after a stop
// no further rebuild is asked for in that cycle. Nothing here touches a Finding: Findings are
// never auto-resolved (RC-6, D-N-7); a failed attempt is an OUTCOME, recorded, and the Release
// stays affected.

// Cycle states.
const (
	CycleOpen      = "open"
	CycleSucceeded = "succeeded"
	CycleExhausted = "exhausted"
)

// Outcome states a single evaluation can have for the loop. They are what the ticket and the
// mail say in their "Rebuild loop" section, so a person reads the loop's decision where the
// posture is.
const (
	OutcomeClean      = "clean"      // no Critical/High: no cycle
	OutcomeOpened     = "opened"     // cycle opened, first rebuild asked for
	OutcomeContinuing = "continuing" // compared; still open; another rebuild asked for
	OutcomeSucceeded  = "succeeded"  // compared; every targeted CVE closed; stop
	OutcomeExhausted  = "exhausted"  // compared; still open; attempt limit reached; stop, tell a person
)

// Snapshot keys the outcome is recorded under on the ticket and mail intents.
const (
	SnapshotRebuildState       = "rebuild_state"
	SnapshotRebuildAttempt     = "rebuild_attempt"
	SnapshotRebuildMaxAttempts = "rebuild_max_attempts"
	SnapshotRebuildTargeted    = "rebuild_targeted"
	SnapshotRebuildClosed      = "rebuild_closed"
	SnapshotRebuildOpen        = "rebuild_open"
	SnapshotRebuildBaseline    = "rebuild_baseline_sbom"
)

// Snapshot keys of the upload outcome (EDR-REMEDIATION-01 D3), copied from the evaluation
// event onto the ticket and mail intents. Counts are decimal strings; the CVE lists are
// comma-separated, already sorted and capped by Governance. Absent keys mean the event carried
// no outcome, which the renderer states by writing no section at all.
const (
	SnapshotOutcomeNew             = "outcome_new"
	SnapshotOutcomeReappeared      = "outcome_reappeared"
	SnapshotOutcomeNoLongerPresent = "outcome_no_longer_present"
	SnapshotOutcomeUnchanged       = "outcome_unchanged"
	SnapshotOutcomeNotJudged       = "outcome_not_judged"
	SnapshotOutcomeNewCVEs         = "outcome_new_cves"
	SnapshotOutcomeReappearedCVEs  = "outcome_reappeared_cves"
	SnapshotOutcomeGoneCVEs        = "outcome_no_longer_present_cves"
	SnapshotOutcomeHasBaseline     = "outcome_has_baseline"
)

// ErrLoopUnavailable — the loop has no posture reader; it cannot decide and says so.
var ErrLoopUnavailable = errors.New("rebuild loop: no posture reader wired")

// RebuildCycle is one loop cycle for one Release.
type RebuildCycle struct {
	ID             int64
	ReleaseID      string
	OriginEventID  string
	BaselineSBOMID string
	LastSBOMID     string
	Targeted       []string
	Attempts       int
	State          string
	OpenedAt       time.Time
	UpdatedAt      time.Time
}

// RebuildCycles is the store port for cycle state.
type RebuildCycles interface {
	// OpenCycle returns the Release's open cycle, found=false when there is none.
	OpenCycle(ctx context.Context, releaseID string) (RebuildCycle, bool, error)
	// CreateCycle persists a new open cycle and returns it with its id.
	CreateCycle(ctx context.Context, c RebuildCycle) (RebuildCycle, error)
	// UpdateCycle persists the cycle's mutable state (last SBOM, attempts, state, updated at).
	UpdateCycle(ctx context.Context, c RebuildCycle) error
}

// RebuildOutcome is what one evaluation meant for the loop.
type RebuildOutcome struct {
	State       string
	Attempt     int // the attempt this evaluation is the result of, or asks for (NextAttempt)
	NextAttempt int // > 0 when a rebuild is to be asked for
	Targeted    []string
	Closed      []string
	Open        []string
	// BaselineSBO is the SBOM this evaluation was COMPARED AGAINST — the cycle's previous SBOM
	// (the opening evaluation has none to compare with, so it names its own). What the ticket
	// and the mail print as "Compared against".
	BaselineSBO string
	// PriorSBO is the SBOM the NEXT rebuild starts from — the one just evaluated — handed to
	// the build job as THEMIS_PRIOR_SBOM_ID.
	PriorSBO string
	cycle    RebuildCycle
}

// Snapshot renders the outcome as intent snapshot facts; a clean outcome records nothing.
func (o RebuildOutcome) Snapshot(maxAttempts int) map[string]string {
	if o.State == "" || o.State == OutcomeClean {
		return nil
	}
	attempt := o.Attempt
	if o.NextAttempt > 0 {
		attempt = o.NextAttempt
	}
	return map[string]string{
		SnapshotRebuildState:       o.State,
		SnapshotRebuildAttempt:     strconv.Itoa(attempt),
		SnapshotRebuildMaxAttempts: strconv.Itoa(maxAttempts),
		SnapshotRebuildTargeted:    strings.Join(o.Targeted, ","),
		SnapshotRebuildClosed:      strings.Join(o.Closed, ","),
		SnapshotRebuildOpen:        strings.Join(o.Open, ","),
		SnapshotRebuildBaseline:    o.BaselineSBO,
	}
}

// RebuildLoop drives cycles. It reads the posture through the same seam the ticket renderer
// uses, keeps cycle state through RebuildCycles, and asks for rebuilds through the intent
// service — all inside whatever unit of work the caller holds (the inbox transaction, on the
// reader path), so an evaluation's loop decision and its intents commit together.
type RebuildLoop struct {
	cycles      RebuildCycles
	posture     ReleaseSeverityReader
	intents     *DeliveryIntentService
	clock       Clock
	maxAttempts int
}

// NewRebuildLoop wires the loop. maxAttempts below 1 takes M2-8's default of 2.
func NewRebuildLoop(cycles RebuildCycles, posture ReleaseSeverityReader, intents *DeliveryIntentService, clock Clock, maxAttempts int) *RebuildLoop {
	if maxAttempts < 1 {
		maxAttempts = 2
	}
	return &RebuildLoop{cycles: cycles, posture: posture, intents: intents, clock: clock, maxAttempts: maxAttempts}
}

// MaxAttempts is the configured attempt limit.
func (l *RebuildLoop) MaxAttempts() int { return l.maxAttempts }

// Evaluate records what a new_sbom evaluation means for the Release's cycle and returns the
// outcome. It persists the cycle (opened, advanced, or stopped) but asks for NO rebuild — Raise
// does that, after the caller has recorded the ticket and the mail, so the outcome's text is
// on them before the build system hears anything.
func (l *RebuildLoop) Evaluate(ctx context.Context, releaseID, sbomID, originEventID string) (RebuildOutcome, error) {
	if l.posture == nil {
		return RebuildOutcome{}, ErrLoopUnavailable
	}
	rows, err := l.posture.ReleaseSeverity(ctx, releaseID)
	if err != nil {
		return RebuildOutcome{}, err
	}
	current := make([]domain.PostureRow, 0, len(rows))
	for _, r := range rows {
		current = append(current, domain.PostureRow{CVE: r.CVE, BaseScore: r.BaseScore})
	}
	now := l.clock.Now()

	cycle, found, err := l.cycles.OpenCycle(ctx, releaseID)
	if err != nil {
		return RebuildOutcome{}, err
	}
	if !found {
		set := domain.NewTargetedSet(current)
		if set.Len() == 0 {
			return RebuildOutcome{State: OutcomeClean}, nil
		}
		cycle = RebuildCycle{
			ReleaseID: releaseID, OriginEventID: originEventID, BaselineSBOMID: sbomID, LastSBOMID: sbomID,
			Targeted: set.CVEs(), Attempts: 1, State: CycleOpen, OpenedAt: now, UpdatedAt: now,
		}
		stored, err := l.cycles.CreateCycle(ctx, cycle)
		if err != nil {
			return RebuildOutcome{}, err
		}
		return RebuildOutcome{State: OutcomeOpened, NextAttempt: 1, Targeted: set.CVEs(), Open: set.CVEs(), Closed: []string{},
			BaselineSBO: sbomID, PriorSBO: sbomID, cycle: stored}, nil
	}

	set := domain.TargetedSetOf(cycle.Targeted)
	closure := set.Closure(current)
	out := RebuildOutcome{Attempt: cycle.Attempts, Targeted: set.CVEs(), Closed: closure.Closed, Open: closure.Open,
		BaselineSBO: cycle.LastSBOMID, PriorSBO: sbomID}
	cycle.LastSBOMID, cycle.UpdatedAt = sbomID, now
	switch {
	case closure.Complete:
		cycle.State, out.State = CycleSucceeded, OutcomeSucceeded
	case cycle.Attempts >= l.maxAttempts:
		cycle.State, out.State = CycleExhausted, OutcomeExhausted
	default:
		cycle.Attempts++
		out.State, out.NextAttempt = OutcomeContinuing, cycle.Attempts
	}
	if err := l.cycles.UpdateCycle(ctx, cycle); err != nil {
		return RebuildOutcome{}, err
	}
	out.cycle = cycle
	return out, nil
}

// Raise asks the build system for the rebuild an outcome calls for — exactly when NextAttempt
// is set, so a succeeded, exhausted or clean outcome raises nothing (the stop IS the decision).
// The intent carries the still-open targeted CVEs and the SBOM the result will be compared
// against; it is deduplicated per (event, type) like the ticket and the mail.
func (l *RebuildLoop) Raise(ctx context.Context, lineage IntentLineage, originEventID string, out RebuildOutcome, productID, projectID string) (Intent, bool, error) {
	if out.NextAttempt <= 0 {
		return Intent{}, false, nil
	}
	in, err := l.intents.EnqueueCIRebuild(ctx, lineage, originEventID, out.cycle.ReleaseID, productID, projectID,
		out.PriorSBO, out.Open, out.NextAttempt, map[string]string{
			SnapshotRebuildState: out.State, SnapshotRebuildAttempt: strconv.Itoa(out.NextAttempt),
			SnapshotRebuildMaxAttempts: strconv.Itoa(l.maxAttempts),
		})
	if err != nil {
		return Intent{}, false, err
	}
	return in, true, nil
}

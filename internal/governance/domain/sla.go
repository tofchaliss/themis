package domain

import (
	"strings"
	"time"
)

// The SLA clock (EDR-REMEDIATION-01 D1, answers Q1/Q2/Q5, safeguards S1/S2). A pure function of a
// Finding's history and a policy: it derives a due date and a state and changes nothing. A breach
// is a READ — it may be shown, reported and notified, and it never touches a Position, a stage or
// a proposal (S1). Every input is already recorded (creation time, Position history with review-by
// dates, the stale mark, the stage, CISA's KEV due date), so the clock is reconstructible at any
// moment and the elapsed history is never lost by a restart (S2).

// SLA severity buckets. The names are the ticket ladder's (M1b-5), lower-cased.
const (
	SLABucketCritical = "critical"
	SLABucketHigh     = "high"
	SLABucketMedium   = "medium"
	SLABucketLow      = "low"
)

// SLABucketOf maps a base score to its bucket by the M1b-5 floors; 0 (no severity evidence) has no
// bucket, and an absent bucket is never read as Low.
func SLABucketOf(baseScore int) string {
	switch {
	case baseScore >= SeverityCriticalFloor:
		return SLABucketCritical
	case baseScore >= SeverityHighFloor:
		return SLABucketHigh
	case baseScore >= SeverityMediumFloor:
		return SLABucketMedium
	case baseScore > 0:
		return SLABucketLow
	default:
		return ""
	}
}

// SLATarget is one bucket's policy: days to fix, and whether the bucket is enforced at all.
type SLATarget struct {
	Days    int
	Enforce bool
}

// SLAPolicy is days-to-fix per bucket (Q5). One estate-wide policy, optional per-Product overrides
// (the caller picks which applies).
type SLAPolicy struct {
	Critical, High, Medium, Low SLATarget
}

// DefaultSLAPolicy is Q5's starting table: 7 / 30 / 90 / 180 days, all enforced.
func DefaultSLAPolicy() SLAPolicy {
	return SLAPolicy{
		Critical: SLATarget{Days: 7, Enforce: true},
		High:     SLATarget{Days: 30, Enforce: true},
		Medium:   SLATarget{Days: 90, Enforce: true},
		Low:      SLATarget{Days: 180, Enforce: true},
	}
}

// Target returns the bucket's target; an unknown bucket has none.
func (p SLAPolicy) Target(bucket string) (SLATarget, bool) {
	switch bucket {
	case SLABucketCritical:
		return p.Critical, true
	case SLABucketHigh:
		return p.High, true
	case SLABucketMedium:
		return p.Medium, true
	case SLABucketLow:
		return p.Low, true
	default:
		return SLATarget{}, false
	}
}

// Valid reports whether every enforced bucket has a positive number of days.
func (p SLAPolicy) Valid() bool {
	for _, t := range []SLATarget{p.Critical, p.High, p.Medium, p.Low} {
		if t.Days < 0 || (t.Enforce && t.Days == 0) {
			return false
		}
	}
	return true
}

// SLADueSoonWindow is how close a due date must be for the state to read `due_soon`.
const SLADueSoonWindow = 7 * 24 * time.Hour

// SLAState is the clock's reading.
type SLAState string

const (
	// SLAWithin: running, the due date is more than SLADueSoonWindow away.
	SLAWithin SLAState = "within"
	// SLADueSoon: running, the due date is within SLADueSoonWindow.
	SLADueSoon SLAState = "due_soon"
	// SLABreached: running, the due date has passed. A reading, never a transition (S1).
	SLABreached SLAState = "breached"
	// SLAPaused: a valid accepted_risk or deferred Position holds (Q2).
	SLAPaused SLAState = "paused"
	// SLAMet / SLAMissed: the clock stopped on a decision that took the Finding out of the queue,
	// on or before / after the due date.
	SLAMet    SLAState = "met"
	SLAMissed SLAState = "missed"
	// SLANotApplicable: no severity bucket and no KEV due date, or the bucket is not enforced.
	SLANotApplicable SLAState = "not_applicable"
)

// SLAPositionFact is the part of one Position version the clock reads.
type SLAPositionFact struct {
	Stance        Stance
	EstablishedAt time.Time
	ReviewBy      time.Time
}

// SLAInput is everything the clock reads about one Finding.
type SLAInput struct {
	CreatedAt time.Time
	// Bucket is the severity bucket FROZEN when the Finding first had one (Q1); CurrentBucket is
	// today's. They may differ, and the difference is shown, never applied.
	Bucket, CurrentBucket string
	Stage                 Stage
	// Positions in version order.
	Positions []SLAPositionFact
	// StaleSince is the current suppressing Position's re-surfacing mark (RF-2); zero when none.
	StaleSince time.Time
	// KEVDue is CISA's due date (D5); the earlier deadline wins.
	KEVDue time.Time
	// StageStoppedAt is when the Finding reached resolved/archived, when known. A stage stop with
	// no recorded time cannot be graded met or missed, so it reads not_applicable.
	StageStoppedAt time.Time
}

// SLAStatus is the clock's answer.
type SLAStatus struct {
	State         SLAState
	Bucket        string
	CurrentBucket string
	BucketChanged bool
	// PeriodStart is when the current SLA period began: creation, or the moment the Finding last
	// returned to the queue from an acceptance (Q2).
	PeriodStart time.Time
	// Due is the deadline of the current period; zero when paused or not applicable.
	Due time.Time
	// KEVDueApplied: CISA's date was earlier than the policy's and is the deadline.
	KEVDueApplied bool
	// DaysLeft is whole days to Due (negative when breached); 0 when there is no Due.
	DaysLeft int
	// StoppedAt is when the clock stopped (met / missed).
	StoppedAt time.Time
	// AcceptancePeriods are every interval spent under acceptance, oldest first (S2).
	AcceptancePeriods []SLAPeriod
	// TotalAge and UnderAcceptance are S2: the Finding's whole age from creation and the summed
	// time spent under a valid acceptance, so a long-running risk is never understated by a
	// restart.
	TotalAge, UnderAcceptance time.Duration
}

// SLAPeriod is one interval spent under a valid acceptance (S2): kept, never folded away.
type SLAPeriod struct {
	Start, End      time.Time // End is zero while the acceptance still holds
	PositionVersion int
}

func pausesSLA(s Stance) bool { return s == StanceAcceptedRisk || s == StanceDeferred }
func stopsSLA(s Stance) bool  { return s == StanceNotAffected || s == StanceMitigated }
func stageStops(s Stage) bool { return s == StageResolved || s == StageArchived }

// EvaluateSLA reads the clock at `now`.
func EvaluateSLA(in SLAInput, policy SLAPolicy, now time.Time) SLAStatus {
	now = now.UTC()
	out := SLAStatus{
		Bucket: strings.TrimSpace(in.Bucket), CurrentBucket: strings.TrimSpace(in.CurrentBucket),
		PeriodStart: in.CreatedAt.UTC(),
	}
	if out.Bucket == "" {
		out.Bucket = out.CurrentBucket // never frozen yet: today's is the first
	}
	out.BucketChanged = out.CurrentBucket != "" && out.Bucket != out.CurrentBucket
	if !in.CreatedAt.IsZero() && now.After(in.CreatedAt) {
		out.TotalAge = now.Sub(in.CreatedAt)
	}

	// Walk the Position history: acceptance intervals (S2) and the start of the current period
	// (Q2: a new period starts when an acceptance ends and the Finding returns to the queue).
	var (
		pausedNow bool
		stoppedAt time.Time
	)
	for i, p := range in.Positions {
		var next time.Time
		if i+1 < len(in.Positions) {
			next = in.Positions[i+1].EstablishedAt
		}
		isLast := i == len(in.Positions)-1
		switch {
		case pausesSLA(p.Stance):
			end := next
			if !p.ReviewBy.IsZero() && (end.IsZero() || p.ReviewBy.Before(end)) {
				end = p.ReviewBy // the acceptance expired on its own date
			}
			if isLast && !in.StaleSince.IsZero() && (end.IsZero() || in.StaleSince.Before(end)) {
				end = in.StaleSince // re-surfaced by drift
			}
			if end.IsZero() || end.After(now) {
				out.UnderAcceptance += now.Sub(p.EstablishedAt)
				out.AcceptancePeriods = append(out.AcceptancePeriods, SLAPeriod{Start: p.EstablishedAt.UTC(), PositionVersion: i + 1})
				pausedNow = isLast
				continue
			}
			out.UnderAcceptance += end.Sub(p.EstablishedAt)
			out.AcceptancePeriods = append(out.AcceptancePeriods, SLAPeriod{Start: p.EstablishedAt.UTC(), End: end.UTC(), PositionVersion: i + 1})
			// The acceptance ended. If what follows is the queue — expiry, a stale mark, or a later
			// Position that neither stops nor pauses the clock — a new period starts there.
			if next.IsZero() || (!stopsSLA(in.Positions[i+1].Stance) && !pausesSLA(in.Positions[i+1].Stance)) {
				out.PeriodStart = end.UTC()
			}
		case stopsSLA(p.Stance):
			if isLast {
				stoppedAt = p.EstablishedAt
			}
		}
	}

	target, known := policy.Target(out.Bucket)
	enforced := known && target.Enforce && target.Days > 0
	if !enforced && in.KEVDue.IsZero() {
		out.State = SLANotApplicable
		return out
	}
	var due time.Time
	if enforced {
		due = out.PeriodStart.Add(time.Duration(target.Days) * 24 * time.Hour)
	}
	if !in.KEVDue.IsZero() && (due.IsZero() || in.KEVDue.Before(due)) {
		due, out.KEVDueApplied = in.KEVDue.UTC(), true
	}

	switch {
	case !stoppedAt.IsZero():
		out.StoppedAt, out.Due = stoppedAt.UTC(), due
		if stoppedAt.After(due) {
			out.State = SLAMissed
		} else {
			out.State = SLAMet
		}
		return out
	case stageStops(in.Stage):
		out.Due = due
		if in.StageStoppedAt.IsZero() {
			out.State = SLANotApplicable
			return out
		}
		out.StoppedAt = in.StageStoppedAt.UTC()
		if out.StoppedAt.After(due) {
			out.State = SLAMissed
		} else {
			out.State = SLAMet
		}
		return out
	case pausedNow:
		out.State, out.Due, out.KEVDueApplied = SLAPaused, time.Time{}, false
		return out
	}
	out.Due = due
	out.DaysLeft = daysBetween(now, due)
	switch {
	case now.After(due):
		out.State = SLABreached
	case due.Sub(now) <= SLADueSoonWindow:
		out.State = SLADueSoon
	default:
		out.State = SLAWithin
	}
	return out
}

// daysBetween is whole days from a to b, rounding toward the deadline's side: positive when b is
// ahead, negative when it has passed.
func daysBetween(a, b time.Time) int {
	d := b.Sub(a)
	if d >= 0 {
		return int(d / (24 * time.Hour))
	}
	return -int((-d + 24*time.Hour - 1) / (24 * time.Hour))
}

// SLABreachedEvent is the fact that one Finding's current SLA period ran past its due date
// (governance.sla_breached.v1). It is emitted once per period and changes nothing (S1): no
// Position, no stage, no proposal — Communication may deliver it, a report may count it.
type SLABreachedEvent struct {
	FindingID     FindingID
	ReleaseID     string
	FaultlineID   string
	CVE           string
	Bucket        string
	PeriodStart   time.Time
	Due           time.Time
	KEVDueApplied bool
	OccurredAt    time.Time
}

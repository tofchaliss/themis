package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

var slaT0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func day(n int) time.Time { return slaT0.Add(time.Duration(n) * 24 * time.Hour) }

func TestSLABucketOf(t *testing.T) {
	for score, want := range map[int]string{
		100: domain.SLABucketCritical, 90: domain.SLABucketCritical, 89: domain.SLABucketHigh,
		70: domain.SLABucketHigh, 69: domain.SLABucketMedium, 40: domain.SLABucketMedium,
		39: domain.SLABucketLow, 1: domain.SLABucketLow, 0: "",
	} {
		if got := domain.SLABucketOf(score); got != want {
			t.Errorf("SLABucketOf(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestSLAPolicyDefaultsTargetsAndValidity(t *testing.T) {
	p := domain.DefaultSLAPolicy()
	if !p.Valid() {
		t.Fatal("default policy invalid")
	}
	for b, days := range map[string]int{"critical": 7, "high": 30, "medium": 90, "low": 180} {
		tg, ok := p.Target(b)
		if !ok || tg.Days != days || !tg.Enforce {
			t.Errorf("Target(%s) = %+v %v", b, tg, ok)
		}
	}
	if _, ok := p.Target(""); ok {
		t.Error("an empty bucket has a target")
	}
	bad := p
	bad.High.Days = 0
	if bad.Valid() {
		t.Error("enforced 0 days is valid")
	}
	bad = p
	bad.Low = domain.SLATarget{Days: -1}
	if bad.Valid() {
		t.Error("negative days is valid")
	}
	off := p
	off.Low = domain.SLATarget{Days: 0, Enforce: false}
	if !off.Valid() {
		t.Error("an unenforced bucket with 0 days is invalid")
	}
}

func TestSLARunningStates(t *testing.T) {
	in := domain.SLAInput{CreatedAt: slaT0, CurrentBucket: domain.SLABucketHigh}
	p := domain.DefaultSLAPolicy()

	s := domain.EvaluateSLA(in, p, day(10))
	if s.State != domain.SLAWithin || !s.Due.Equal(day(30)) || s.DaysLeft != 20 || s.Bucket != "high" {
		t.Fatalf("within: %+v", s)
	}
	if s.TotalAge != 10*24*time.Hour || s.BucketChanged {
		t.Fatalf("age/bucket: %+v", s)
	}
	if s = domain.EvaluateSLA(in, p, day(25)); s.State != domain.SLADueSoon || s.DaysLeft != 5 {
		t.Fatalf("due soon: %+v", s)
	}
	s = domain.EvaluateSLA(in, p, day(31).Add(time.Hour))
	if s.State != domain.SLABreached || s.DaysLeft != -2 {
		t.Fatalf("breached: %+v", s)
	}
}

// Q1: the deadline follows the FROZEN bucket; a later severity is shown, never applied.
func TestSLAFrozenBucketQ1(t *testing.T) {
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketLow, CurrentBucket: domain.SLABucketCritical}
	s := domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(10))
	if s.Bucket != "low" || s.CurrentBucket != "critical" || !s.BucketChanged || !s.Due.Equal(day(180)) {
		t.Fatalf("frozen bucket: %+v", s)
	}
}

func TestSLAKEVDueEarlierWins(t *testing.T) {
	p := domain.DefaultSLAPolicy()
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketHigh, KEVDue: day(14)}
	if s := domain.EvaluateSLA(in, p, day(1)); !s.KEVDueApplied || !s.Due.Equal(day(14)) {
		t.Fatalf("earlier KEV: %+v", s)
	}
	in.KEVDue = day(60)
	if s := domain.EvaluateSLA(in, p, day(1)); s.KEVDueApplied || !s.Due.Equal(day(30)) {
		t.Fatalf("later KEV: %+v", s)
	}
	// No bucket at all, but CISA set a date: the date is the deadline.
	in = domain.SLAInput{CreatedAt: slaT0, KEVDue: day(21)}
	if s := domain.EvaluateSLA(in, p, day(1)); s.State != domain.SLAWithin || !s.KEVDueApplied {
		t.Fatalf("KEV only: %+v", s)
	}
}

func TestSLANotApplicable(t *testing.T) {
	p := domain.DefaultSLAPolicy()
	if s := domain.EvaluateSLA(domain.SLAInput{CreatedAt: slaT0}, p, day(1)); s.State != domain.SLANotApplicable {
		t.Fatalf("no bucket: %+v", s)
	}
	p.Medium.Enforce = false
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketMedium}
	if s := domain.EvaluateSLA(in, p, day(1)); s.State != domain.SLANotApplicable {
		t.Fatalf("unenforced: %+v", s)
	}
}

func TestSLAStopsOnDecision(t *testing.T) {
	p := domain.DefaultSLAPolicy()
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketCritical,
		Positions: []domain.SLAPositionFact{{Stance: domain.StanceMitigated, EstablishedAt: day(5)}}}
	if s := domain.EvaluateSLA(in, p, day(40)); s.State != domain.SLAMet || !s.StoppedAt.Equal(day(5)) {
		t.Fatalf("met: %+v", s)
	}
	in.Positions[0] = domain.SLAPositionFact{Stance: domain.StanceNotAffected, EstablishedAt: day(9)}
	if s := domain.EvaluateSLA(in, p, day(40)); s.State != domain.SLAMissed {
		t.Fatalf("missed: %+v", s)
	}
	// A stopping Position superseded by an affected one: the clock runs again from creation.
	in.Positions = append(in.Positions, domain.SLAPositionFact{Stance: domain.StanceAffected, EstablishedAt: day(10)})
	if s := domain.EvaluateSLA(in, p, day(40)); s.State != domain.SLABreached || !s.PeriodStart.Equal(slaT0) {
		t.Fatalf("reopened: %+v", s)
	}
}

func TestSLAStopsOnStage(t *testing.T) {
	p := domain.DefaultSLAPolicy()
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketCritical, Stage: domain.StageResolved, StageStoppedAt: day(3)}
	if s := domain.EvaluateSLA(in, p, day(40)); s.State != domain.SLAMet || !s.StoppedAt.Equal(day(3)) {
		t.Fatalf("resolved in time: %+v", s)
	}
	in.Stage, in.StageStoppedAt = domain.StageArchived, day(8)
	if s := domain.EvaluateSLA(in, p, day(40)); s.State != domain.SLAMissed {
		t.Fatalf("archived late: %+v", s)
	}
	in.StageStoppedAt = time.Time{}
	if s := domain.EvaluateSLA(in, p, day(40)); s.State != domain.SLANotApplicable || !s.Due.Equal(day(7)) {
		t.Fatalf("stage stop, time unknown: %+v", s)
	}
}

// Q2: the clock pauses under a valid acceptance.
func TestSLAPausesUnderAcceptanceQ2(t *testing.T) {
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketHigh,
		Positions: []domain.SLAPositionFact{{Stance: domain.StanceAcceptedRisk, EstablishedAt: day(20), ReviewBy: day(100)}}}
	s := domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(50))
	if s.State != domain.SLAPaused || !s.Due.IsZero() || s.DaysLeft != 0 {
		t.Fatalf("paused: %+v", s)
	}
	if s.UnderAcceptance != 30*24*time.Hour || len(s.AcceptancePeriods) != 1 || !s.AcceptancePeriods[0].End.IsZero() {
		t.Fatalf("open period: %+v", s)
	}
	// Deferred with no review date pauses the same way.
	in.Positions[0] = domain.SLAPositionFact{Stance: domain.StanceDeferred, EstablishedAt: day(20)}
	if s = domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(50)); s.State != domain.SLAPaused {
		t.Fatalf("deferred: %+v", s)
	}
}

// Q2: expiry on the review date restarts the period from zero at that moment.
func TestSLARestartsOnExpiryQ2(t *testing.T) {
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketHigh,
		Positions: []domain.SLAPositionFact{{Stance: domain.StanceAcceptedRisk, EstablishedAt: day(20), ReviewBy: day(40)}}}
	s := domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(45))
	if s.State != domain.SLAWithin || !s.PeriodStart.Equal(day(40)) || !s.Due.Equal(day(70)) {
		t.Fatalf("restart on expiry: %+v", s)
	}
}

// Q2: a re-surfacing (disposition_stale) restarts the period at the stale mark.
func TestSLARestartsOnStaleQ2(t *testing.T) {
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketCritical, StaleSince: day(30),
		Positions: []domain.SLAPositionFact{{Stance: domain.StanceAcceptedRisk, EstablishedAt: day(10), ReviewBy: day(200)}}}
	s := domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(32))
	if s.State != domain.SLADueSoon || !s.PeriodStart.Equal(day(30)) || !s.Due.Equal(day(37)) {
		t.Fatalf("restart on stale: %+v", s)
	}
}

// An acceptance replaced by an affected Position: a new period starts at the replacement.
// One replaced by another acceptance, or by a stopping decision, does not start a period.
func TestSLAAcceptanceSucceededBy(t *testing.T) {
	p := domain.DefaultSLAPolicy()
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketHigh, Positions: []domain.SLAPositionFact{
		{Stance: domain.StanceAcceptedRisk, EstablishedAt: day(5)},
		{Stance: domain.StanceAffected, EstablishedAt: day(15)},
	}}
	if s := domain.EvaluateSLA(in, p, day(20)); !s.PeriodStart.Equal(day(15)) {
		t.Fatalf("affected after acceptance: %+v", s)
	}
	in.Positions[1] = domain.SLAPositionFact{Stance: domain.StanceDeferred, EstablishedAt: day(15)}
	s := domain.EvaluateSLA(in, p, day(20))
	if s.State != domain.SLAPaused || len(s.AcceptancePeriods) != 2 || !s.PeriodStart.Equal(slaT0) {
		t.Fatalf("acceptance chain: %+v", s)
	}
	in.Positions[1] = domain.SLAPositionFact{Stance: domain.StanceMitigated, EstablishedAt: day(15)}
	if s = domain.EvaluateSLA(in, p, day(20)); s.State != domain.SLAMet || !s.PeriodStart.Equal(slaT0) {
		t.Fatalf("mitigated after acceptance: %+v", s)
	}
}

// S2 — restarting the SLA never erases elapsed time: after two acceptances and two restarts, the
// Finding's whole age, every acceptance period (with its Position version) and their sum are all
// still reported beside the current period.
func TestSLARestartNeverErasesElapsedTimeS2(t *testing.T) {
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketMedium, Positions: []domain.SLAPositionFact{
		{Stance: domain.StanceAcceptedRisk, EstablishedAt: day(10), ReviewBy: day(40)},
		{Stance: domain.StanceAffected, EstablishedAt: day(50)},
		{Stance: domain.StanceAcceptedRisk, EstablishedAt: day(60), ReviewBy: day(80)},
	}}
	s := domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(100))
	if !s.PeriodStart.Equal(day(80)) || !s.Due.Equal(day(170)) {
		t.Fatalf("current period: %+v", s)
	}
	if s.TotalAge != 100*24*time.Hour {
		t.Fatalf("total age lost: %v", s.TotalAge)
	}
	if s.UnderAcceptance != 50*24*time.Hour {
		t.Fatalf("time under acceptance lost: %v", s.UnderAcceptance)
	}
	want := []domain.SLAPeriod{{Start: day(10), End: day(40), PositionVersion: 1}, {Start: day(60), End: day(80), PositionVersion: 3}}
	if len(s.AcceptancePeriods) != len(want) {
		t.Fatalf("periods: %+v", s.AcceptancePeriods)
	}
	for i, w := range want {
		g := s.AcceptancePeriods[i]
		if !g.Start.Equal(w.Start) || !g.End.Equal(w.End) || g.PositionVersion != w.PositionVersion {
			t.Fatalf("period %d = %+v, want %+v", i, g, w)
		}
	}
}

// S1 — an SLA breach never changes governance state. The clock is a pure read: evaluating a
// breached Finding leaves its inputs (stage, Positions) exactly as they were, and the reading
// itself carries no stance or stage, only a derived state.
func TestSLABreachNeverChangesGovernanceStateS1(t *testing.T) {
	positions := []domain.SLAPositionFact{{Stance: domain.StanceAffected, EstablishedAt: day(1)}}
	in := domain.SLAInput{CreatedAt: slaT0, Bucket: domain.SLABucketCritical, Stage: domain.StagePositionEstablished, Positions: positions}
	s := domain.EvaluateSLA(in, domain.DefaultSLAPolicy(), day(30))
	if s.State != domain.SLABreached {
		t.Fatalf("want breached: %+v", s)
	}
	if in.Stage != domain.StagePositionEstablished || len(in.Positions) != 1 || in.Positions[0].Stance != domain.StanceAffected {
		t.Fatalf("inputs changed: %+v", in)
	}
}

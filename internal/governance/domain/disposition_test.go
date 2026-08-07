package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"

	"github.com/themis-project/themis/internal/governance/domain"
)

// GOV-14b. `residual_priority` zeroes a not_affected / accepted_risk Finding, which is only SAFE
// because D14 pairs it with a watcher that re-surfaces the Finding when the premise drifts. The
// zeroing shipped 2026-08-06; the watcher did not, so an acceptance was permanent in practice —
// the Finding left the queue and nothing brought it back.
func TestDetectDispositionDrift(t *testing.T) {
	for _, tc := range []struct {
		name        string
		decidedWith domain.ExploitSignals
		now         domain.ExploitSignals
		want        bool
		wantIn      string
	}{
		{
			name:        "a CVE entering KEV invalidates the premise",
			decidedWith: domain.ExploitSignals{EPSS: 0.01},
			now:         domain.ExploitSignals{EPSS: 0.01, KEV: true},
			want:        true, wantIn: "Known Exploited",
		},
		{
			name:        "a newly public exploit invalidates the premise",
			decidedWith: domain.ExploitSignals{},
			now:         domain.ExploitSignals{ExploitPublic: true},
			want:        true, wantIn: "public exploit",
		},
		{
			name:        "EPSS rising past the threshold invalidates the premise",
			decidedWith: domain.ExploitSignals{EPSS: 0.03},
			now:         domain.ExploitSignals{EPSS: 0.71},
			want:        true, wantIn: "3% → 71%",
		},
		{
			// The signal was already true when the decision was taken, so the decision was made
			// KNOWING it. Re-surfacing here would fire on every subsequent enrichment forever.
			name:        "a signal that was already true is not drift",
			decidedWith: domain.ExploitSignals{KEV: true, ExploitPublic: true, EPSS: 0.9},
			now:         domain.ExploitSignals{KEV: true, ExploitPublic: true, EPSS: 0.9},
			want:        false,
		},
		{
			// One-directional by design: a CVE getting SAFER does not re-open a suppression. The
			// decision remains at least as well founded as it was, and re-surfacing on improvement
			// trains people to ignore the signal.
			name:        "signals improving is never drift",
			decidedWith: domain.ExploitSignals{KEV: true, ExploitPublic: true, EPSS: 0.9},
			now:         domain.ExploitSignals{EPSS: 0.1},
			want:        false,
		},
		{
			// Absolute threshold: small wobbles in the noise near zero must not fire, because that
			// is where EPSS is least stable and a re-surfaced Finding least likely to be real.
			name:        "a small EPSS wobble is not drift",
			decidedWith: domain.ExploitSignals{EPSS: 0.03},
			now:         domain.ExploitSignals{EPSS: 0.09},
			want:        false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := domain.DetectDispositionDrift(tc.decidedWith, tc.now, domain.DefaultEPSSDriftThreshold)
			if d.Material() != tc.want {
				t.Fatalf("Material() = %v, want %v (%+v)", d.Material(), tc.want, d)
			}
			if tc.wantIn != "" && !strings.Contains(d.Reason(), tc.wantIn) {
				t.Errorf("Reason() = %q, want it to contain %q — a re-surfacing must say WHAT moved", d.Reason(), tc.wantIn)
			}
			if !tc.want && d.Reason() != "" {
				t.Errorf("Reason() = %q on no drift, want empty", d.Reason())
			}
		})
	}
}

// An out-of-range threshold is a config error, not a licence to re-surface everything (or nothing).
func TestDetectDispositionDrift_ThresholdFallback(t *testing.T) {
	for _, bad := range []float64{0, -1, 1.5} {
		d := domain.DetectDispositionDrift(
			domain.ExploitSignals{EPSS: 0.10}, domain.ExploitSignals{EPSS: 0.15}, bad)
		if d.Material() {
			t.Errorf("threshold %v: a 0.05 rise fired; a bad threshold must fall back to the default", bad)
		}
	}
}

// Only the suppressing stances are watched. `mitigated` and `deferred` keep a non-zero weight, so
// a Finding holding one is still visible and needs no re-surfacing to be noticed.
func TestSuppressesTriage(t *testing.T) {
	for _, s := range []domain.Stance{domain.StanceNotAffected, domain.StanceAcceptedRisk} {
		if !domain.SuppressesTriage(s) {
			t.Errorf("%q zeroes residual priority and must be watched", s)
		}
	}
	for _, s := range []domain.Stance{
		domain.StanceAffected, domain.StanceMitigated, domain.StanceDeferred, domain.StanceUnderInvestigation,
	} {
		if domain.SuppressesTriage(s) {
			t.Errorf("%q keeps a non-zero weight and is still visible", s)
		}
	}
}

// The re-surfacing fact carries the Finding's identity and the Position it does NOT change, so a
// consumer can route it without a follow-up read — and so the record shows the decision stood.
func TestNewDispositionStale(t *testing.T) {
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	p, err := domain.NewGovernanceProposal("p1", domain.Actor{Kind: domain.ActorHuman, ID: "a"},
		domain.StanceAcceptedRisk, "accepted", at, value.TrustObserved)
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatalf("raise: %v", err)
	}
	pos, err := f.AcceptProposal("p1", domain.Actor{Kind: domain.ActorHuman, ID: "a"}, at)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	e := domain.NewDispositionStale(f, pos, "a public exploit now exists for this CVE", at)
	if e.FindingID != "fnd-1" || e.ReleaseID != "rel-1" || e.FaultlineID != "fl-1" || e.CVE != "CVE-2024-1" {
		t.Errorf("identity lost: %+v", e)
	}
	if e.Stance != string(domain.StanceAcceptedRisk) || e.PositionVersion != 1 {
		t.Errorf("the event must name the suppressing Position it leaves in force: %+v", e)
	}
	if e.Reason == "" || !e.OccurredAt.Equal(at) {
		t.Errorf("event = %+v", e)
	}
}

// The EPSS wording has to survive the small numbers, because that is exactly where a rise matters
// most: a CVE going from "essentially never" to "likely" is the headline case.
func TestDispositionDrift_ReasonFormatsSmallProbabilities(t *testing.T) {
	for _, tc := range []struct {
		before, after float64
		wantIn        string
	}{
		{0.0, 0.71, "0% → 71%"},
		{0.001, 0.5, "<1% → 50%"}, // rounds to zero but is not zero — saying "0%" would be a lie
		{0.004, 0.9, "<1% → 90%"},
	} {
		d := domain.DetectDispositionDrift(
			domain.ExploitSignals{EPSS: tc.before}, domain.ExploitSignals{EPSS: tc.after},
			domain.DefaultEPSSDriftThreshold)
		if !strings.Contains(d.Reason(), tc.wantIn) {
			t.Errorf("Reason() = %q, want it to contain %q", d.Reason(), tc.wantIn)
		}
	}
}

// The Finding carries the CURRENT exploitability picture so a decision taken later can snapshot
// the premise it rested on. Reconstitution accepts it variadically, so a Finding rebuilt without
// signals reads as "nothing known" — the conservative direction, since any positive signal then
// looks like drift and re-surfaces the Finding.
func TestFindingSignals(t *testing.T) {
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	if (f.Signals() != domain.ExploitSignals{}) {
		t.Errorf("a fresh Finding knows nothing, got %+v", f.Signals())
	}
	sig := domain.ExploitSignals{KEV: true, ExploitPublic: true, EPSS: 0.42}
	f.RefreshSignals(sig)
	if f.Signals() != sig {
		t.Errorf("Signals() = %+v, want %+v", f.Signals(), sig)
	}

	// Reconstituted WITHOUT signals: the legacy shape, and it must not error or guess.
	bare := domain.ReconstituteFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1",
		nil, domain.StageIdentified, nil, nil, 1)
	if (bare.Signals() != domain.ExploitSignals{}) {
		t.Errorf("a Finding rebuilt without signals must know nothing, got %+v", bare.Signals())
	}
	// Reconstituted WITH signals: the current shape.
	withSig := domain.ReconstituteFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1",
		nil, domain.StageIdentified, nil, nil, 1, sig)
	if withSig.Signals() != sig {
		t.Errorf("Signals() = %+v, want %+v", withSig.Signals(), sig)
	}
}

// Accepted-risk expiry. Zero `until` means NO review date was agreed — which is not the same as
// "expires immediately"; inventing a deadline the decider did not set would re-surface every
// suppression on the next enrichment and train people to ignore the signal.
func TestExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name  string
		until time.Time
		want  bool
	}{
		{"a passed date has expired", now.Add(-time.Hour), true},
		{"a future date has not", now.Add(time.Hour), false},
		{"the exact instant has not — After is strict", now, false},
		{"no date never expires", time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.Expired(tc.until, now); got != tc.want {
				t.Errorf("Expired(%v) = %v, want %v", tc.until, got, tc.want)
			}
		})
	}
}

// AcceptProposal takes the review-by date VARIADICALLY so every existing caller is untouched. Both
// shapes must work: a decision with a stated shelf life records it, and one without records none
// rather than a zero that would read as "expired in year 1".
func TestAcceptProposal_ReviewByIsOptional(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	accept := func(t *testing.T, reviewBy ...time.Time) domain.Position {
		t.Helper()
		f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
		if err != nil {
			t.Fatalf("new finding: %v", err)
		}
		p, err := domain.NewGovernanceProposal("p1", domain.Actor{Kind: domain.ActorHuman, ID: "a"},
			domain.StanceAcceptedRisk, "accepted", at, value.TrustObserved)
		if err != nil {
			t.Fatalf("proposal: %v", err)
		}
		if err := f.RaiseProposal(p); err != nil {
			t.Fatalf("raise: %v", err)
		}
		pos, err := f.AcceptProposal("p1", domain.Actor{Kind: domain.ActorHuman, ID: "a"}, at, reviewBy...)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		return pos
	}

	if got := accept(t).Inputs().ReviewBy; !got.IsZero() {
		t.Errorf("ReviewBy = %v, want zero — no date was agreed", got)
	}
	until := at.Add(90 * 24 * time.Hour)
	if got := accept(t, until).Inputs().ReviewBy; !got.Equal(until) {
		t.Errorf("ReviewBy = %v, want %v", got, until)
	}
}

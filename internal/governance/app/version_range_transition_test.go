package app_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// TRUST-9: the version-range verdict (T5) fires on EXACTLY ONE transition, and nothing
// demonstrated it. This is that demonstration.
//
// Two independent gates evaluate the same predicate at different times, and the first STARVES the
// second:
//
//  1. Knowledge's `ApplyCorrelation` skips `RecordMatch` when the component is provably out of
//     range, so no Match — and therefore no Finding — is created at all.
//  2. Governance's `reactToVersionRange` raises its system `not_affected` proposal only when every
//     matched component of an EXISTING Finding is provably out of range.
//
// Because (1) guarantees a Finding's components were NOT provably out of range at match time, (2)
// can only become true one way: the card had **no usable range** when the Finding opened
// (`RangeUndecidable`, which correlation does not skip on), and a usable range arrived later that
// excludes the component. That is the case ProvablyOutOfRange's own doc comment names — "a Finding
// created BEFORE the range was known, which correlation's own gate will never revisit".
func TestVersionRangeVerdict_FiresOnlyOnTheUndecidableToOutOfRangeTransition(t *testing.T) {
	// A Finding that exists because the card carried no usable range at correlation time.
	seed := func(t *testing.T) *fakeRepo {
		t.Helper()
		repo := newRepo()
		f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
		if _, err := f.AbsorbComponent(domain.MatchedComponent{
			PURL: "pkg:pypi/urllib3@1.26.5", Name: "urllib3", Version: "1.26.5", Ecosystem: "pypi",
		}); err != nil {
			t.Fatalf("absorb: %v", err)
		}
		repo.seed(f)
		return repo
	}
	notAffectedRaised := func(repo *fakeRepo) bool {
		for _, f := range repo.byID {
			for _, p := range f.Proposals() {
				if p.Stance() == domain.StanceNotAffected {
					return true
				}
			}
		}
		return false
	}

	t.Run("a usable range that EXCLUDES the component raises not_affected", func(t *testing.T) {
		repo := seed(t)
		// 1.26.5 is outside "<1.0.0" — the range that arrived after the Finding opened.
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
			FaultlineID: "fl-1", AffectedRanges: []string{"<1.0.0"}, RangeTrust: value.TrustObserved,
		}); err != nil {
			t.Fatalf("react: %v", err)
		}
		if !notAffectedRaised(repo) {
			t.Fatal("the transition undecidable → out-of-range must raise a system not_affected proposal")
		}
	})

	t.Run("a usable range that INCLUDES the component raises nothing", func(t *testing.T) {
		repo := seed(t)
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
			FaultlineID: "fl-1", AffectedRanges: []string{"<2.0.0"}, RangeTrust: value.TrustObserved,
		}); err != nil {
			t.Fatalf("react: %v", err)
		}
		if notAffectedRaised(repo) {
			t.Fatal("a component INSIDE the affected range must not be suppressed")
		}
	})

	t.Run("no usable range raises nothing — undecidable is not not_affected", func(t *testing.T) {
		repo := seed(t)
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
			FaultlineID: "fl-1", AffectedRanges: []string{"not a constraint"}, RangeTrust: value.TrustObserved,
		}); err != nil {
			t.Fatalf("react: %v", err)
		}
		if notAffectedRaised(repo) {
			t.Fatal("an undecidable range must never suppress — 'we cannot tell' is not 'not affected'")
		}
	})

	// The interlock the whole rule rests on: a Finding whose components were ALREADY provably out
	// of range would never have been created by correlation, so the second gate would have nothing
	// to fire on. Asserting the range predicate directly is what documents that the two gates share
	// one oracle rather than two implementations that can drift.
	t.Run("both gates share one oracle", func(t *testing.T) {
		comps := []domain.MatchedComponent{{PURL: "pkg:pypi/urllib3@1.26.5", Version: "1.26.5", Ecosystem: "pypi"}}
		if !domain.ProvablyOutOfRange(comps, []string{"<1.0.0"}) {
			t.Error("the Governance predicate disagrees with the correlation-time verdict")
		}
		if domain.ProvablyOutOfRange(comps, []string{"<2.0.0"}) {
			t.Error("a component inside the range must not read as provably out of range")
		}
	})
}

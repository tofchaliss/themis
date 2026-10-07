package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// completion is one announced per-SBOM completion fact.
type completion struct {
	releaseID string
	sbomID    string
	cause     string
	at        time.Time
}

// fakeAnnouncer records the completion announcements and, with the match recorder in hand,
// WHEN they arrived relative to the matches — the app-level half of the ordering rule
// (EDR-DELIVERY-01 M2-1). The store half is the outbox timestamp, proved in the store's
// integration test.
type fakeAnnouncer struct {
	calls                []completion
	err                  error
	matches              *fakeMatches
	matchCallsAtAnnounce int
}

func (f *fakeAnnouncer) AnnounceCorrelationCompleted(_ context.Context, releaseID, sbomID, cause string, at time.Time) error {
	if f.matches != nil {
		f.matchCallsAtAnnounce = f.matches.calls
	}
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, completion{releaseID: releaseID, sbomID: sbomID, cause: cause, at: at})
	return nil
}

// The upload path: one completion per SBOM, carrying `new_sbom`, announced AFTER every match
// the correlation recorded. "After" is the whole contract — a consumer that handles this event
// must already have handled every other fact for the SBOM.
func TestApplyCorrelation_AnnouncesCompletionAfterTheMatches(t *testing.T) {
	ctx := context.Background()
	inv := fakeInventory{inv: inventoryOf("pkg:deb/debian/openssl@3.0", "pkg:deb/debian/zlib@1.3")}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		"pkg:deb/debian/openssl@3.0": {{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "nvd", value.SeverityHigh)}},
		"pkg:deb/debian/zlib@1.3":    {{CVE: cve(t, "CVE-2024-2"), Proposal: vulnFacts(t, "nvd", value.SeverityLow)}},
	}}
	matches := newMatches()
	ann := &fakeAnnouncer{matches: matches}
	s := correlation(t, inv, disc, matches, newRepo()).WithCompletion(ann)

	if _, err := s.Correlate(ctx, "rel-1", "ev-1"); err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(ann.calls) != 1 {
		t.Fatalf("announcements = %d, want exactly 1 per SBOM", len(ann.calls))
	}
	got := ann.calls[0]
	if got.releaseID != "rel-1" || got.sbomID != "ev-1" || got.cause != domain.CauseNewSBOM {
		t.Errorf("announced %+v, want rel-1/ev-1/%s", got, domain.CauseNewSBOM)
	}
	if matches.calls != 2 {
		t.Fatalf("recorded matches = %d, want 2 (the fixture correlates both components)", matches.calls)
	}
	if ann.matchCallsAtAnnounce != matches.calls {
		t.Errorf("completion announced after %d of %d matches — it must be LAST in the unit of work",
			ann.matchCallsAtAnnounce, matches.calls)
	}
}

// Zero matches still announces. Suppressing it would make silence ambiguous: a subscriber
// could not tell "evaluated, clean" from "not evaluated yet" or from "the pipeline is broken".
func TestApplyCorrelation_ZeroMatchesStillAnnounces(t *testing.T) {
	ann := &fakeAnnouncer{}
	s := correlation(t, fakeInventory{inv: inventoryOf("pkg:pypi/quiet@1")}, fakeDiscovery{}, newMatches(), newRepo()).
		WithCompletion(ann)

	if n, err := s.Correlate(context.Background(), "rel-clean", "ev-clean"); err != nil || n != 0 {
		t.Fatalf("Correlate = (%d, %v), want zero matches and no error", n, err)
	}
	if len(ann.calls) != 1 || ann.calls[0].cause != domain.CauseNewSBOM {
		t.Fatalf("announcements = %+v, want one new_sbom completion for an SBOM with nothing to report", ann.calls)
	}
}

// The sweep announces the SAME event with `rediscovery`, because nothing was built: a consumer
// that read it as a new upload would spend a release's rebuild-attempt budget on a feed update.
func TestRediscoverySweep_AnnouncesRediscoveryCause(t *testing.T) {
	inv := fakeInventory{inv: inventoryOf("pkg:rpm/rocky/openssl@3.0.7")}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		"pkg:rpm/rocky/openssl@3.0.7": {{CVE: cve(t, "CVE-2026-9999"), Proposal: vulnFacts(t, "osv", value.SeverityHigh)}},
	}}
	ledger := newLedger(app.CorrelatedRelease{ReleaseID: "rel-old", EvidenceID: "ev-old"})
	ann := &fakeAnnouncer{}
	corr := correlation(t, inv, disc, newMatches(), newRepo()).WithLedger(ledger).WithCompletion(ann)

	if swept, _, err := app.NewRediscoveryService(ledger, corr, fixedClock{}, 0, 0).Sweep(context.Background()); err != nil || swept != 1 {
		t.Fatalf("Sweep = (%d, %v), want the stale release swept", swept, err)
	}
	if len(ann.calls) != 1 {
		t.Fatalf("announcements = %d, want 1", len(ann.calls))
	}
	if got := ann.calls[0]; got.cause != domain.CauseRediscovery || got.sbomID != "ev-old" {
		t.Errorf("announced %+v, want ev-old with cause %s", got, domain.CauseRediscovery)
	}
}

// A plan built before the Cause field existed means an upload — PlanCorrelation stamps every
// plan it builds, so an empty cause can only come from a hand-constructed one.
func TestApplyCorrelation_EmptyCauseMeansUpload(t *testing.T) {
	ann := &fakeAnnouncer{}
	s := correlation(t, fakeInventory{}, fakeDiscovery{}, newMatches(), newRepo()).WithCompletion(ann)

	if _, err := s.ApplyCorrelation(context.Background(), app.CorrelationPlan{ReleaseID: "rel-1", EvidenceID: "ev-1"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(ann.calls) != 1 || ann.calls[0].cause != domain.CauseNewSBOM {
		t.Fatalf("announcements = %+v, want one new_sbom completion", ann.calls)
	}
}

// The cause vocabulary is closed. A third value is a programming error, and it fails the apply
// rather than reaching Governance as a value no consumer has a case for.
func TestApplyCorrelation_UnknownCauseRefused(t *testing.T) {
	ann := &fakeAnnouncer{}
	s := correlation(t, fakeInventory{}, fakeDiscovery{}, newMatches(), newRepo()).WithCompletion(ann)

	_, err := s.ApplyCorrelation(context.Background(), app.CorrelationPlan{
		ReleaseID: "rel-1", EvidenceID: "ev-1", Cause: "because-i-said-so",
	})
	if err == nil {
		t.Fatal("an unknown discovery cause must fail the apply")
	}
	if len(ann.calls) != 0 {
		t.Errorf("announced %+v on an unknown cause — nothing may be published", ann.calls)
	}
}

// The announcement is a write in the same unit of work, so its failure fails the apply: the
// matches and the fact that they are complete commit together or not at all.
func TestApplyCorrelation_AnnouncerErrorPropagates(t *testing.T) {
	ann := &fakeAnnouncer{err: errors.New("outbox down")}
	s := correlation(t, fakeInventory{inv: inventoryOf("pkg:pypi/a@1")}, fakeDiscovery{}, newMatches(), newRepo()).
		WithCompletion(ann)

	if _, err := s.Correlate(context.Background(), "rel-1", "ev-1"); err == nil {
		t.Fatal("a failed completion write must fail the apply")
	}
}

// No SBOM to name, nothing to announce — the same guard the re-discovery ledger uses. And with
// no announcer wired at all, correlation behaves exactly as it did before N-M2a.
func TestApplyCorrelation_NoEvidenceIDAndNoAnnouncerAreSilent(t *testing.T) {
	ann := &fakeAnnouncer{}
	s := correlation(t, fakeInventory{}, fakeDiscovery{}, newMatches(), newRepo()).WithCompletion(ann)
	if _, err := s.ApplyCorrelation(context.Background(), app.CorrelationPlan{ReleaseID: "rel-1"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(ann.calls) != 0 {
		t.Errorf("announced %+v for a plan with no evidence id", ann.calls)
	}

	unwired := correlation(t, fakeInventory{inv: inventoryOf("pkg:pypi/a@1")}, fakeDiscovery{}, newMatches(), newRepo())
	if _, err := unwired.Correlate(context.Background(), "rel-1", "ev-1"); err != nil {
		t.Fatalf("correlate without an announcer: %v", err)
	}
}

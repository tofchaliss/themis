package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// countingRedHat records how often each CVE was fetched, so the D10 gate's skips are
// observable rather than inferred.
type countingRedHat struct {
	calls map[string]int
	props map[string][]app.ProposalFor
}

func (c *countingRedHat) FetchCVE(_ context.Context, cve string) ([]app.ProposalFor, error) {
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[cve]++
	return c.props[cve], nil
}

type fakeChangeSignal struct {
	changed  map[string]struct{}
	ok       bool
	gotSince []time.Time
}

func (f *fakeChangeSignal) ChangedSince(_ context.Context, since time.Time) (map[string]struct{}, bool) {
	f.gotSince = append(f.gotSince, since)
	return f.changed, f.ok
}

// mutableKnown lets a test grow the carded set between sweeps — the "card added between
// sweeps" case the gate must fetch immediately.
type mutableKnown struct{ set map[string]struct{} }

func (m *mutableKnown) KnownCVEs(context.Context) (map[string]struct{}, error) { return m.set, nil }

func gatedSvc(t *testing.T, src app.RedHatCVESource, kn app.KnownCVEs, sig app.RedHatChangeSignal) *app.RedHatEnrichmentService {
	t.Helper()
	fold := app.NewFaultlineService(newRepo(), &seqIDs{}, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"), domain.NewTrustPolicy(nil))
	return app.NewRedHatEnrichmentService(src, kn, fold).WithChangeSignal(sig, fixedClock{})
}

// The core D10 contract: sweep 1 is full and never consults the signal (there is no watermark
// yet); sweep 2 re-asks only what the signal reports changed, and skips the rest.
func TestRedHatEnrich_GateSkipsUnchangedAfterFirstFullSweep(t *testing.T) {
	ctx := context.Background()
	src := &countingRedHat{props: map[string][]app.ProposalFor{
		"CVE-2024-1": rhProps(t, "CVE-2024-1"),
		"CVE-2024-2": rhProps(t, "CVE-2024-2"),
	}}
	sig := &fakeChangeSignal{changed: map[string]struct{}{"CVE-2024-1": {}}, ok: true}
	s := gatedSvc(t, src, known("CVE-2024-1", "CVE-2024-2"), sig)

	if _, err := s.Enrich(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if len(sig.gotSince) != 0 {
		t.Fatalf("the first sweep must be full without consulting the signal (consulted %d times)", len(sig.gotSince))
	}
	if _, err := s.Enrich(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if src.calls["CVE-2024-1"] != 2 {
		t.Errorf("changed CVE fetched %d times, want 2 (re-asked on change)", src.calls["CVE-2024-1"])
	}
	if src.calls["CVE-2024-2"] != 1 {
		t.Errorf("unchanged CVE fetched %d times, want 1 (skipped by the gate)", src.calls["CVE-2024-2"])
	}
	if len(sig.gotSince) != 1 || !sig.gotSince[0].Equal(fixedClock{}.Now()) {
		t.Errorf("signal consulted with since=%v, want the last completed sweep's start %v", sig.gotSince, fixedClock{}.Now())
	}
}

// Fail-open rule 2: a signal failure disables the gate for that sweep — exactly the pre-D10
// full sweep, so a broken changes.csv can only cost requests, never freshness.
func TestRedHatEnrich_GateFailsOpenToFullSweepOnSignalFailure(t *testing.T) {
	ctx := context.Background()
	src := &countingRedHat{props: map[string][]app.ProposalFor{"CVE-2024-1": rhProps(t, "CVE-2024-1")}}
	sig := &fakeChangeSignal{ok: false}
	s := gatedSvc(t, src, known("CVE-2024-1"), sig)

	for i := 0; i < 3; i++ {
		if _, err := s.Enrich(ctx); err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
	}
	if src.calls["CVE-2024-1"] != 3 {
		t.Errorf("with a failing signal every sweep must be full: fetched %d times, want 3", src.calls["CVE-2024-1"])
	}
}

// A card added between sweeps is not in the fetched set and must be fetched immediately, even
// when the signal reports nothing changed.
func TestRedHatEnrich_GateFetchesACVEItNeverSaw(t *testing.T) {
	ctx := context.Background()
	src := &countingRedHat{props: map[string][]app.ProposalFor{
		"CVE-2024-1": rhProps(t, "CVE-2024-1"),
		"CVE-2024-9": rhProps(t, "CVE-2024-9"),
	}}
	sig := &fakeChangeSignal{changed: map[string]struct{}{}, ok: true}
	kn := &mutableKnown{set: map[string]struct{}{"CVE-2024-1": {}}}
	s := gatedSvc(t, src, kn, sig)

	if _, err := s.Enrich(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	kn.set["CVE-2024-9"] = struct{}{} // carded between sweeps
	if _, err := s.Enrich(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if src.calls["CVE-2024-9"] != 1 {
		t.Errorf("a newly carded CVE must be fetched despite an empty change set (fetched %d times)", src.calls["CVE-2024-9"])
	}
	if src.calls["CVE-2024-1"] != 1 {
		t.Errorf("the unchanged known CVE must stay skipped (fetched %d times, want 1)", src.calls["CVE-2024-1"])
	}
}

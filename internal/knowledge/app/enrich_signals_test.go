package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeSignals struct {
	sigs map[string]domain.ExploitSignal
	err  error
}

func (f fakeSignals) Signals(context.Context) (map[string]domain.ExploitSignal, error) {
	return f.sigs, f.err
}

type fakeKnown struct {
	set map[string]struct{}
	err error
}

func (f fakeKnown) KnownCVEs(context.Context) (map[string]struct{}, error) { return f.set, f.err }

func known(cves ...string) fakeKnown {
	m := map[string]struct{}{}
	for _, c := range cves {
		m[c] = struct{}{}
	}
	return fakeKnown{set: m}
}

func enrichSvc(t *testing.T, repo app.Repository, sig app.ExploitSignalSource, kn app.KnownCVEs) *app.SignalEnrichmentService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"))
	return app.NewSignalEnrichmentService(sig, kn, fold, fixedClock{})
}

func TestEnrich_FoldsOnlyKnownWithSignals(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	// CVE-2024-1 is carded + has a signal → folds; CVE-2024-2 is carded + no signal → skip;
	// CVE-2024-3 has a signal but is NOT carded → never folded; "not-a-cve" is carded (defensive
	// parse-skip); CVE-2024-4 is carded but its signal is invalid (EPSS out of range) → skip.
	sigs := fakeSignals{sigs: map[string]domain.ExploitSignal{
		"CVE-2024-1": {EPSS: 0.9, KEV: true},
		"CVE-2024-3": {ExploitPublic: true},
		"not-a-cve":  {KEV: true},
		"CVE-2024-4": {EPSS: 2.0}, // out of range → NewExploitSignalProposal rejects
	}}
	kn := known("CVE-2024-1", "CVE-2024-2", "not-a-cve", "CVE-2024-4")

	n, err := enrichSvc(t, repo, sigs, kn).Enrich(ctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if n != 1 {
		t.Fatalf("folded = %d, want 1 (only CVE-2024-1)", n)
	}
	if _, ok := repo.cards["CVE-2024-1"]; !ok {
		t.Error("expected CVE-2024-1 card to be enriched")
	}
	if _, ok := repo.cards["CVE-2024-3"]; ok {
		t.Error("CVE-2024-3 has a signal but no card — must not be created")
	}
}

func TestEnrich_EmptyKnownIsNoOp(t *testing.T) {
	n, err := enrichSvc(t, newRepo(), fakeSignals{sigs: map[string]domain.ExploitSignal{"CVE-2024-1": {KEV: true}}}, known()).Enrich(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("empty known: got (%d,%v), want (0,nil)", n, err)
	}
}

func TestEnrich_Errors(t *testing.T) {
	ctx := context.Background()
	// known error propagates.
	if _, err := enrichSvc(t, newRepo(), fakeSignals{}, fakeKnown{err: errors.New("boom")}).Enrich(ctx); err == nil {
		t.Error("known error: expected error")
	}
	// signals error propagates.
	if _, err := enrichSvc(t, newRepo(), fakeSignals{err: errors.New("boom")}, known("CVE-2024-1")).Enrich(ctx); err == nil {
		t.Error("signals error: expected error")
	}
	// fold error propagates.
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	sigs := fakeSignals{sigs: map[string]domain.ExploitSignal{"CVE-2024-1": {KEV: true}}}
	if _, err := enrichSvc(t, badRepo, sigs, known("CVE-2024-1")).Enrich(ctx); err == nil {
		t.Error("fold error: expected error")
	}
}

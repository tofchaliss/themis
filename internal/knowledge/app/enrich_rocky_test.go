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

type fakeRocky struct {
	props    []app.ProposalFor
	err      error
	gotKnown map[string]struct{}
	calls    int
}

func (f *fakeRocky) ProposalsForKnown(_ context.Context, known map[string]struct{}) ([]app.ProposalFor, error) {
	f.calls++
	f.gotKnown = known
	if f.err != nil {
		return nil, f.err
	}
	return f.props, nil
}

func rockySvc(t *testing.T, repo app.Repository, src app.RockyFixSource, kn app.KnownCVEs) *app.RockyEnrichmentService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"), domain.NewTrustPolicy(nil))
	return app.NewRockyEnrichmentService(src, kn, fold)
}

// rockyFixProps builds the fix-bound Proposal an RXSA sweep yields for a CVE: source-package
// rpm Fixes only, SeverityUnknown (EDR-VEX-01 D11 — `rocky` never contends for the headline).
func rockyFixProps(t *testing.T, cveStr, pkg, fixVersion string) []app.ProposalFor {
	t.Helper()
	p, err := domain.NewVulnFactsProposal("rocky", time.Unix(1_700_000_000, 0), domain.VulnFacts{
		Severity: value.SeverityUnknown,
		Fixes:    []domain.FixedVersion{{Package: pkg, Version: fixVersion, Ecosystem: "rpm"}},
	})
	if err != nil {
		t.Fatalf("rocky proposal: %v", err)
	}
	return []app.ProposalFor{{CVE: cve(t, cveStr), Proposal: p}}
}

func TestRockyEnrich_FoldsFixBoundsAndPassesTheKnownSetIn(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	src := &fakeRocky{props: rockyFixProps(t, "CVE-2026-1", "kernel", "0:5.14.0-687.36.1.el9_8.cloud.1.0")}

	n, err := rockySvc(t, repo, src, known("CVE-2026-1", "CVE-2026-2")).Enrich(ctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if n != 1 {
		t.Fatalf("folded = %d, want 1", n)
	}
	// The D5 bound travels INTO the source (D11, same shape as the Alpine secdb): the errata
	// set is walked whole, so the known set must reach the client for the in-memory discard.
	if len(src.gotKnown) != 2 {
		t.Fatalf("known set did not reach the source: got %v", src.gotKnown)
	}
	f, found, err := repo.GetByCVE(ctx, "CVE-2026-1")
	if err != nil || !found {
		t.Fatalf("card not found after fold: found=%v err=%v", found, err)
	}
	fixes := f.View().StrictFixesFor("kernel", "rpm")
	if len(fixes) != 1 {
		t.Fatalf("StrictFixesFor(kernel, rpm) = %v, want the folded RXSA bound", fixes)
	}
}

func TestRockyEnrich_EmptyKnownIsNoOpWithoutFetching(t *testing.T) {
	src := &fakeRocky{}
	n, err := rockySvc(t, newRepo(), src, known()).Enrich(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("empty known: n=%d err=%v, want 0/nil", n, err)
	}
	if src.calls != 0 {
		t.Fatal("an empty carded set must not fetch the errata at all")
	}
}

func TestRockyEnrich_Errors(t *testing.T) {
	ctx := context.Background()
	// A source error aborts the sweep — one paginated walk, so its failure IS the sweep failing.
	src := &fakeRocky{err: errors.New("apollo down")}
	if _, err := rockySvc(t, newRepo(), src, known("CVE-2026-1")).Enrich(ctx); err == nil {
		t.Fatal("a source error must abort the sweep so feed health records it")
	}
	// A known-set read error aborts before any fetch.
	fetchless := &fakeRocky{}
	if _, err := rockySvc(t, newRepo(), fetchless, fakeKnown{err: errors.New("boom")}).Enrich(ctx); err == nil {
		t.Fatal("a known-set error must abort the sweep")
	}
	if fetchless.calls != 0 {
		t.Fatal("a known-set error must abort before fetching")
	}
	// A fold (store) error propagates — a persistence fault, not a feed gap.
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	src2 := &fakeRocky{props: rockyFixProps(t, "CVE-2026-1", "kernel", "0:5.14.0-687.el9")}
	if _, err := rockySvc(t, badRepo, src2, known("CVE-2026-1")).Enrich(ctx); err == nil {
		t.Fatal("a fold error must abort the sweep")
	}
}

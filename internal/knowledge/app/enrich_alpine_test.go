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

type fakeAlpine struct {
	props    []app.ProposalFor
	err      error
	gotKnown map[string]struct{}
}

func (f *fakeAlpine) ProposalsForKnown(_ context.Context, known map[string]struct{}) ([]app.ProposalFor, error) {
	f.gotKnown = known
	if f.err != nil {
		return nil, f.err
	}
	return f.props, nil
}

func alpineSvc(t *testing.T, repo app.Repository, src app.AlpineFixSource, kn app.KnownCVEs) *app.AlpineEnrichmentService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"), domain.NewTrustPolicy(nil))
	return app.NewAlpineEnrichmentService(src, kn, fold)
}

// alpineFixProps builds the fix-bound Proposal an Alpine sweep yields for a CVE: Fixes only,
// SeverityUnknown (the secdb states no severity — EDR-VEX-01 D7).
func alpineFixProps(t *testing.T, cveStr, pkg, fixVersion string) []app.ProposalFor {
	t.Helper()
	p, err := domain.NewVulnFactsProposal("alpine", time.Unix(1_700_000_000, 0), domain.VulnFacts{
		Severity: value.SeverityUnknown,
		Fixes:    []domain.FixedVersion{{Package: pkg, Version: fixVersion}},
	})
	if err != nil {
		t.Fatalf("alpine proposal: %v", err)
	}
	return []app.ProposalFor{{CVE: cve(t, cveStr), Proposal: p}}
}

func TestAlpineEnrich_FoldsFixBoundsAndPassesTheKnownSetIn(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	src := &fakeAlpine{props: alpineFixProps(t, "CVE-2024-1", "openssl", "3.1.4-r5")}

	n, err := alpineSvc(t, repo, src, known("CVE-2024-1", "CVE-2024-2")).Enrich(ctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if n != 1 {
		t.Fatalf("folded = %d, want 1", n)
	}
	// The D5 bound travels INTO the source — the secdb is not per-CVE addressable, so the
	// adapter must be able to discard uncarded records before anything is materialized.
	if len(src.gotKnown) != 2 {
		t.Errorf("known set passed to source = %v, want both carded CVEs", src.gotKnown)
	}
	card, ok := repo.cards["CVE-2024-1"]
	if !ok {
		t.Fatal("expected CVE-2024-1 card")
	}
	if fixes := card.View().FixesFor("openssl", "apk"); len(fixes) != 1 || fixes[0] != "3.1.4-r5" {
		t.Errorf("FixesFor(openssl) = %v, want the apk fix bound", fixes)
	}
	// The whole point of SeverityUnknown: the fix bound lands without contending for the
	// reconciled severity headline.
	if sev := card.View().Severity; sev != value.SeverityUnknown {
		t.Errorf("severity = %v, want unknown (the secdb states none)", sev)
	}
}

func TestAlpineEnrich_EmptyKnownIsNoOpWithoutFetching(t *testing.T) {
	src := &fakeAlpine{props: alpineFixProps(t, "CVE-2024-1", "openssl", "3.1.4-r5")}
	n, err := alpineSvc(t, newRepo(), src, known()).Enrich(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("empty known: got (%d,%v), want (0,nil)", n, err)
	}
	if src.gotKnown != nil {
		t.Error("no card means no fetch — the source must not be consulted at all")
	}
}

func TestAlpineEnrich_Errors(t *testing.T) {
	ctx := context.Background()
	// known error propagates.
	if _, err := alpineSvc(t, newRepo(), &fakeAlpine{}, fakeKnown{err: errors.New("boom")}).Enrich(ctx); err == nil {
		t.Error("known error: expected error")
	}
	// source error aborts the sweep — there is ONE branch-DB fetch, so its failure IS the
	// sweep failing (unlike the per-CVE feeds, where one CVE's gap is skipped).
	if _, err := alpineSvc(t, newRepo(), &fakeAlpine{err: errors.New("secdb 500")}, known("CVE-2024-1")).Enrich(ctx); err == nil {
		t.Error("source error: expected error")
	}
	// fold (store) error propagates — a persistence fault, not a feed gap.
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	src := &fakeAlpine{props: alpineFixProps(t, "CVE-2024-1", "openssl", "3.1.4-r5")}
	if _, err := alpineSvc(t, badRepo, src, known("CVE-2024-1")).Enrich(ctx); err == nil {
		t.Error("fold error: expected error")
	}
}

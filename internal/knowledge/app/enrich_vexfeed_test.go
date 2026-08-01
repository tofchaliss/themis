package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeVexFeed struct {
	byCVE  map[string][]app.ProposalFor
	errCVE map[string]error
}

func (f fakeVexFeed) FetchCVE(_ context.Context, cve string) ([]app.ProposalFor, error) {
	if e := f.errCVE[cve]; e != nil {
		return nil, e
	}
	return f.byCVE[cve], nil
}

func vexSvc(t *testing.T, repo app.Repository, src app.VexFeedSource, kn app.KnownCVEs) *app.VexEnrichmentService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"))
	return app.NewVexEnrichmentService(src, kn, fold)
}

func vexProps(t *testing.T, cveStr, pkg string) []app.ProposalFor {
	t.Helper()
	p, err := domain.NewApplicabilityProposal("vexfeed", time.Unix(1_700_000_000, 0).UTC(),
		domain.Applicability{Package: pkg, Status: "not_affected", Justification: "CSAF VEX: not affected"})
	if err != nil {
		t.Fatalf("applicability: %v", err)
	}
	return []app.ProposalFor{{CVE: cve(t, cveStr), Proposal: p}}
}

func TestVexEnrich_FoldsKnownCVEs(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	src := fakeVexFeed{byCVE: map[string][]app.ProposalFor{"CVE-2024-1": vexProps(t, "CVE-2024-1", "openssl")}}
	kn := known("CVE-2024-1", "CVE-2024-2") // CVE-2024-2 has no vendor VEX → nothing folded

	n, err := vexSvc(t, repo, src, kn).Enrich(ctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if n != 1 {
		t.Fatalf("folded = %d, want 1", n)
	}
	card, ok := repo.cards["CVE-2024-1"]
	if !ok {
		t.Fatal("expected CVE-2024-1 card")
	}
	if apps := card.View().Applicabilities; len(apps) != 1 || apps[0].Status != "not_affected" || apps[0].Package != "openssl" {
		t.Errorf("applicabilities = %+v", apps)
	}
}

func TestVexEnrich_SkipsPerCVEFetchError(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	src := fakeVexFeed{
		byCVE:  map[string][]app.ProposalFor{"CVE-2024-2": vexProps(t, "CVE-2024-2", "zlib")},
		errCVE: map[string]error{"CVE-2024-1": errors.New("502 bad gateway")},
	}
	n, err := vexSvc(t, repo, src, known("CVE-2024-1", "CVE-2024-2")).Enrich(ctx)
	if err != nil {
		t.Fatalf("a per-CVE fetch error must not abort the sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("folded = %d, want 1 (CVE-2024-2 only)", n)
	}
	if _, ok := repo.cards["CVE-2024-1"]; ok {
		t.Error("a fetch-errored CVE must not be carded")
	}
}

func TestVexEnrich_EmptyKnownIsNoOp(t *testing.T) {
	src := fakeVexFeed{byCVE: map[string][]app.ProposalFor{"CVE-2024-1": vexProps(t, "CVE-2024-1", "openssl")}}
	n, err := vexSvc(t, newRepo(), src, known()).Enrich(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("empty known: got (%d,%v), want (0,nil)", n, err)
	}
}

func TestVexEnrich_Errors(t *testing.T) {
	ctx := context.Background()
	if _, err := vexSvc(t, newRepo(), fakeVexFeed{}, fakeKnown{err: errors.New("boom")}).Enrich(ctx); err == nil {
		t.Error("known error: expected error")
	}
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	src := fakeVexFeed{byCVE: map[string][]app.ProposalFor{"CVE-2024-1": vexProps(t, "CVE-2024-1", "openssl")}}
	if _, err := vexSvc(t, badRepo, src, known("CVE-2024-1")).Enrich(ctx); err == nil {
		t.Error("fold error: expected error")
	}
}

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

type fakeRedHat struct {
	byCVE  map[string][]app.ProposalFor
	errCVE map[string]error // per-CVE fetch error (a transient/404 is modeled as an error the sweep skips)
}

func (f fakeRedHat) FetchCVE(_ context.Context, cve string) ([]app.ProposalFor, error) {
	if e := f.errCVE[cve]; e != nil {
		return nil, e
	}
	return f.byCVE[cve], nil
}

func redhatSvc(t *testing.T, repo app.Repository, src app.RedHatCVESource, kn app.KnownCVEs) *app.RedHatEnrichmentService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"))
	return app.NewRedHatEnrichmentService(src, kn, fold)
}

// rhProps builds the two Proposals a Red Hat fetch yields for a CVE: a vendor-severity
// vuln-facts Proposal + a not_affected applicability Proposal.
func rhProps(t *testing.T, cveStr string) []app.ProposalFor {
	t.Helper()
	at := time.Unix(1_700_000_000, 0).UTC()
	appP, err := domain.NewApplicabilityProposal("redhat", at, domain.Applicability{
		Package: "openssl", Status: "not_affected", Justification: "Red Hat: not affected in Red Hat Enterprise Linux 8",
	})
	if err != nil {
		t.Fatalf("applicability: %v", err)
	}
	return []app.ProposalFor{
		{CVE: cve(t, cveStr), Proposal: vulnFacts(t, "redhat", value.SeverityHigh)},
		{CVE: cve(t, cveStr), Proposal: appP},
	}
}

func TestRedHatEnrich_FoldsKnownCVEs(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	// CVE-2024-1 is carded + has Red Hat data → both Proposals fold; CVE-2024-2 is carded but Red
	// Hat tracks nothing (nil) → nothing folded.
	src := fakeRedHat{byCVE: map[string][]app.ProposalFor{"CVE-2024-1": rhProps(t, "CVE-2024-1")}}
	kn := known("CVE-2024-1", "CVE-2024-2")

	n, err := redhatSvc(t, repo, src, kn).Enrich(ctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if n != 2 {
		t.Fatalf("folded = %d, want 2 (vuln-facts + applicability for CVE-2024-1)", n)
	}
	card, ok := repo.cards["CVE-2024-1"]
	if !ok {
		t.Fatal("expected CVE-2024-1 card")
	}
	if apps := card.View().Applicabilities; len(apps) != 1 || apps[0].Status != "not_affected" || apps[0].Package != "openssl" {
		t.Errorf("applicabilities = %+v, want one not_affected openssl", apps)
	}
}

func TestRedHatEnrich_SkipsPerCVEFetchError(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	// CVE-2024-1's fetch errors (transient / 404-as-error) → skipped; CVE-2024-2 folds. One gap
	// never aborts the sweep.
	src := fakeRedHat{
		byCVE:  map[string][]app.ProposalFor{"CVE-2024-2": rhProps(t, "CVE-2024-2")},
		errCVE: map[string]error{"CVE-2024-1": errors.New("429 slow down")},
	}
	n, err := redhatSvc(t, repo, src, known("CVE-2024-1", "CVE-2024-2")).Enrich(ctx)
	if err != nil {
		t.Fatalf("a per-CVE fetch error must not abort the sweep: %v", err)
	}
	if n != 2 {
		t.Errorf("folded = %d, want 2 (CVE-2024-2 only; CVE-2024-1 skipped)", n)
	}
	if _, ok := repo.cards["CVE-2024-1"]; ok {
		t.Error("a fetch-errored CVE must not be carded")
	}
}

func TestRedHatEnrich_EmptyKnownIsNoOp(t *testing.T) {
	src := fakeRedHat{byCVE: map[string][]app.ProposalFor{"CVE-2024-1": rhProps(t, "CVE-2024-1")}}
	n, err := redhatSvc(t, newRepo(), src, known()).Enrich(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("empty known: got (%d,%v), want (0,nil)", n, err)
	}
}

func TestRedHatEnrich_Errors(t *testing.T) {
	ctx := context.Background()
	// known error propagates.
	if _, err := redhatSvc(t, newRepo(), fakeRedHat{}, fakeKnown{err: errors.New("boom")}).Enrich(ctx); err == nil {
		t.Error("known error: expected error")
	}
	// fold (store) error propagates — a persistence fault, not a feed gap.
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	src := fakeRedHat{byCVE: map[string][]app.ProposalFor{"CVE-2024-1": rhProps(t, "CVE-2024-1")}}
	if _, err := redhatSvc(t, badRepo, src, known("CVE-2024-1")).Enrich(ctx); err == nil {
		t.Error("fold error: expected error")
	}
}

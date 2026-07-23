package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeScannerSource struct {
	props []app.ScannerProposal
	err   error
}

func (f fakeScannerSource) ScannerProposals(_ context.Context, _ string) ([]app.ScannerProposal, error) {
	return f.props, f.err
}

func scannerService(t *testing.T, src app.ScannerReportSource, matches *fakeMatches, repo *fakeRepo) *app.ScannerReportService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"))
	return app.NewScannerReportService(src, fold, matches, fixedClock{})
}

func TestScannerReport_IngestAndIdempotent(t *testing.T) {
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1"}},
		{CVE: cve(t, "CVE-2024-2"), Proposal: vulnFacts(t, "scanner", value.SeverityMedium),
			Component: app.InventoryComponent{PURL: "pkg:pypi/bar@2"}},
	}}
	matches := newMatches()
	svc := scannerService(t, src, matches, newRepo())

	n, err := svc.Ingest(context.Background(), "rel-1", "ev-1")
	if err != nil || n != 2 {
		t.Fatalf("Ingest = %d, %v; want 2, nil", n, err)
	}
	// Re-ingesting the same report records no new matches (idempotent).
	n2, err := svc.Ingest(context.Background(), "rel-1", "ev-1")
	if err != nil || n2 != 0 {
		t.Fatalf("re-Ingest = %d, %v; want 0, nil", n2, err)
	}
}

func TestScannerReport_Errors(t *testing.T) {
	prop := app.ScannerProposal{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
		Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1"}}

	// source error propagates
	if _, err := scannerService(t, fakeScannerSource{err: errors.New("boom")}, newMatches(), newRepo()).
		Ingest(context.Background(), "rel-1", "ev-1"); err == nil {
		t.Error("expected source error")
	}
	// fold error propagates (aggregate save fails)
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	if _, err := scannerService(t, fakeScannerSource{props: []app.ScannerProposal{prop}}, newMatches(), badRepo).
		Ingest(context.Background(), "rel-1", "ev-1"); err == nil {
		t.Error("expected fold error")
	}
	// match-recorder error propagates
	badMatches := &fakeMatches{recorded: map[string]bool{}, err: errors.New("boom")}
	if _, err := scannerService(t, fakeScannerSource{props: []app.ScannerProposal{prop}}, badMatches, newRepo()).
		Ingest(context.Background(), "rel-1", "ev-1"); err == nil {
		t.Error("expected match-recorder error")
	}
}

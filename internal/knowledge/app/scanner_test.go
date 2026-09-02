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
	props   []app.ScannerProposal
	skipped int
	err     error
}

func (f fakeScannerSource) ScannerProposals(_ context.Context, _ string) ([]app.ScannerProposal, int, error) {
	return f.props, f.skipped, f.err
}

func scannerService(t *testing.T, src app.ScannerReportSource, matches *fakeMatches, repo *fakeRepo) *app.ScannerReportService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	return app.NewScannerReportService(src, fold, matches, fixedClock{})
}

func TestScannerReport_IngestAndIdempotent(t *testing.T) {
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1"}, Origin: "scanner/trivy"},
		{CVE: cve(t, "CVE-2024-2"), Proposal: vulnFacts(t, "scanner", value.SeverityMedium),
			Component: app.InventoryComponent{PURL: "pkg:pypi/bar@2"}, Origin: "scanner"},
	}}
	matches := newMatches()
	svc := scannerService(t, src, matches, newRepo())

	n, err := svc.Ingest(context.Background(), "rel-1", "ev-1")
	if err != nil || n != 2 {
		t.Fatalf("Ingest = %d, %v; want 2, nil", n, err)
	}
	// KN-SCAN-2: the source adapter's origin rides the recorded match unchanged, so the
	// posture can say which engine found the occurrence.
	if got := matches.byPURL["pkg:pypi/foo@1"].DetectionOrigin; got != "scanner/trivy" {
		t.Errorf("detection origin = %q, want scanner/trivy", got)
	}
	if got := matches.byPURL["pkg:pypi/bar@2"].DetectionOrigin; got != "scanner" {
		t.Errorf("detection origin = %q, want scanner", got)
	}
	// The plan carries the release and the skip count through to the log line.
	plan, err := svc.PlanIngest(context.Background(), "rel-1", "ev-1")
	if err != nil || plan.ReleaseID != "rel-1" || len(plan.Items) != 2 {
		t.Fatalf("PlanIngest = %+v, %v; want the 2-item plan for rel-1", plan, err)
	}
	// Re-ingesting the same report records no new matches (idempotent).
	n2, err := svc.Ingest(context.Background(), "rel-1", "ev-1")
	if err != nil || n2 != 0 {
		t.Fatalf("re-Ingest = %d, %v; want 0, nil", n2, err)
	}
}

// The KN-VERDICT-1 link-(b) regression: a scanner-reported occurrence runs through the SAME
// verdict seam as discovery (EDR-VERDICT-01 D2). Before this, the scanner path recorded
// unjudged rows on the premise "the scanner already version-matched" — which is exactly false
// for backports, which live in the build release a scanner reading .egg-info cannot see.
func TestScannerReport_JudgesOccurrencesThroughTheSharedSeam(t *testing.T) {
	fixed := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/openssl@1.0.2k-17.el8_10", Name: "openssl",
		Version: "1.0.2k-17.el8_10", Ecosystem: "rpm",
	}
	live := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/openssl@1.0.2k-10.el8", Name: "openssl",
		Version: "1.0.2k-10.el8", Ecosystem: "rpm",
	}
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2024-31"), Proposal: vulnFactsFixed(t, "scanner", "openssl-1.0.2k-16.el8_10"),
			Component: fixed, Origin: "scanner/trivy"},
		{CVE: cve(t, "CVE-2024-31"), Proposal: vulnFactsFixed(t, "scanner", "openssl-1.0.2k-16.el8_10"),
			Component: live, Origin: "scanner/trivy"},
	}}
	matches := newMatches()
	svc := scannerService(t, src, matches, newRepo())

	if n, err := svc.Ingest(context.Background(), "rel-1", "ev-1"); err != nil || n != 2 {
		t.Fatalf("Ingest = %d, %v; want both occurrences recorded", n, err)
	}
	if m := matches.byPURL[fixed.PURL]; m.Verdict.State != domain.VerdictClearedVendorFix {
		t.Errorf("at/above the same-stream bound: verdict = %+v, want cleared_vendor_fix", m.Verdict)
	}
	if m := matches.byPURL[live.PURL]; m.Verdict.State.IsOpen() != true {
		t.Errorf("below the bound: verdict = %+v, must stay open", m.Verdict)
	}
	if m := matches.byPURL[fixed.PURL]; m.CardVersion <= 0 {
		t.Errorf("CardVersion = %d, want the judged-against card version for the re-verdict stamp", m.CardVersion)
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

// The coordinator dispatch (KN-SCAN-1): a scanner-report evidence event reaches the scanner
// service through the same plan/apply shape as sbom and vex — this exact dispatch used to
// return a nil apply, which made a successful upload a silent no-op.
func TestCoordinator_ScannerReportIngests(t *testing.T) {
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1"}},
	}}
	matches := newMatches()
	coord := app.NewCoordinator(nil, nil).WithScanner(scannerService(t, src, matches, newRepo()))

	if err := coord.OnEvidenceRegistered(context.Background(),
		app.EvidenceRegistered{EvidenceID: "ev-9", ReleaseID: "rel-9", Kind: "scanner-report"}); err != nil {
		t.Fatalf("OnEvidenceRegistered: %v", err)
	}
	if len(matches.recorded) != 1 {
		t.Fatalf("recorded = %d matches, want the finding matched", len(matches.recorded))
	}
}

// A read-phase failure (Evidence unreachable, wrong kind) propagates so the inbox retries the
// event rather than silently committing nothing.
func TestCoordinator_ScannerReadErrorPropagates(t *testing.T) {
	coord := app.NewCoordinator(nil, nil).
		WithScanner(scannerService(t, fakeScannerSource{err: errors.New("evidence down")}, newMatches(), newRepo()))
	if err := coord.OnEvidenceRegistered(context.Background(),
		app.EvidenceRegistered{EvidenceID: "ev-9", ReleaseID: "rel-9", Kind: "scanner-report"}); err == nil {
		t.Fatal("a scanner read-phase error must propagate")
	}
}

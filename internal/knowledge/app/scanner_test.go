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

// The bridge through the scanner door: a Trivy-style report that catalogued BOTH the rpm
// database and site-packages is its own same-inventory candidate set, so the shadow clears
// (inferred) beside its patched rpm — and strict mode holds it open. The duplicate row also
// exercises the plan's sibling dedup.
func TestScannerReport_OwnershipBridgeAndStrictMode(t *testing.T) {
	shadow := app.InventoryComponent{
		PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi",
	}
	rpm := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10", Name: "platform-python-setuptools",
		Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
	}
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2025-47273"), Proposal: vulnFactsFixedFor(t, "scanner", "python-setuptools", "0:39.2.0-9.el8_10"),
			Component: shadow, Origin: "scanner/trivy"},
		{CVE: cve(t, "CVE-2025-47273"), Proposal: vulnFactsFixedFor(t, "scanner", "python-setuptools", "0:39.2.0-9.el8_10"),
			Component: rpm, Origin: "scanner/trivy"},
		// The same rpm reported twice (two findings can name one component) — dedups in the plan.
		{CVE: cve(t, "CVE-2025-47273"), Proposal: vulnFactsFixedFor(t, "scanner", "python-setuptools", "0:39.2.0-9.el8_10"),
			Component: rpm, Origin: "scanner/trivy"},
	}}
	matches := newMatches()
	if _, err := scannerService(t, src, matches, newRepo()).Ingest(context.Background(), "rel-1", "ev-1"); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if m := matches.byPURL[shadow.PURL]; m.Verdict.State != domain.VerdictClearedVendorFix || m.Verdict.Grade != domain.VerdictGradeInferred {
		t.Errorf("default bridge: verdict = %+v, want an inferred clearance", m.Verdict)
	}

	strictMatches := newMatches()
	svc := scannerService(t, src, strictMatches, newRepo()).WithInferredBridge(false)
	if _, err := svc.Ingest(context.Background(), "rel-1", "ev-1"); err != nil {
		t.Fatalf("strict ingest: %v", err)
	}
	if m := strictMatches.byPURL[shadow.PURL]; !m.Verdict.State.IsOpen() {
		t.Errorf("strict mode: verdict = %+v, must stay open", m.Verdict)
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

// identityLedger/identityInventory supply the release's canonical inventory — the authoritative
// candidate set for identity resolution (EDR-IDENTITY-01 D2).
type identityLedger struct {
	ev    string
	found bool
	err   error
}

func (l identityLedger) EvidenceForRelease(context.Context, string) (string, bool, error) {
	return l.ev, l.found, l.err
}

type identityInventory struct {
	comps []app.InventoryComponent
	err   error
}

func (i identityInventory) GetInventory(context.Context, string) (app.Inventory, error) {
	return app.Inventory{Components: i.comps}, i.err
}

type capturedIngest struct {
	calls                                int
	recorded, items, skipped, unresolved int
}

func (c *capturedIngest) ScannerIngest(_, _ string, recorded, items, skipped, unresolved int) {
	c.calls++
	c.recorded, c.items, c.skipped, c.unresolved = recorded, items, skipped, unresolved
}

// The measured case, end to end (EDR-IDENTITY-01 D2): a scanner observation carrying `app:httpd`
// resolves onto the release's own `pkg:rpm/rocky/httpd@2.4.57` — ONE component, not two security
// subjects. Before this, the observation was recorded with that raw string as its identity and
// became a subject on 60+ cards.
func TestScannerReport_ResolvesPurllessObservationOntoItsTwin(t *testing.T) {
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2023-31122"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"},
			Origin:    "scanner/cortex"},
	}}
	matches := newMatches()
	report := &capturedIngest{}
	svc := scannerService(t, src, matches, newRepo()).
		WithIdentityCandidates(identityLedger{ev: "ev-sbom", found: true},
			identityInventory{comps: []app.InventoryComponent{
				{PURL: "pkg:rpm/rocky/httpd@2.4.57", Name: "httpd", Version: "2.4.57", Ecosystem: "rpm"},
			}}).
		WithIngestReporter(report)

	if n, err := svc.Ingest(context.Background(), "rel-1", "ev-report"); err != nil || n != 1 {
		t.Fatalf("Ingest = %d, %v; want 1, nil", n, err)
	}
	if _, ok := matches.byPURL["pkg:rpm/rocky/httpd@2.4.57"]; !ok {
		t.Errorf("the observation did not land on the twin's purl; recorded %v", matches.byPURL)
	}
	if _, ok := matches.byPURL["app:httpd"]; ok {
		t.Error("the raw identifier was recorded as an identity — exactly the defect D1 forbids")
	}
	// D6: the counts reach an operator, on every ingest.
	if report.calls != 1 || report.recorded != 1 || report.items != 1 || report.unresolved != 0 {
		t.Errorf("report = %+v, want one call with 1 recorded / 1 item / 0 unresolved", report)
	}
}

// D2/D6: with no twin the observation ABSTAINS — retained and counted as unresolved, never
// guessed at, never recorded with an unusable identity, and never treated as a bystander.
func TestScannerReport_UnresolvedObservationIsCountedNotRecorded(t *testing.T) {
	src := fakeScannerSource{skipped: 2, props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2023-31122"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"},
			Origin:    "scanner/cortex"},
		{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1"}, Origin: "scanner"},
	}}
	matches := newMatches()
	report := &capturedIngest{}
	// A scanner-ONLY release: the ledger has no correlated evidence, so there is never a twin.
	svc := scannerService(t, src, matches, newRepo()).
		WithIdentityCandidates(identityLedger{}, identityInventory{}).
		WithIngestReporter(report)

	n, err := svc.Ingest(context.Background(), "rel-1", "ev-report")
	if err != nil {
		t.Fatalf("an unresolvable observation must not fail the ingest: %v", err)
	}
	if n != 1 {
		t.Errorf("recorded %d matches, want 1 — only the identifiable component", n)
	}
	if _, ok := matches.byPURL["app:httpd"]; ok {
		t.Error("an unresolved observation was recorded; no row may carry a non-identity")
	}
	if _, ok := matches.byPURL[""]; ok {
		t.Error("a row with an EMPTY purl was written — the primary-key collapse and the stream halt")
	}
	// The whole point of D6: it is visible. `skipped` was computed and never surfaced before
	// (KN-SCAN-OBS-1), so a half-translated report looked exactly like a clean one.
	if report.calls != 1 || report.unresolved != 1 || report.skipped != 2 || report.recorded != 1 {
		t.Errorf("report = %+v, want 1 unresolved / 2 skipped / 1 recorded", report)
	}
}

// Ambiguity abstains (D2). Two distinct purls for one name+version is exactly the case where a
// guess would be wrong, so no tie-break is invented — and an unreadable inventory degrades the
// same way, because a poorer context must never be stamped as an answer.
func TestScannerReport_AmbiguityAndDegradationBothAbstain(t *testing.T) {
	obs := app.ScannerProposal{
		CVE: cve(t, "CVE-2023-31122"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
		Component: app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"},
		Origin:    "scanner/cortex",
	}
	twins := []app.InventoryComponent{
		{PURL: "pkg:rpm/rocky/httpd@2.4.57", Name: "httpd", Version: "2.4.57", Ecosystem: "rpm"},
		{PURL: "pkg:rpm/rhel/httpd@2.4.57", Name: "httpd", Version: "2.4.57", Ecosystem: "rpm"},
	}
	for _, tc := range []struct {
		name      string
		ledger    identityLedger
		inventory identityInventory
	}{
		{"two candidates", identityLedger{ev: "ev-sbom", found: true}, identityInventory{comps: twins}},
		{"inventory read fails", identityLedger{ev: "ev-sbom", found: true}, identityInventory{err: errors.New("evidence down")}},
		{"ledger read fails", identityLedger{err: errors.New("db down")}, identityInventory{comps: twins[:1]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := newMatches()
			report := &capturedIngest{}
			svc := scannerService(t, fakeScannerSource{props: []app.ScannerProposal{obs}}, matches, newRepo()).
				WithIdentityCandidates(tc.ledger, tc.inventory).
				WithIngestReporter(report)
			if _, err := svc.Ingest(context.Background(), "rel-1", "ev-report"); err != nil {
				t.Fatalf("degradation must not fail the ingest: %v", err)
			}
			if len(matches.byPURL) != 0 {
				t.Errorf("recorded %v, want nothing — abstention writes no row", matches.byPURL)
			}
			if report.unresolved != 1 {
				t.Errorf("unresolved = %d, want 1 — abstention must still be visible", report.unresolved)
			}
		})
	}
}

// The candidate set includes the report's OWN usable components, because twins can travel
// together in one document — the measured SPDX file carried both. With no inventory wired at all
// (single-context dev), that is the only source, and it must still work.
func TestScannerReport_ReportsOwnComponentsAreCandidates(t *testing.T) {
	src := fakeScannerSource{props: []app.ScannerProposal{
		{CVE: cve(t, "CVE-2023-31122"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"},
			Origin:    "scanner/cortex"},
		{CVE: cve(t, "CVE-2023-31122"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
			Component: app.InventoryComponent{
				PURL: "pkg:rpm/rocky/httpd@2.4.57", Name: "httpd", Version: "2.4.57", Ecosystem: "rpm"},
			Origin: "scanner/cortex"},
	}}
	matches := newMatches()
	svc := scannerService(t, src, matches, newRepo()) // no identity ports wired at all
	if _, err := svc.Ingest(context.Background(), "rel-1", "ev-report"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if _, ok := matches.byPURL["pkg:rpm/rocky/httpd@2.4.57"]; !ok {
		t.Errorf("the twin in the same report was not used as a candidate; recorded %v", matches.byPURL)
	}
	if _, ok := matches.byPURL["app:httpd"]; ok {
		t.Error("the raw identifier was recorded as an identity")
	}
}

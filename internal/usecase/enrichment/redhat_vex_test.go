package enrichment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

type stubRHFetcher struct {
	reports  map[string]domain.RedHatCVEReport
	notFound map[string]bool
	err      map[string]error
	calls    map[string]int
}

func (f *stubRHFetcher) FetchCVE(_ context.Context, cve string) (domain.RedHatCVEReport, bool, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[cve]++
	if f.err != nil {
		if e := f.err[cve]; e != nil {
			return domain.RedHatCVEReport{}, false, e
		}
	}
	if f.notFound[cve] {
		return domain.RedHatCVEReport{}, false, nil
	}
	r, ok := f.reports[cve]
	return r, ok, nil
}

type stubFindings struct {
	rows []domain.OpenRiskContextRow
	err  error
}

func (s stubFindings) ListOpenRiskContexts(_ context.Context, _, _ int) ([]domain.OpenRiskContextRow, error) {
	return s.rows, s.err
}

type stubAssertionWriter struct {
	got  []domain.VendorVEXAssertion
	feed string
	err  error
}

func (s *stubAssertionWriter) UpsertAssertions(_ context.Context, feed string, a []domain.VendorVEXAssertion) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.feed = feed
	s.got = append(s.got, a...)
	return len(a), nil
}

type stubReEnqueuer struct {
	ids []string
	err error
}

func (s *stubReEnqueuer) EnqueueApplyVEXForSBOMs(_ context.Context, ids []string) error {
	if s.err != nil {
		return s.err
	}
	s.ids = append(s.ids, ids...)
	return nil
}

type countingRHMetrics struct{ counts map[string]int }

func (m *countingRHMetrics) RecordVerdict(status string) {
	if m.counts == nil {
		m.counts = map[string]int{}
	}
	m.counts[status]++
}

func rpmRow(artifact, purl, cve string) domain.OpenRiskContextRow {
	return domain.OpenRiskContextRow{ArtifactID: artifact, ComponentPURL: purl, CVEID: cve, EffectiveState: "detected"}
}

var ncursesRHReport = domain.RedHatCVEReport{
	CVEID:          "CVE-2022-29458",
	ThreatSeverity: "Low",
	Statement:      "vulnerable code is build-time tic",
	PackageStates: []domain.RedHatPackageState{
		{PackageName: "ncurses", FixState: "Not affected", CPE: "cpe:/o:redhat:enterprise_linux:8"},
	},
	AffectedReleases: []domain.RedHatAffectedRelease{
		{PackageNEVRA: "ncurses-0:6.2-10.20210508.el9_6.2", CPE: "cpe:/o:redhat:enterprise_linux:9", Advisory: "RHSA-2025:12876"},
	},
}

func TestRedHatVEXNotAffectedAffectedFixed(t *testing.T) {
	rows := []domain.OpenRiskContextRow{
		// el8 ncurses → Red Hat "Not affected"
		rpmRow("art-1", "pkg:rpm/rocky/ncurses@6.1-10.20180224.el8?arch=x86_64", "CVE-2022-29458"),
		// el8 openssl, installed BELOW the el8 fix → affected
		rpmRow("art-1", "pkg:rpm/rocky/openssl@0:1.1.1k-14.el8_10?arch=x86_64", "CVE-2024-OPENSSL"),
		// el8 openssl on a second artifact, installed AT/ABOVE the el8 fix → fixed
		rpmRow("art-2", "pkg:rpm/rocky/openssl@0:1.1.1k-16.el8_10?arch=x86_64", "CVE-2024-OPENSSL"),
		// pypi finding → skipped (not rpm)
		rpmRowPyPI(),
	}
	opensslReport := domain.RedHatCVEReport{
		CVEID:          "CVE-2024-OPENSSL",
		ThreatSeverity: "Important",
		AffectedReleases: []domain.RedHatAffectedRelease{
			{PackageNEVRA: "openssl-0:1.1.1k-15.el8_10", CPE: "cpe:/o:redhat:enterprise_linux:8", Advisory: "RHSA-2024:1"},
		},
	}
	fetcher := &stubRHFetcher{reports: map[string]domain.RedHatCVEReport{
		"CVE-2022-29458":   ncursesRHReport,
		"CVE-2024-OPENSSL": opensslReport,
	}}
	store := &stubAssertionWriter{}
	reEnq := &stubReEnqueuer{}
	metrics := &countingRHMetrics{}
	svc := &RedHatVEXService{Fetcher: fetcher, Findings: stubFindings{rows: rows}, Store: store, ReEnrich: reEnq, Metrics: metrics}

	res, err := svc.RunCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.NotAffected != 1 || res.Affected != 1 || res.Fixed != 1 {
		t.Fatalf("result = %+v", res)
	}
	if store.feed != "redhat" || len(store.got) != 3 {
		t.Fatalf("assertions = %d feed=%q", len(store.got), store.feed)
	}
	// openssl fetched once though it appears in two findings.
	if fetcher.calls["CVE-2024-OPENSSL"] != 1 {
		t.Fatalf("openssl fetched %d times, want 1", fetcher.calls["CVE-2024-OPENSSL"])
	}
	// statuses keyed to the finding's PURL with the vendor rationale in the justification.
	byStatus := map[string]domain.VendorVEXAssertion{}
	for _, a := range store.got {
		byStatus[a.Status] = a
	}
	na := byStatus[domain.VEXStatusNotAffected]
	if na.ComponentPURL != "pkg:rpm/rocky/ncurses@6.1-10.20180224.el8?arch=x86_64" || na.Severity != "Low" {
		t.Fatalf("not_affected assertion = %+v", na)
	}
	if !contains(na.Justification, "Not affected on RHEL-8") || !contains(na.Justification, "threat severity: Low") {
		t.Fatalf("justification not visible: %q", na.Justification)
	}
	if byStatus[domain.VEXStatusFixed].ComponentPURL == "" || byStatus[domain.VEXStatusAffected].ComponentPURL == "" {
		t.Fatalf("missing fixed/affected assertions: %+v", byStatus)
	}
	if len(reEnq.ids) != 2 || res.ArtifactsQueued != 2 {
		t.Fatalf("artifacts queued = %v (%d)", reEnq.ids, res.ArtifactsQueued)
	}
}

func rpmRowPyPI() domain.OpenRiskContextRow {
	return domain.OpenRiskContextRow{ArtifactID: "art-1", ComponentPURL: "pkg:pypi/jinja2@3.1.6", CVEID: "CVE-2016-10745", EffectiveState: "detected"}
}

func TestRedHatVEXUncoveredStream(t *testing.T) {
	// el10 ncurses — Red Hat published nothing for stream 10 → no assertion.
	rows := []domain.OpenRiskContextRow{
		rpmRow("art-1", "pkg:rpm/rocky/ncurses@6.3-1.el10?arch=x86_64", "CVE-2022-29458"),
	}
	fetcher := &stubRHFetcher{reports: map[string]domain.RedHatCVEReport{"CVE-2022-29458": ncursesRHReport}}
	store := &stubAssertionWriter{}
	svc := &RedHatVEXService{Fetcher: fetcher, Findings: stubFindings{rows: rows}, Store: store}
	res, err := svc.RunCycle(context.Background())
	if err != nil || res.CVEsChecked != 1 || len(store.got) != 0 {
		t.Fatalf("uncovered: res=%+v assertions=%d err=%v", res, len(store.got), err)
	}
}

func TestRedHatVEXNotFoundAndBackoff(t *testing.T) {
	rows := []domain.OpenRiskContextRow{rpmRow("art-1", "pkg:rpm/rocky/foo@1-1.el8", "CVE-2024-404")}
	fetcher := &stubRHFetcher{notFound: map[string]bool{"CVE-2024-404": true}}
	store := &stubAssertionWriter{}
	metrics := &countingRHMetrics{}
	now := time.Now()
	svc := &RedHatVEXService{Fetcher: fetcher, Findings: stubFindings{rows: rows}, Store: store, Metrics: metrics, Now: func() time.Time { return now }}

	if _, err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second cycle: CVE within the back-off window → not re-fetched.
	if _, err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls["CVE-2024-404"] != 1 {
		t.Fatalf("404 CVE fetched %d times, want 1 (back-off)", fetcher.calls["CVE-2024-404"])
	}
	if metrics.counts["checked"] != 1 {
		t.Fatalf("checked metric = %d", metrics.counts["checked"])
	}
}

func TestRedHatVEXAbortsOnConsecutiveErrors(t *testing.T) {
	var rows []domain.OpenRiskContextRow
	errs := map[string]error{}
	for i := 0; i < maxConsecutiveRedHatErrors+2; i++ {
		cve := "CVE-ERR-" + string(rune('A'+i))
		rows = append(rows, rpmRow("art-1", "pkg:rpm/rocky/p@1-1.el8", cve))
		errs[cve] = errors.New("boom")
	}
	fetcher := &stubRHFetcher{err: errs}
	svc := &RedHatVEXService{Fetcher: fetcher, Findings: stubFindings{rows: rows}, Store: &stubAssertionWriter{}}
	if _, err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected abort after consecutive failures")
	}
}

func TestRedHatVEXNilDepsAndErrors(t *testing.T) {
	// Nil deps → no-op.
	if _, err := (&RedHatVEXService{}).RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Findings error propagates.
	svc := &RedHatVEXService{Fetcher: &stubRHFetcher{}, Findings: stubFindings{err: errors.New("db")}, Store: &stubAssertionWriter{}}
	if _, err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected findings error")
	}
	// Store error propagates.
	rows := []domain.OpenRiskContextRow{rpmRow("art-1", "pkg:rpm/rocky/ncurses@6.1-1.el8", "CVE-2022-29458")}
	store := &stubAssertionWriter{err: errors.New("store")}
	svc2 := &RedHatVEXService{Fetcher: &stubRHFetcher{reports: map[string]domain.RedHatCVEReport{"CVE-2022-29458": ncursesRHReport}}, Findings: stubFindings{rows: rows}, Store: store}
	if _, err := svc2.RunCycle(context.Background()); err == nil {
		t.Fatal("expected store error")
	}
	// ReEnrich error propagates.
	svc3 := &RedHatVEXService{Fetcher: &stubRHFetcher{reports: map[string]domain.RedHatCVEReport{"CVE-2022-29458": ncursesRHReport}}, Findings: stubFindings{rows: rows}, Store: &stubAssertionWriter{}, ReEnrich: &stubReEnqueuer{err: errors.New("queue")}}
	if _, err := svc3.RunCycle(context.Background()); err == nil {
		t.Fatal("expected reenrich error")
	}
}

func TestRPMPurlHelpers(t *testing.T) {
	if got := rpmPackageName("pkg:rpm/rocky/perl-Time-Local@1:1.280-1.el8?arch=noarch"); got != "perl-time-local" {
		t.Fatalf("rpmPackageName = %q", got)
	}
	if got := rpmInstalledVersion("pkg:rpm/rocky/openssl@1.1.1k-15.el8_10?arch=x86_64"); got != "1.1.1k-15.el8_10" {
		t.Fatalf("rpmInstalledVersion = %q", got)
	}
	if got := rpmInstalledVersion("pkg:rpm/rocky/openssl"); got != "" {
		t.Fatalf("versionless = %q", got)
	}
	// "@" present but the version segment is empty (qualifiers only).
	if got := rpmInstalledVersion("pkg:rpm/rocky/openssl@?arch=x86_64"); got != "" {
		t.Fatalf("empty version = %q", got)
	}
	// The epoch is carried as a purl qualifier and folded back into the EVR.
	if got := rpmInstalledVersion("pkg:rpm/rocky/libpng@1.6.34-10.el8_10?arch=x86_64&distro=rocky-8.9&epoch=2"); got != "2:1.6.34-10.el8_10" {
		t.Fatalf("epoch qualifier = %q, want 2:1.6.34-10.el8_10", got)
	}
	// An epoch already present in @version is not double-prefixed.
	if got := rpmInstalledVersion("pkg:rpm/rocky/openssl@0:1.1.1k-15.el8_10?epoch=9"); got != "0:1.1.1k-15.el8_10" {
		t.Fatalf("explicit epoch = %q, want 0:1.1.1k-15.el8_10", got)
	}
}

// TestRedHatVEXMinorStreamFalseResolutionRegression locks in the v0.3.6 fix for the
// libtiff CVE-2026-4775 false "resolved": Red Hat lists the el8 main-stream fix
// (release 37, el8_10) plus older minor-locked AUS/E4S backports (release 21/29).
// An el8_10 install at release 36 must resolve to AFFECTED against the main-stream
// 37 — not "fixed" against the trailing el8_8.2 backport (36 > 29). The libpng row
// additionally exercises the epoch-qualifier fix (epoch 2 install vs epoch 2 fix).
func TestRedHatVEXMinorStreamFalseResolutionRegression(t *testing.T) {
	rows := []domain.OpenRiskContextRow{
		// libtiff: no epoch anywhere; the dangerous case that surfaced as "resolved".
		rpmRow("art-1", "pkg:rpm/rocky/libtiff@4.0.9-36.el8_10?arch=x86_64&distro=rocky-8.9", "CVE-2026-4775"),
		// libpng: epoch carried as a purl qualifier; below the main-stream fix.
		rpmRow("art-1", "pkg:rpm/rocky/libpng@1.6.34-10.el8_10?arch=x86_64&distro=rocky-8.9&epoch=2", "CVE-2026-33416"),
	}
	reports := map[string]domain.RedHatCVEReport{
		"CVE-2026-4775": {CVEID: "CVE-2026-4775", ThreatSeverity: "Important", AffectedReleases: []domain.RedHatAffectedRelease{
			{PackageNEVRA: "libtiff-0:4.0.9-37.el8_10", CPE: "cpe:/a:redhat:enterprise_linux:8", Advisory: "RHSA-2026:16055"},
			{PackageNEVRA: "libtiff-0:4.0.9-21.el8_6.2", CPE: "cpe:/a:redhat:rhel_aus:8.6", Advisory: "RHSA-2026:19657"},
			{PackageNEVRA: "libtiff-0:4.0.9-29.el8_8.2", CPE: "cpe:/a:redhat:rhel_e4s:8.8", Advisory: "RHSA-2026:19604"},
		}},
		"CVE-2026-33416": {CVEID: "CVE-2026-33416", ThreatSeverity: "Moderate", AffectedReleases: []domain.RedHatAffectedRelease{
			{PackageNEVRA: "libpng-2:1.6.34-11.el8_10", CPE: "cpe:/o:redhat:enterprise_linux:8", Advisory: "RHSA-2026:29898"},
			{PackageNEVRA: "libpng-2:1.6.34-8.el8_8.3", CPE: "cpe:/o:redhat:rhel_e4s:8.8", Advisory: "RHSA-2026:29900"},
		}},
	}
	store := &stubAssertionWriter{}
	svc := &RedHatVEXService{Fetcher: &stubRHFetcher{reports: reports}, Findings: stubFindings{rows: rows}, Store: store}

	res, err := svc.RunCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Fixed != 0 {
		t.Fatalf("no finding may resolve to fixed, got %d", res.Fixed)
	}
	if res.Affected != 2 || len(store.got) != 2 {
		t.Fatalf("both must be affected: res=%+v assertions=%d", res, len(store.got))
	}
	byPkg := map[string]domain.VendorVEXAssertion{}
	for _, a := range store.got {
		byPkg[a.PackageName] = a
	}
	if a := byPkg["libtiff"]; a.Status != domain.VEXStatusAffected || a.Fixed != "0:4.0.9-37.el8_10" {
		t.Fatalf("libtiff must be affected vs the main-stream fix, got %+v", a)
	}
	if a := byPkg["libpng"]; a.Status != domain.VEXStatusAffected || a.Fixed != "2:1.6.34-11.el8_10" {
		t.Fatalf("libpng must be affected vs the main-stream fix, got %+v", a)
	}
}

func TestRedHatVEXConfigAndEdgeCases(t *testing.T) {
	now := time.Now()
	rows := []domain.OpenRiskContextRow{
		rpmRow("art-1", "pkg:rpm/rocky/ncurses@6.1-1.el8", "CVE-2022-29458"), // not_affected (Metrics nil → no-op)
		rpmRow("art-1", "pkg:rpm/foo@1.0", "CVE-NOSTREAM"),                   // rpm, no distro keyword → no el stream → no assertion
	}
	fetcher := &stubRHFetcher{reports: map[string]domain.RedHatCVEReport{
		"CVE-2022-29458": ncursesRHReport,
		"CVE-NOSTREAM": {CVEID: "CVE-NOSTREAM", PackageStates: []domain.RedHatPackageState{
			{PackageName: "foo", FixState: "Affected", CPE: "cpe:/o:redhat:enterprise_linux:8"}}},
	}}
	store := &stubAssertionWriter{}
	svc := &RedHatVEXService{
		Fetcher: fetcher, Findings: stubFindings{rows: rows}, Store: store,
		BatchLimit: 100, RetryAfter: time.Hour, Now: func() time.Time { return now }, // exercise configured (non-default) branches
	}
	if _, err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second cycle: both CVEs are within the configured 1h back-off → not re-fetched.
	if _, err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls["CVE-2022-29458"] != 1 {
		t.Fatalf("ncurses re-fetched %d times despite back-off", fetcher.calls["CVE-2022-29458"])
	}
	for _, a := range store.got {
		if a.CVEID == "CVE-NOSTREAM" {
			t.Fatal("stream-less rpm must not produce an assertion")
		}
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

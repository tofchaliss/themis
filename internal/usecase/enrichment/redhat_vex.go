package enrichment

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// Red Hat VEX overlay enrichment (Option B — on-demand Security Data API).
//
// The CSAF directory crawler never finds Red Hat's VEX (the repo serves year
// subdirectories with no top-level .json), so the overlay was always empty. This
// service is the Red Hat analogue of CVSSBackfillService: for each distinct
// RPM-family CVE in open findings it pulls the per-CVE document from
// access.redhat.com/hydra/rest/securitydata, resolves the verdict for the
// component's exact EL stream, and writes a VEX-overlay assertion (keyed to the
// finding's own PURL so the existing matcher applies it by exact match). A
// "Not affected" verdict surfaces as a visible, human-overridable overlay signal —
// Themis never auto-rescopes severity; the vendor rationale is carried in the
// justification so the analyst can confirm a likely back-port false positive.

const (
	defaultRedHatVEXBatchLimit = 500
	defaultRedHatVEXRetryAfter = 24 * time.Hour
	maxConsecutiveRedHatErrors = 8
)

// RedHatVerdictFetcher fetches one CVE's Red Hat verdict (implemented by adapter/redhat).
type RedHatVerdictFetcher interface {
	FetchCVE(ctx context.Context, cveID string) (domain.RedHatCVEReport, bool, error)
}

// OpenFindingLister lists open findings to enrich (implemented by the enrichment repo).
type OpenFindingLister interface {
	ListOpenRiskContexts(ctx context.Context, offset, limit int) ([]domain.OpenRiskContextRow, error)
}

// VEXAssertionWriter persists vendor VEX assertions (implemented by vexfeed.PostgresAssertionStore).
type VEXAssertionWriter interface {
	UpsertAssertions(ctx context.Context, feed string, assertions []domain.VendorVEXAssertion) (int, error)
}

// VEXOverlayReEnqueuer re-applies the overlay for the given artifacts.
type VEXOverlayReEnqueuer interface {
	EnqueueApplyVEXForSBOMs(ctx context.Context, ids []string) error
}

// RedHatVEXMetrics records per-CVE verdict outcomes.
type RedHatVEXMetrics interface {
	RecordVerdict(status string) // not_affected | fixed | affected | checked | error
}

// NoOpRedHatVEXMetrics ignores metrics.
type NoOpRedHatVEXMetrics struct{}

// RecordVerdict discards the metric.
func (NoOpRedHatVEXMetrics) RecordVerdict(string) {}

// RedHatVEXService applies Red Hat verdicts to open RPM findings as VEX overlay.
type RedHatVEXService struct {
	Fetcher    RedHatVerdictFetcher
	Findings   OpenFindingLister
	Store      VEXAssertionWriter
	ReEnrich   VEXOverlayReEnqueuer
	Metrics    RedHatVEXMetrics
	Logger     domain.Logger
	BatchLimit int
	RetryAfter time.Duration
	Now        func() time.Time

	mu      sync.Mutex
	checked map[string]time.Time // CVE → last fetch (in-memory back-off; resets on restart)
}

// RedHatVEXResult summarizes a cycle.
type RedHatVEXResult struct {
	CVEsChecked     int
	Assertions      int
	NotAffected     int
	Fixed           int
	Affected        int
	ArtifactsQueued int
}

// RunCycle pulls Red Hat verdicts for the open RPM findings, writes overlay
// assertions, and queues affected artifacts for overlay re-application.
func (s *RedHatVEXService) RunCycle(ctx context.Context) (RedHatVEXResult, error) {
	if s.Fetcher == nil || s.Findings == nil || s.Store == nil {
		return RedHatVEXResult{}, nil
	}
	log := domain.LoggerOrNop(s.Logger)
	metrics := s.metrics()

	rows, err := s.Findings.ListOpenRiskContexts(ctx, 0, s.batchLimit())
	if err != nil {
		return RedHatVEXResult{}, err
	}

	// Group the rpm findings by CVE so each CVE is fetched once per cycle.
	byCVE := map[string][]domain.OpenRiskContextRow{}
	var order []string
	for _, row := range rows {
		if !strings.HasPrefix(strings.ToLower(row.ComponentPURL), "pkg:rpm/") {
			continue
		}
		if _, ok := byCVE[row.CVEID]; !ok {
			order = append(order, row.CVEID)
		}
		byCVE[row.CVEID] = append(byCVE[row.CVEID], row)
	}

	var assertions []domain.VendorVEXAssertion
	artifactSet := map[string]struct{}{}
	result := RedHatVEXResult{}
	consecutiveErrors := 0
	aborted := false

	for _, cveID := range order {
		if s.recentlyChecked(cveID) {
			continue
		}
		report, found, fetchErr := s.Fetcher.FetchCVE(ctx, cveID)
		if fetchErr != nil {
			consecutiveErrors++
			metrics.RecordVerdict("error")
			log.Warn("redhat vex fetch failed", domain.LogString("cve_id", cveID), domain.LogErr(fetchErr))
			if consecutiveErrors >= maxConsecutiveRedHatErrors {
				aborted = true
				break
			}
			continue
		}
		consecutiveErrors = 0
		s.markChecked(cveID)
		result.CVEsChecked++
		if !found {
			metrics.RecordVerdict("checked")
			continue
		}
		for _, row := range byCVE[cveID] {
			assertion, kind, ok := s.buildAssertion(report, row)
			if !ok {
				continue
			}
			assertions = append(assertions, assertion)
			artifactSet[row.ArtifactID] = struct{}{}
			metrics.RecordVerdict(kind)
			switch kind {
			case domain.VEXStatusNotAffected:
				result.NotAffected++
			case domain.VEXStatusFixed:
				result.Fixed++
			default:
				result.Affected++
			}
		}
	}

	if len(assertions) > 0 {
		n, err := s.Store.UpsertAssertions(ctx, "redhat", assertions)
		if err != nil {
			return result, err
		}
		result.Assertions = n
		if s.ReEnrich != nil && len(artifactSet) > 0 {
			ids := make([]string, 0, len(artifactSet))
			for id := range artifactSet {
				ids = append(ids, id)
			}
			if err := s.ReEnrich.EnqueueApplyVEXForSBOMs(ctx, ids); err != nil {
				return result, err
			}
			result.ArtifactsQueued = len(ids)
		}
	}

	if aborted {
		return result, fmt.Errorf("redhat vex aborted after %d consecutive fetch failures", consecutiveErrors)
	}
	log.Info("redhat vex cycle completed",
		domain.LogInt("cves_checked", result.CVEsChecked),
		domain.LogInt("not_affected", result.NotAffected),
		domain.LogInt("fixed", result.Fixed),
		domain.LogInt("affected", result.Affected),
		domain.LogInt("artifacts_queued", result.ArtifactsQueued))
	return result, nil
}

// buildAssertion resolves the Red Hat verdict for one finding's exact EL stream
// and turns it into an overlay assertion keyed to the finding's PURL. Returns
// ok=false when Red Hat published no verdict for the component's stream.
func (s *RedHatVEXService) buildAssertion(report domain.RedHatCVEReport, row domain.OpenRiskContextRow) (domain.VendorVEXAssertion, string, bool) {
	pkg := rpmPackageName(row.ComponentPURL)
	stream := domain.RPMReleaseMajor(row.ComponentPURL)
	if pkg == "" || stream == "" {
		return domain.VendorVEXAssertion{}, "", false
	}
	verdict := report.VerdictForStream(pkg, stream)
	if !verdict.Covered {
		return domain.VendorVEXAssertion{}, "", false
	}

	status := domain.VEXStatusAffected
	switch {
	case verdict.NotAffected:
		status = domain.VEXStatusNotAffected
	case verdict.FixedEVR != "":
		installed := rpmInstalledVersion(row.ComponentPURL)
		if installed != "" && domain.CompareVersionsEco("rpm", installed, verdict.FixedEVR) >= 0 {
			status = domain.VEXStatusFixed
		}
	}

	return domain.VendorVEXAssertion{
		AdvisoryID:    "redhat:" + report.CVEID,
		Feed:          "redhat",
		CVEID:         report.CVEID,
		ComponentPURL: row.ComponentPURL,
		Status:        status,
		Justification: redHatJustification(report, verdict, stream),
		Fixed:         verdict.FixedEVR,
		Severity:      report.ThreatSeverity,
		Ecosystem:     "redhat",
		PackageName:   pkg,
	}, status, true
}

func (s *RedHatVEXService) recentlyChecked(cveID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.checked[cveID]
	if !ok {
		return false
	}
	return s.now().Sub(last) < s.retryAfter()
}

func (s *RedHatVEXService) markChecked(cveID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checked == nil {
		s.checked = map[string]time.Time{}
	}
	s.checked[cveID] = s.now()
}

func (s *RedHatVEXService) metrics() RedHatVEXMetrics {
	if s.Metrics == nil {
		return NoOpRedHatVEXMetrics{}
	}
	return s.Metrics
}

func (s *RedHatVEXService) batchLimit() int {
	if s.BatchLimit <= 0 {
		return defaultRedHatVEXBatchLimit
	}
	return s.BatchLimit
}

func (s *RedHatVEXService) retryAfter() time.Duration {
	if s.RetryAfter <= 0 {
		return defaultRedHatVEXRetryAfter
	}
	return s.RetryAfter
}

func (s *RedHatVEXService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// redHatJustification renders the vendor verdict as human-readable triage context
// (visible in the overlay) so an analyst can confirm a likely back-port false
// positive — Themis never auto-suppresses without the reasoning attached.
func redHatJustification(report domain.RedHatCVEReport, verdict domain.RedHatStreamVerdict, stream string) string {
	var b strings.Builder
	b.WriteString("Red Hat: ")
	if verdict.FixState != "" {
		b.WriteString(verdict.FixState)
	} else if verdict.FixedEVR != "" {
		b.WriteString("Affected")
	}
	b.WriteString(" on RHEL-" + stream)
	if verdict.FixedEVR != "" {
		b.WriteString(", fixed in " + verdict.FixedEVR)
		if verdict.Advisory != "" {
			b.WriteString(" (" + verdict.Advisory + ")")
		}
	}
	if report.ThreatSeverity != "" {
		b.WriteString("; threat severity: " + report.ThreatSeverity)
	}
	if report.Statement != "" {
		b.WriteString(". " + report.Statement)
	}
	return b.String()
}

// rpmPackageName extracts the bare package name from an rpm PURL:
// "pkg:rpm/rocky/openssl@1.1.1k-15.el8_10?arch=x86_64" → "openssl".
func rpmPackageName(purl string) string {
	rest := strings.TrimPrefix(strings.ToLower(purl), "pkg:rpm/")
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}

// rpmInstalledVersion extracts the version segment from an rpm PURL:
// "pkg:rpm/rocky/openssl@1.1.1k-15.el8_10?arch=x86_64" → "1.1.1k-15.el8_10".
func rpmInstalledVersion(purl string) string {
	at := strings.Index(purl, "@")
	if at < 0 {
		return ""
	}
	v := purl[at+1:]
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	return v
}

package watch

import (
	"context"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const cycleStatusSuccess = "success"
const cycleStatusFailure = "failure"

// Service orchestrates CVE feed polling and catalog matching.
type Service struct {
	NVD     domain.NVDCVEFeedClient
	OSV     domain.OSVCVEFeedClient
	Repo    domain.WatchRepository
	Notify  domain.NotificationSender
	Metrics domain.WatchMetricsRecorder
	// Correlator (CR-2) re-correlates each catalog component through the shared
	// CorrelationSource core (the in-memory distro index), so periodic watch picks
	// up distro findings via the same engine ingest uses. Optional; nil skips it.
	Correlator domain.VulnerabilityFetcher
	Clock      func() time.Time
	OnSuccess  func(time.Time)
}

// RunCycle fetches CVEs, matches the catalog, creates findings, and updates poll state.
func (s *Service) RunCycle(ctx context.Context) error {
	start := s.now()
	status := cycleStatusFailure
	defer func() {
		if s.Metrics != nil {
			s.Metrics.RecordCycle(status, time.Since(start))
		}
	}()

	since, err := s.Repo.GetLastSuccessTimestamp(ctx)
	if err != nil {
		return fmt.Errorf("get last success timestamp: %w", err)
	}

	catalog, err := s.Repo.ListWatchCatalog(ctx)
	if err != nil {
		return fmt.Errorf("list watch catalog: %w", err)
	}

	feedVulns, err := s.fetchVulnerabilities(ctx, since)
	if err != nil {
		return err
	}

	for i, vuln := range feedVulns {
		record := feedToRecord(vuln)
		id, upsertErr := s.Repo.UpsertVulnerability(ctx, record)
		if upsertErr != nil {
			return fmt.Errorf("upsert vulnerability %s: %w", vuln.CVEID, upsertErr)
		}
		feedVulns[i].CVEID = record.CVEID
		_ = id
	}

	var osvVulns []domain.FeedVulnerability
	if s.OSV != nil && len(catalog) > 0 {
		osvVulns, err = s.fetchFromOSV(ctx)
		if err != nil {
			return err
		}
		for _, vuln := range osvVulns {
			if _, upsertErr := s.Repo.UpsertVulnerability(ctx, feedToRecord(vuln)); upsertErr != nil {
				return fmt.Errorf("upsert osv vulnerability %s: %w", vuln.CVEID, upsertErr)
			}
		}
	}

	stored, err := s.Repo.ListVulnerabilityRecords(ctx)
	if err != nil {
		return fmt.Errorf("list stored vulnerabilities: %w", err)
	}

	matchVulns := mergeFeedVulnerabilities(feedVulns, osvVulns, recordsToFeed(stored))

	newByEcosystem := make(map[string]int)
	batchKey := "cve-watch-" + s.now().Format(time.RFC3339)
	for _, pair := range MatchCatalog(catalog, matchVulns) {
		if err := s.createWatchFinding(ctx, pair.Entry, pair.Vuln, batchKey, newByEcosystem); err != nil {
			return err
		}
	}

	// CR-2: re-correlate each catalog component through the shared Correlator so
	// the periodic watch also surfaces distro-index findings (deduped by HasFinding).
	if s.Correlator != nil {
		for _, entry := range catalog {
			records, corrErr := s.Correlator.FetchForComponent(ctx, domain.CanonicalComponent{
				PURL:      entry.PURL,
				Name:      entry.Name,
				Version:   entry.Version,
				Ecosystem: entry.Ecosystem,
			})
			if corrErr != nil {
				return fmt.Errorf("correlate watch component %s: %w", entry.PURL, corrErr)
			}
			for _, rec := range records {
				if err := s.createWatchFinding(ctx, entry, feedFromRecord(rec), batchKey, newByEcosystem); err != nil {
					return err
				}
			}
		}
	}

	if s.Notify != nil {
		_ = s.Notify.FlushDigest(ctx, batchKey)
	}

	if s.Metrics != nil {
		for ecosystem, count := range newByEcosystem {
			s.Metrics.RecordNewFindings(ecosystem, count)
		}
	}

	now := s.now()
	if err := s.Repo.SetLastSuccessTimestamp(ctx, now); err != nil {
		return fmt.Errorf("set last success timestamp: %w", err)
	}
	if s.OnSuccess != nil {
		s.OnSuccess(now)
	}
	status = cycleStatusSuccess
	return nil
}

// createWatchFinding upserts the matched vulnerability and creates a watch
// finding for it (deduped via HasFinding), recording provenance and notifying.
// Shared by the bulk MatchCatalog pass and the CR-2 Correlator pass.
func (s *Service) createWatchFinding(ctx context.Context, entry domain.WatchCatalogEntry, vuln domain.FeedVulnerability, batchKey string, newByEcosystem map[string]int) error {
	vulnID, err := s.Repo.UpsertVulnerability(ctx, feedToRecord(vuln))
	if err != nil {
		return fmt.Errorf("upsert matched vulnerability %s: %w", vuln.CVEID, err)
	}
	exists, err := s.Repo.HasFinding(ctx, entry.ComponentVersionID, vuln.CVEID)
	if err != nil {
		return fmt.Errorf("check existing finding: %w", err)
	}
	if exists {
		return nil
	}
	result, err := s.Repo.CreateWatchFinding(ctx, domain.CreateWatchFindingInput{
		ComponentVersionID: entry.ComponentVersionID,
		VulnerabilityID:    vulnID,
		ScanReportID:       entry.ScanReportID,
		ArtifactID:         entry.ArtifactID,
		CVEID:              vuln.CVEID,
		Severity:           vuln.Severity,
		ProductID:          entry.ProductID,
		ProjectID:          entry.ProjectID,
		ComponentPURL:      domain.VersionedPURL(entry.PURL, entry.Version),
		Source:             domain.DefaultFindingSource(vuln.Source),
		SourceCVSSScore:    vuln.CVSSScore,
		SourceCVSSVector:   vuln.CVSSVector,
		SourceFixedVersion: firstFixVersion(vuln.FixVersions),
	})
	if err != nil {
		return fmt.Errorf("create watch finding: %w", err)
	}
	if !result.Created {
		return nil
	}
	newByEcosystem[entry.Ecosystem]++
	if s.Notify != nil {
		_ = s.Notify.Dispatch(ctx, domain.NotificationEvent{
			Type:      domain.NotificationEventCVEWatchFinding,
			ProductID: entry.ProductID,
			ProjectID: entry.ProjectID,
			BatchKey:  batchKey,
			Findings: []domain.NotificationFinding{{
				CVEID:          vuln.CVEID,
				ComponentPURL:  entry.PURL,
				Severity:       vuln.Severity,
				EffectiveState: domain.EffectiveStateDetected,
			}},
		})
	}
	return nil
}

func (s *Service) fetchVulnerabilities(ctx context.Context, since time.Time) ([]domain.FeedVulnerability, error) {
	if s.NVD != nil {
		vulns, err := s.NVD.FetchModifiedSince(ctx, since)
		if err == nil {
			return vulns, nil
		}
		if s.OSV == nil {
			return nil, fmt.Errorf("nvd fetch failed: %w", err)
		}
		return s.fetchFromOSV(ctx)
	}
	if s.OSV != nil {
		return s.fetchFromOSV(ctx)
	}
	return nil, fmt.Errorf("no CVE feed client configured")
}

func (s *Service) fetchFromOSV(ctx context.Context) ([]domain.FeedVulnerability, error) {
	catalog, err := s.Repo.ListWatchCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("list catalog for osv fallback: %w", err)
	}
	grouped := GroupByEcosystem(catalog)
	var out []domain.FeedVulnerability
	for ecosystem, entries := range grouped {
		packages := UniquePackageNames(entries)
		if len(packages) == 0 {
			continue
		}
		vulns, queryErr := s.OSV.QueryByEcosystem(ctx, ecosystem, packages)
		if queryErr != nil {
			return nil, fmt.Errorf("osv query %s: %w", ecosystem, queryErr)
		}
		out = append(out, vulns...)
	}
	return out, nil
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

func feedToRecord(vuln domain.FeedVulnerability) domain.VulnerabilityRecord {
	affected := vuln.AffectedVersions
	if affected == nil {
		affected = []string{}
	}
	fixes := vuln.FixVersions
	if fixes == nil {
		fixes = []string{}
	}
	return domain.VulnerabilityRecord{
		CVEID:            vuln.CVEID,
		Severity:         vuln.Severity,
		CVSSScore:        vuln.CVSSScore,
		CVSSVector:       vuln.CVSSVector,
		Ecosystem:        vuln.Ecosystem,
		PackageName:      vuln.PackageName,
		AffectedVersions: affected,
		FixVersions:      fixes,
		Source:           vuln.Source,
	}
}

func firstFixVersion(fixes []string) string {
	if len(fixes) > 0 {
		return fixes[0]
	}
	return ""
}

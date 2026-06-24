package watch

import "github.com/themis-project/themis/internal/domain"

// feedFromRecord converts a single correlated record (from the Correlator) into a
// feed vulnerability for watch finding creation, carrying provenance (CR-2/CR-3).
func feedFromRecord(record domain.VulnerabilityRecord) domain.FeedVulnerability {
	return domain.FeedVulnerability{
		CVEID:            record.CVEID,
		Severity:         record.Severity,
		CVSSScore:        record.CVSSScore,
		CVSSVector:       record.CVSSVector,
		Ecosystem:        record.Ecosystem,
		PackageName:      record.PackageName,
		AffectedVersions: record.AffectedVersions,
		FixVersions:      record.FixVersions,
		Source:           record.Source,
	}
}

func recordsToFeed(records []domain.VulnerabilityRecord) []domain.FeedVulnerability {
	out := make([]domain.FeedVulnerability, 0, len(records))
	for _, record := range records {
		out = append(out, domain.FeedVulnerability{
			CVEID:            record.CVEID,
			Severity:         record.Severity,
			CVSSScore:        record.CVSSScore,
			CVSSVector:       record.CVSSVector,
			Ecosystem:        record.Ecosystem,
			PackageName:      record.PackageName,
			AffectedVersions: record.AffectedVersions,
			FixVersions:      record.FixVersions,
			Source:           record.Source,
		})
	}
	return out
}

// mergeFeedVulnerabilities de-duplicates feed records by (cve, ecosystem, package),
// keeping the higher-precedence source on a collision (CR-3 distro-authoritative
// merge) rather than blindly keeping whichever group was iterated first.
func mergeFeedVulnerabilities(groups ...[]domain.FeedVulnerability) []domain.FeedVulnerability {
	index := make(map[string]int)
	var out []domain.FeedVulnerability
	for _, group := range groups {
		for _, vuln := range group {
			key := vuln.CVEID + "|" + vuln.Ecosystem + "|" + vuln.PackageName
			if pos, ok := index[key]; ok {
				existing := out[pos]
				if domain.FindingSourcePrecedence(vuln.Ecosystem, vuln.Source) >
					domain.FindingSourcePrecedence(existing.Ecosystem, existing.Source) {
					out[pos] = vuln
				}
				continue
			}
			index[key] = len(out)
			out = append(out, vuln)
		}
	}
	return out
}

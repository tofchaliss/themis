package watch

import "github.com/themis-project/themis/internal/domain"

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
		})
	}
	return out
}

func mergeFeedVulnerabilities(groups ...[]domain.FeedVulnerability) []domain.FeedVulnerability {
	seen := make(map[string]struct{})
	var out []domain.FeedVulnerability
	for _, group := range groups {
		for _, vuln := range group {
			key := vuln.CVEID + "|" + vuln.Ecosystem + "|" + vuln.PackageName
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, vuln)
		}
	}
	return out
}

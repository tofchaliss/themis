package watch

import "github.com/themis-project/themis/internal/domain"

// VersionMatches reports whether version falls within affected version constraints.
func VersionMatches(affected []string, version string) bool {
	return domain.VersionMatches(affected, version)
}

// PackageMatches reports whether a feed vulnerability applies to a catalog entry.
func PackageMatches(vuln domain.FeedVulnerability, entry domain.WatchCatalogEntry) bool {
	return domain.PackageIdentityMatch(vuln.Ecosystem, vuln.PackageName, entry.Ecosystem, entry.Name) &&
		domain.VersionMatchesEco(entry.Ecosystem, vuln.AffectedVersions, entry.Version)
}

// GroupByEcosystem batches catalog entries by ecosystem.
func GroupByEcosystem(entries []domain.WatchCatalogEntry) map[string][]domain.WatchCatalogEntry {
	grouped := make(map[string][]domain.WatchCatalogEntry)
	for _, entry := range entries {
		grouped[entry.Ecosystem] = append(grouped[entry.Ecosystem], entry)
	}
	return grouped
}

// UniquePackageNames returns deduplicated package names for an ecosystem group.
func UniquePackageNames(entries []domain.WatchCatalogEntry) []domain.OSVPackageQuery {
	seen := make(map[string]struct{}, len(entries))
	out := make([]domain.OSVPackageQuery, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		if _, ok := seen[entry.Name]; ok {
			continue
		}
		seen[entry.Name] = struct{}{}
		out = append(out, domain.OSVPackageQuery{Name: entry.Name})
	}
	return out
}

// MatchCatalog returns catalog entries affected by the supplied vulnerabilities.
func MatchCatalog(entries []domain.WatchCatalogEntry, vulns []domain.FeedVulnerability) []matchedPair {
	var pairs []matchedPair
	for _, entry := range entries {
		for _, vuln := range vulns {
			if PackageMatches(vuln, entry) {
				pairs = append(pairs, matchedPair{Entry: entry, Vuln: vuln})
			}
		}
	}
	return pairs
}

type matchedPair struct {
	Entry domain.WatchCatalogEntry
	Vuln  domain.FeedVulnerability
}

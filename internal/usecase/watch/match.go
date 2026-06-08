package watch

import (
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// VersionMatches reports whether version falls within affected version constraints.
// Empty affected means unknown range (match all). Supports exact, wildcard, and
// simple comparator prefixes (<, <=, >, >=).
func VersionMatches(affected []string, version string) bool {
	if len(affected) == 0 {
		return true
	}
	for _, candidate := range affected {
		candidate = strings.TrimSpace(candidate)
		switch {
		case candidate == version, candidate == "*":
			return true
		case strings.HasPrefix(candidate, "<="):
			if compareVersions(version, strings.TrimSpace(candidate[2:])) <= 0 {
				return true
			}
		case strings.HasPrefix(candidate, "<"):
			if compareVersions(version, strings.TrimSpace(candidate[1:])) < 0 {
				return true
			}
		case strings.HasPrefix(candidate, ">="):
			if compareVersions(version, strings.TrimSpace(candidate[2:])) >= 0 {
				return true
			}
		case strings.HasPrefix(candidate, ">"):
			if compareVersions(version, strings.TrimSpace(candidate[1:])) > 0 {
				return true
			}
		}
	}
	return false
}

func compareVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	maxLen := len(leftParts)
	if len(rightParts) > maxLen {
		maxLen = len(rightParts)
	}
	for i := 0; i < maxLen; i++ {
		var lPart, rPart string
		if i < len(leftParts) {
			lPart = leftParts[i]
		}
		if i < len(rightParts) {
			rPart = rightParts[i]
		}
		if lPart == rPart {
			continue
		}
		if lPart == "" {
			return -1
		}
		if rPart == "" {
			return 1
		}
		if lPart < rPart {
			return -1
		}
		return 1
	}
	return 0
}

// PackageMatches reports whether a feed vulnerability applies to a catalog entry.
func PackageMatches(vuln domain.FeedVulnerability, entry domain.WatchCatalogEntry) bool {
	if vuln.PackageName != entry.Name {
		return false
	}
	if vuln.Ecosystem != "" && vuln.Ecosystem != entry.Ecosystem {
		return false
	}
	return VersionMatches(vuln.AffectedVersions, entry.Version)
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

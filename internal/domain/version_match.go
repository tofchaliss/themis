package domain

import "strings"

// NormalizeEcosystem maps feed and PURL ecosystem names to a canonical lowercase key.
func NormalizeEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "golang":
		return "go"
	case "python":
		return "pypi"
	case "nuget":
		return "nuget"
	default:
		return strings.ToLower(strings.TrimSpace(ecosystem))
	}
}

// PackageIdentityMatch reports whether a CVE record applies to a component package name.
func PackageIdentityMatch(recordEcosystem, recordName, componentEcosystem, componentName string) bool {
	recEco := NormalizeEcosystem(recordEcosystem)
	compEco := NormalizeEcosystem(componentEcosystem)
	if recEco != "" && compEco != "" && recEco != compEco {
		return false
	}
	recName := strings.ToLower(strings.TrimSpace(recordName))
	compName := strings.ToLower(strings.TrimSpace(componentName))
	if recName == "" || compName == "" {
		return false
	}
	if recName == compName {
		return true
	}
	// Maven PURLs often use group:artifact while feeds may store artifact only.
	if strings.HasSuffix(compName, ":"+recName) {
		return true
	}
	if strings.HasSuffix(recName, ":"+compName) {
		return true
	}
	return false
}

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
		case candidate == version, candidate == "*", candidate == "unknown":
			return true
		case strings.HasPrefix(candidate, "<="):
			if CompareVersions(version, strings.TrimSpace(candidate[2:])) <= 0 {
				return true
			}
		case strings.HasPrefix(candidate, "<"):
			if CompareVersions(version, strings.TrimSpace(candidate[1:])) < 0 {
				return true
			}
		case strings.HasPrefix(candidate, ">="):
			if CompareVersions(version, strings.TrimSpace(candidate[2:])) >= 0 {
				return true
			}
		case strings.HasPrefix(candidate, ">"):
			if CompareVersions(version, strings.TrimSpace(candidate[1:])) > 0 {
				return true
			}
		}
	}
	return false
}

// CompareVersions compares dotted version strings lexicographically by segment.
func CompareVersions(left, right string) int {
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

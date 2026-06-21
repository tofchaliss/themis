package domain

import "strings"

// VersionedPURL returns the version-qualified PURL used as the stable finding
// identity (D11), reconstructed from a versionless PURL and a version — e.g.
// VersionedPURL("pkg:apk/busybox", "1.36") = "pkg:apk/busybox@1.36".
//
// It is idempotent: if the PURL already carries a version (a literal "@", as real
// CycloneDX/Syft/Trivy purls do — scoped npm namespaces are %40-encoded so this
// is unambiguous) it is returned unchanged. Appending a second "@version" would
// produce a malformed identity like "pkg:apk/curl@1?arch=x@1" that breaks PURL
// parsing in the vendor-VEX matcher. An empty version also yields the PURL as-is.
func VersionedPURL(purl, version string) string {
	if version == "" || strings.Contains(purl, "@") {
		return purl
	}
	return purl + "@" + version
}

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

// VersionMatches reports whether version satisfies the affected constraints.
//
// Each element of affected is a constraint GROUP. A version matches a group only
// if it satisfies EVERY comparator in that group (AND); it matches the whole set
// if it satisfies ANY group (OR). A group carries the bounds of a single affected
// range joined by commas, e.g. ">= 1.0.0, < 2.0.0" matches the half-open interval
// [1.0.0, 2.0.0). This AND-within / OR-across split is what stops a range's lower
// and upper bounds from being satisfied independently — the historical over-match
// bug where ">= 1.0.0" alone matched every newer version (a curl 8.x picking up a
// 2014 CVE fixed in 7.36).
//
// Empty affected means "no version information" and matches all versions. The
// sentinels "*"/"unknown" also match all; "none" matches nothing (emitted when a
// range is present but yields no usable bound, so a parse gap fails closed rather
// than claiming every version is affected).
func VersionMatches(affected []string, version string) bool {
	if len(affected) == 0 {
		return true
	}
	for _, group := range affected {
		if matchConstraintGroup(group, version) {
			return true
		}
	}
	return false
}

func matchConstraintGroup(group, version string) bool {
	matched := false
	for _, raw := range strings.Split(group, ",") {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		if !matchConstraint(candidate, version) {
			return false
		}
		matched = true
	}
	return matched
}

// matchConstraint evaluates a single comparator, exact version, or wildcard.
func matchConstraint(candidate, version string) bool {
	switch {
	case candidate == "none":
		return false
	case candidate == "*", candidate == "unknown", candidate == version:
		return true
	case strings.HasPrefix(candidate, "<="):
		return CompareVersions(version, strings.TrimSpace(candidate[2:])) <= 0
	case strings.HasPrefix(candidate, ">="):
		return CompareVersions(version, strings.TrimSpace(candidate[2:])) >= 0
	case strings.HasPrefix(candidate, "<"):
		return CompareVersions(version, strings.TrimSpace(candidate[1:])) < 0
	case strings.HasPrefix(candidate, ">"):
		return CompareVersions(version, strings.TrimSpace(candidate[1:])) > 0
	default:
		return false
	}
}

// CompareVersions compares two version strings with numeric-aware ordering and
// returns -1, 0, or 1. It follows the well-known rpmvercmp approach: each string
// is split into alternating runs of digits and letters (separators are skipped),
// numeric runs compare as integers (leading zeros ignored, the longer run wins),
// and a numeric run outranks a letter run at the same position. This fixes the
// two ways a naive lexical compare went wrong: multi-digit segments (8.14.1 is
// now correctly greater than 8.9.0, not less) and Alpine apk "-rN" revision
// suffixes. It does not model apk pre-release suffixes (_alpha/_rc) or epochs.
func CompareVersions(left, right string) int {
	for left != "" && right != "" {
		left = trimVersionSeparators(left)
		right = trimVersionSeparators(right)
		if left == "" || right == "" {
			break
		}
		lNumeric := isVersionDigit(left[0])
		rNumeric := isVersionDigit(right[0])
		if lNumeric != rNumeric {
			// A numeric segment is newer than an alphabetic one.
			if lNumeric {
				return 1
			}
			return -1
		}
		var lSeg, rSeg string
		if lNumeric {
			lSeg, left = takeVersionRun(left, isVersionDigit)
			rSeg, right = takeVersionRun(right, isVersionDigit)
			lSeg = strings.TrimLeft(lSeg, "0")
			rSeg = strings.TrimLeft(rSeg, "0")
			if len(lSeg) != len(rSeg) {
				if len(lSeg) > len(rSeg) {
					return 1
				}
				return -1
			}
		} else {
			lSeg, left = takeVersionRun(left, isVersionLetter)
			rSeg, right = takeVersionRun(right, isVersionLetter)
		}
		if lSeg != rSeg {
			if lSeg < rSeg {
				return -1
			}
			return 1
		}
	}
	left = trimVersionSeparators(left)
	right = trimVersionSeparators(right)
	switch {
	case left == "" && right == "":
		return 0
	case left == "":
		return -1
	default:
		return 1
	}
}

func trimVersionSeparators(s string) string {
	for s != "" && !isVersionDigit(s[0]) && !isVersionLetter(s[0]) {
		s = s[1:]
	}
	return s
}

func takeVersionRun(s string, pred func(byte) bool) (string, string) {
	i := 0
	for i < len(s) && pred(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func isVersionDigit(b byte) bool  { return b >= '0' && b <= '9' }
func isVersionLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

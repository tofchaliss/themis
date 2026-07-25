package value

import (
	"strconv"
	"strings"
)

// VersionClass is the comparison family an ecosystem's versions belong to.
//
// Version ordering is not universal: Alpine apk (with -rN build revisions) and the
// RPM family (epoch:version-release, with the "~" pre-release marker) order versions
// by their own rules, while everything else uses a generic rpmvercmp-style
// numeric-aware ordering. This engine is ported by design from the frozen v0.3.x PoC
// version engine (internal/domain/version_engine.go + version_match.go): the PoC is
// reference only and is never imported; the logic — and its rapid property tests — is
// re-homed here as a shared-kernel value object so Knowledge correlation and the
// Intelligence Rule Engine share one comparator.
type VersionClass string

const (
	// VersionClassAPK uses Alpine apk segment ordering (with -rN build revisions).
	VersionClassAPK VersionClass = "apk"
	// VersionClassRPM uses RPM epoch:version-release ordering (with ~ pre-release).
	VersionClassRPM VersionClass = "rpm"
	// VersionClassGeneric uses rpmvercmp-style numeric-aware ordering.
	VersionClassGeneric VersionClass = "generic"
)

// NormalizeEcosystem maps feed and PURL ecosystem names to a canonical lowercase key.
func NormalizeEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "golang":
		return "go"
	case "python":
		return "pypi"
	default:
		return strings.ToLower(strings.TrimSpace(ecosystem))
	}
}

// ClassifyEcosystem maps an ecosystem (PURL type or feed ecosystem name) to its
// version comparison class. Distro families that share rpm ordering — Red Hat,
// Rocky, Alma, CentOS, Fedora — all map to rpm; Alpine/apk/Wolfi maps to apk.
func ClassifyEcosystem(ecosystem string) VersionClass {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	switch eco {
	case "apk", "alpine", "wolfi", "chainguard":
		return VersionClassAPK
	case "rpm", "redhat", "rhel", "rocky", "rocky linux", "almalinux", "alma", "centos", "fedora":
		return VersionClassRPM
	}
	// OSV/feed names occasionally arrive with suffixes ("Rocky Linux 9").
	switch {
	case strings.Contains(eco, "alpine"), strings.Contains(eco, "wolfi"):
		return VersionClassAPK
	case strings.Contains(eco, "rocky"), strings.Contains(eco, "redhat"),
		strings.Contains(eco, "red hat"), strings.Contains(eco, "alma"),
		strings.Contains(eco, "centos"), strings.Contains(eco, "fedora"),
		strings.Contains(eco, "rhel"):
		return VersionClassRPM
	default:
		return VersionClassGeneric
	}
}

// CompareVersions compares left and right using the ordering rules of the given
// ecosystem and returns -1, 0, or 1. An empty (or generic) ecosystem uses the
// generic numeric-aware comparator; it is the single comparator every range check
// calls, so apk (-rN) and rpm (epoch/release/~) versions order by their own rules
// on every path.
func CompareVersions(ecosystem, left, right string) int {
	switch ClassifyEcosystem(ecosystem) {
	case VersionClassAPK:
		return compareAPKVersion(left, right)
	case VersionClassRPM:
		return compareRPMVersion(left, right)
	default:
		return compareGeneric(left, right)
	}
}

// AffectedRange is the canonical affected-version model: a list of AND groups
// (comma-joined comparators) matched OR-across-groups, carrying the ecosystem so
// comparison uses the right ordering rules. A group such as ">= 2.0, < 2.5" is kept
// as ONE group so both bounds must hold together — the AND-within/OR-across split
// that stops a range's lower and upper bounds from being satisfied independently
// (the historical over-match where ">= 1.0" alone matched every newer version).
type AffectedRange struct {
	Ecosystem string
	Groups    []string
}

// Matches reports whether version satisfies the affected range (any group). An empty
// group list means "no version information" and matches all versions; the sentinels
// "*"/"unknown" also match all; "none" matches nothing (emitted when a range is
// present but yields no usable bound, so a parse gap fails closed).
func (r AffectedRange) Matches(version string) bool {
	if len(r.Groups) == 0 {
		return true
	}
	for _, group := range r.Groups {
		if matchConstraintGroup(r.Ecosystem, group, version) {
			return true
		}
	}
	return false
}

// RangeVerdict is the three-state result of checking an installed version against an
// AffectedRange. It is certain in only the two comparable directions; when the inputs
// are insufficient to decide (no usable range, or an empty version) it is
// RangeUndecidable so callers defer rather than assume. The Intelligence Rule Engine
// short-circuits to "not affected" only on RangeOutOfRange.
type RangeVerdict int

const (
	// RangeUndecidable — not enough information to decide (defer to judgment).
	RangeUndecidable RangeVerdict = iota
	// RangeOutOfRange — the installed version is provably outside the affected range.
	RangeOutOfRange
	// RangeInRange — the installed version falls within the affected range.
	RangeInRange
)

// String returns the verdict label.
func (v RangeVerdict) String() string {
	switch v {
	case RangeOutOfRange:
		return "out_of_range"
	case RangeInRange:
		return "in_range"
	default:
		return "undecidable"
	}
}

// Applicability reports whether installedVersion falls within r. It is deliberately
// certain in only the two comparable directions: with a usable range and a non-empty
// version it returns RangeInRange or RangeOutOfRange; with no usable range or an
// empty version it returns RangeUndecidable, so the caller defers (e.g. to human/LLM
// judgment) rather than assuming a version is unaffected on a parse gap.
func (r AffectedRange) Applicability(installedVersion string) RangeVerdict {
	v := StripVersionQualifiers(strings.TrimSpace(installedVersion))
	if v == "" || !r.hasUsableConstraint() {
		return RangeUndecidable
	}
	if r.Matches(v) {
		return RangeInRange
	}
	return RangeOutOfRange
}

// hasUsableConstraint reports whether any group carries at least one real comparator
// (anything other than an empty token or the "none" sentinel). An all-"none"/empty
// range is a parse gap, not a decidable "outside the range".
func (r AffectedRange) hasUsableConstraint() bool {
	for _, group := range r.Groups {
		for _, raw := range strings.Split(group, ",") {
			if c := strings.TrimSpace(raw); c != "" && c != "none" {
				return true
			}
		}
	}
	return false
}

// BuildConstraintGroup composes a single AND constraint group from optional range
// bounds (inclusive/exclusive lower, inclusive/exclusive upper). Empty bounds and the
// "0" sentinel lower bound are skipped. The result is a comma-joined group such as
// ">= 2.0, < 2.5" — kept as ONE group so both bounds must hold together. Returns ""
// when no usable bound is present.
func BuildConstraintGroup(lowerIncl, lowerExcl, upperIncl, upperExcl string) string {
	var parts []string
	if v := strings.TrimSpace(lowerIncl); v != "" && v != "0" {
		parts = append(parts, ">= "+v)
	}
	if v := strings.TrimSpace(lowerExcl); v != "" && v != "0" {
		parts = append(parts, "> "+v)
	}
	if v := strings.TrimSpace(upperIncl); v != "" {
		parts = append(parts, "<= "+v)
	}
	if v := strings.TrimSpace(upperExcl); v != "" {
		parts = append(parts, "< "+v)
	}
	return strings.Join(parts, ", ")
}

// StripVersionQualifiers removes the PURL qualifier (?key=val) and subpath (#path)
// that real SBOM purls append after the version — e.g.
// "8.14.1-r2?arch=x86_64&distro=3.20.2" → "8.14.1-r2" — so version comparison never
// trips on qualifiers.
func StripVersionQualifiers(version string) string {
	if i := strings.IndexAny(version, "?#"); i >= 0 {
		return version[:i]
	}
	return version
}

func matchConstraintGroup(ecosystem, group, version string) bool {
	matched := false
	for _, raw := range strings.Split(group, ",") {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		if !matchConstraint(ecosystem, candidate, version) {
			return false
		}
		matched = true
	}
	return matched
}

// matchConstraint evaluates a single comparator, exact version, or wildcard.
func matchConstraint(ecosystem, candidate, version string) bool {
	switch {
	case candidate == "none":
		return false
	case candidate == "*", candidate == "unknown", candidate == version:
		return true
	case strings.HasPrefix(candidate, "<="):
		return CompareVersions(ecosystem, version, strings.TrimSpace(candidate[2:])) <= 0
	case strings.HasPrefix(candidate, ">="):
		return CompareVersions(ecosystem, version, strings.TrimSpace(candidate[2:])) >= 0
	case strings.HasPrefix(candidate, "<"):
		return CompareVersions(ecosystem, version, strings.TrimSpace(candidate[1:])) < 0
	case strings.HasPrefix(candidate, ">"):
		return CompareVersions(ecosystem, version, strings.TrimSpace(candidate[1:])) > 0
	default:
		return false
	}
}

// --- generic (rpmvercmp-style) ordering --------------------------------------

func compareGeneric(left, right string) int {
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

// --- apk (Alpine) ordering ---------------------------------------------------

func compareAPKVersion(a, b string) int {
	aParts := splitAPKParts(a)
	bParts := splitAPKParts(b)
	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if cmp := compareAPKSegment(av, bv); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func splitAPKParts(version string) []string {
	var parts []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			parts = append(parts, current.String())
			current.Reset()
		}
	}
	for _, ch := range version {
		if ch == '.' || ch == '-' || ch == '_' {
			flush()
			continue
		}
		current.WriteRune(ch)
	}
	flush()
	return parts
}

func compareAPKSegment(a, b string) int {
	if a == b {
		return 0
	}
	ai, aErr := strconv.Atoi(a)
	bi, bErr := strconv.Atoi(b)
	if aErr == nil && bErr == nil {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a, b)
}

// --- rpm (epoch:version-release) ordering ------------------------------------

func compareRPMVersion(a, b string) int {
	aEpoch, aRest := splitRPMEpoch(a)
	bEpoch, bRest := splitRPMEpoch(b)
	if aEpoch != bEpoch {
		if aEpoch < bEpoch {
			return -1
		}
		return 1
	}
	aVer, aRel := splitRPMVersionRelease(aRest)
	bVer, bRel := splitRPMVersionRelease(bRest)
	if cmp := rpmvercmp(aVer, bVer); cmp != 0 {
		return cmp
	}
	return rpmvercmp(aRel, bRel)
}

func splitRPMEpoch(version string) (epoch int, rest string) {
	colon := strings.Index(version, ":")
	if colon < 0 {
		return 0, version
	}
	ep, err := strconv.Atoi(version[:colon])
	if err != nil {
		return 0, version
	}
	return ep, version[colon+1:]
}

func splitRPMVersionRelease(s string) (version, release string) {
	if i := strings.Index(s, "-"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// rpmvercmp is a faithful port of RPM's rpmvercmp (lib/rpmvercmp.c): separators are
// skipped, the "~" pre-release marker sorts before everything else (1.0~rc1 < 1.0),
// numeric segments outrank alphabetic ones and compare as integers (leading zeros
// stripped, longer wins), and alphabetic segments compare lexically.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isRPMAlnum(a[i]) && a[i] != '~' {
			i++
		}
		for j < len(b) && !isRPMAlnum(b[j]) && b[j] != '~' {
			j++
		}

		// Tilde sorts before everything, including the empty string.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		aStart, bStart := i, j
		numeric := isVersionDigit(a[i])
		if numeric {
			for i < len(a) && isVersionDigit(a[i]) {
				i++
			}
			for j < len(b) && isVersionDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isVersionLetter(a[i]) {
				i++
			}
			for j < len(b) && isVersionLetter(b[j]) {
				j++
			}
		}

		// Different segment types at the same position: numeric outranks alpha.
		if bStart == j {
			if numeric {
				return 1
			}
			return -1
		}

		aSeg := a[aStart:i]
		bSeg := b[bStart:j]
		if numeric {
			aSeg = strings.TrimLeft(aSeg, "0")
			bSeg = strings.TrimLeft(bSeg, "0")
			if len(aSeg) != len(bSeg) {
				if len(aSeg) > len(bSeg) {
					return 1
				}
				return -1
			}
		}
		if cmp := strings.Compare(aSeg, bSeg); cmp != 0 {
			return cmp
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

func isRPMAlnum(b byte) bool { return isVersionDigit(b) || isVersionLetter(b) }

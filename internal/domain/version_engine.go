package domain

import (
	"strconv"
	"strings"
)

// CR-1 — one version engine.
//
// Before this change version comparison was forked across four code paths
// (the generic CompareVersions in version_match.go, vexfeed.compareAlpineVersion,
// vexfeed.compareRPMEVR) and three range builders (osv.rangeConstraintGroup,
// nvd.cpeAffectedVersions, vexfeed.alpineRangeStatus). A fix in one path never
// reached the others — the reason the OSV over-match fix never touched NVD.
//
// All version ordering now flows through CompareVersionsEco; all range producers
// emit the canonical constraint-group string consumed by VersionMatchesEco via
// BuildConstraintGroup. apk and rpm get ecosystem-correct ordering everywhere.

// VersionClass is the comparison family an ecosystem belongs to.
type VersionClass string

const (
	// VersionClassAPK uses Alpine apk segment ordering (with -rN build revisions).
	VersionClassAPK VersionClass = "apk"
	// VersionClassRPM uses RPM epoch:version-release ordering (with ~ pre-release).
	VersionClassRPM VersionClass = "rpm"
	// VersionClassGeneric uses rpmvercmp-style numeric-aware ordering.
	VersionClassGeneric VersionClass = "generic"
)

// ClassifyEcosystem maps an ecosystem (PURL type or feed ecosystem name) to its
// version comparison class. Distro families that share rpm ordering — Red Hat,
// Rocky, Alma, CentOS, Fedora — all map to rpm; Alpine/apk maps to apk.
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

// CompareVersionsEco compares two versions using the ordering rules of the given
// ecosystem and returns -1, 0, or 1. It is the single comparator every feeder,
// matcher, and overlay path calls.
func CompareVersionsEco(ecosystem, left, right string) int {
	switch ClassifyEcosystem(ecosystem) {
	case VersionClassAPK:
		return compareAPKVersion(left, right)
	case VersionClassRPM:
		return compareRPMVersion(left, right)
	default:
		return CompareVersions(left, right)
	}
}

// VersionConstraintSet is the canonical affected-version model: a list of AND
// groups (comma-joined comparators), matched OR-across-groups, carrying the
// ecosystem so comparison uses the right ordering rules.
type VersionConstraintSet struct {
	Ecosystem string
	Groups    []string
}

// Matches reports whether version satisfies the constraint set.
func (s VersionConstraintSet) Matches(version string) bool {
	return VersionMatchesEco(s.Ecosystem, s.Groups, version)
}

// BuildConstraintGroup composes a single AND constraint group from optional range
// bounds (inclusive/exclusive lower, inclusive/exclusive upper). Empty bounds and
// the "0" sentinel lower bound are skipped. The result is a comma-joined group
// such as ">= 2.0, < 2.5" — kept as ONE group so both bounds must hold together,
// which is what prevents the lower/upper over-match (a 1.x picking up a CVE that
// only affects [2.0, 2.5)). Returns "" when no usable bound is present.
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

// rpmvercmp is a faithful port of RPM's rpmvercmp (lib/rpmvercmp.c). It compares
// two version (or release) strings segment by segment: separators are skipped,
// the "~" pre-release marker sorts before everything else (1.0~rc1 < 1.0),
// numeric segments outrank alphabetic ones and compare as integers (leading
// zeros stripped, longer wins), and alphabetic segments compare lexically.
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

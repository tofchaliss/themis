package value

import (
	"testing"

	"pgregory.net/rapid"
)

// versionToken generates a small alphanumeric/dotted version-like string so the
// comparators are exercised across digit/letter runs and separators.
func versionToken(t *rapid.T) string {
	return rapid.StringMatching(`[0-9]{1,3}([.\-_][0-9a-z]{1,3}){0,3}`).Draw(t, "version")
}

func ecosystemToken(t *rapid.T) string {
	return rapid.SampledFrom([]string{"npm", "apk", "rpm", "Alpine", "Rocky Linux", "maven", "go"}).Draw(t, "ecosystem")
}

// CompareVersions must be antisymmetric: cmp(a,b) == -cmp(b,a) for every ecosystem.
// A fix to one comparator can never silently break this law.
func TestCompareVersionsAntisymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := ecosystemToken(t)
		a := versionToken(t)
		b := versionToken(t)
		if got, mirror := CompareVersions(eco, a, b), CompareVersions(eco, b, a); got != -mirror {
			t.Fatalf("antisymmetry broken (%s): cmp(%q,%q)=%d cmp(%q,%q)=%d", eco, a, b, got, b, a, mirror)
		}
	})
}

// CompareVersions must be reflexive: a version always equals itself.
func TestCompareVersionsReflexiveProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := ecosystemToken(t)
		a := versionToken(t)
		if CompareVersions(eco, a, a) != 0 {
			t.Fatalf("reflexivity broken (%s): cmp(%q,%q) != 0", eco, a, a)
		}
	})
}

// A version below an exclusive lower bound must NEVER satisfy a half-open range group
// built by BuildConstraintGroup — the over-match invariant, and it must never be
// judged RangeInRange by Applicability.
func TestApplicabilityLowerBoundProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := ecosystemToken(t)
		lower := versionToken(t)
		upper := versionToken(t)
		below := versionToken(t)
		// Only assert when `below` is strictly less than the lower bound and the
		// bounds form a non-empty interval.
		if CompareVersions(eco, below, lower) >= 0 {
			return
		}
		if CompareVersions(eco, lower, upper) >= 0 {
			return
		}
		r := AffectedRange{Ecosystem: eco, Groups: []string{BuildConstraintGroup(lower, "", "", upper)}}
		if r.Matches(below) {
			t.Fatalf("over-match (%s): %q matched [%q, %q)", eco, below, lower, upper)
		}
		if v := r.Applicability(below); v == RangeInRange {
			t.Fatalf("Applicability (%s): %q judged in-range for [%q, %q)", eco, below, lower, upper)
		}
	})
}

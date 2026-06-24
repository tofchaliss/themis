package domain

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

// CompareVersionsEco must be antisymmetric: cmp(a,b) == -cmp(b,a) for every
// ecosystem. A fix to one comparator can never silently break this law.
func TestCompareVersionsEcoAntisymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := ecosystemToken(t)
		a := versionToken(t)
		b := versionToken(t)
		if got, mirror := CompareVersionsEco(eco, a, b), CompareVersionsEco(eco, b, a); got != -mirror {
			t.Fatalf("antisymmetry broken (%s): cmp(%q,%q)=%d cmp(%q,%q)=%d", eco, a, b, got, b, a, mirror)
		}
	})
}

// CompareVersionsEco must be reflexive: a version always equals itself.
func TestCompareVersionsEcoReflexiveProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := ecosystemToken(t)
		a := versionToken(t)
		if CompareVersionsEco(eco, a, a) != 0 {
			t.Fatalf("reflexivity broken (%s): cmp(%q,%q) != 0", eco, a, a)
		}
	})
}

// A version below an exclusive lower bound must NEVER satisfy a half-open range
// group built by BuildConstraintGroup — the over-match invariant behind D-NVD-1.
func TestConstraintGroupLowerBoundProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := ecosystemToken(t)
		lower := versionToken(t)
		upper := versionToken(t)
		below := versionToken(t)
		// Only assert when `below` is strictly less than the lower bound and the
		// bounds form a non-empty interval.
		if CompareVersionsEco(eco, below, lower) >= 0 {
			return
		}
		if CompareVersionsEco(eco, lower, upper) >= 0 {
			return
		}
		group := BuildConstraintGroup(lower, "", "", upper)
		set := VersionConstraintSet{Ecosystem: eco, Groups: []string{group}}
		if set.Matches(below) {
			t.Fatalf("over-match (%s): %q matched [%q, %q)", eco, below, lower, upper)
		}
	})
}

package value

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

// The ANY-match contract, characterized from real data (CVE-2026-29167 on MRF 2026-09-17).
//
// RPMFixedByStream asks *"did a published same-major fix ship at or below this install?"* — NOT
// *"is the install at least the highest published bound?"* It clears between a low and a high
// bound, deliberately.
//
// An eyeball comparison against the highest bound read this exact case as "one build behind" and
// was wrong. The comparator's result is the evidence; a version string that merely looks lower is
// an observation.
func TestRPMFixedByStreamClearsBetweenLowAndHighBound(t *testing.T) {
	const installed = "2.4.37-65.module+el8.10.0+40257+286895ef.9"
	bounds := []string{
		"0:2.4.37-65.module+el8.10.0+1830+22f0c9e0",     // base build — the fix shipped here
		"0:2.4.37-65.module+el8.10.0+40312+2c72bb9b.10", // a later rebuild, above the install
	}
	if !RPMFixedByStream("rpm", installed, bounds) {
		t.Error("installed is at/above the base el8 bound and must clear — any-match, not highest-match")
	}
	// The contract's boundary: with ONLY a bound above the install, nothing clears.
	if RPMFixedByStream("rpm", installed, bounds[1:]) {
		t.Error("with only a bound ABOVE the install, the comparator must not clear")
	}
}

// WHY "highest-match" IS NOT THE SAFER RULE — recorded because we believed it was.
//
// A property asserting `any-match == highest-match` under monotonic same-major bounds was
// proposed as regression protection and DISPROVED by rapid in under a second:
//
//	installed  2.4.37-1.module+el8.0.0+9999+def
//	bounds     2.4.37-1.module+el8.0.0+1000+abc0   (satisfied)
//	           2.4.37-80.module+el8.0.0+1100+abc1  (not satisfied)
//
// The install carries the fix that shipped in `2.4.37-1…+1000`; a later `2.4.37-80` bound also
// carrying it does not make the install vulnerable. So highest-match would UNDER-clear —
// refusing to clear installs that demonstrably hold the fix. Any-match is the correct question,
// and this test pins the asymmetry so nobody "hardens" the loop into the wrong rule.
func TestRPMFixedByStreamHighestMatchWouldUnderClear(t *testing.T) {
	const installed = "2.4.37-1.module+el8.0.0+9999+def"
	bounds := []string{
		"0:2.4.37-1.module+el8.0.0+1000+abc0",
		"0:2.4.37-80.module+el8.0.0+1100+abc1",
	}
	if !RPMFixedByStream("rpm", installed, bounds) {
		t.Fatal("the install is at/above a published same-major fix and must clear")
	}
	// Demonstrate the alternative rule's verdict on the same input, so the divergence is a
	// recorded fact rather than an argument.
	highest := ""
	for _, f := range bounds {
		if highest == "" || compareRPMVersion(RPMEVR(f), RPMEVR(highest)) > 0 {
			highest = f
		}
	}
	if compareRPMVersion(RPMEVR(installed), RPMEVR(highest)) >= 0 {
		t.Fatal("test premise broken: the install should be BELOW the highest bound here")
	}
}

// The fail-safe directions, which ARE the invariants worth a property (EDR-VEX-01 Phase 3): a
// clearance requires a same-major bound the install satisfies, and every other input decides
// "affected". These hold regardless of how bounds are ordered, so they survive the ordering
// question the any-match contract leaves open (see RPMFixedByStream's doc comment).
func TestRPMFixedByStreamFailsSafeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		release := rapid.IntRange(1, 90).Draw(t, "release")
		major := rapid.IntRange(8, 10).Draw(t, "major")
		installed := fmt.Sprintf("2.4.37-%d.module+el%d.0.0+9999+def", release, major)

		// A bound in a DIFFERENT major never clears, however high it is.
		other := major + 1
		if major == 10 {
			other = 8
		}
		high := fmt.Sprintf("0:2.4.37-999.module+el%d.0.0+1+a", other)
		if RPMFixedByStream("rpm", installed, []string{high}) {
			t.Fatalf("a bound in el%d must never clear an el%d install", other, major)
		}
		// No bounds at all never clears.
		if RPMFixedByStream("rpm", installed, nil) {
			t.Fatal("no bounds must never clear")
		}
		// A non-rpm ecosystem never decides here.
		if RPMFixedByStream("apk", installed, []string{fmt.Sprintf("0:2.4.37-1.module+el%d.0.0+1+a", major)}) {
			t.Fatal("a non-rpm ecosystem must never clear through the rpm stream rule")
		}
		// An install with no resolvable EL major never clears.
		if RPMFixedByStream("rpm", "2.4.37-65", []string{fmt.Sprintf("0:2.4.37-1.module+el%d.0.0+1+a", major)}) {
			t.Fatal("an install without a resolvable EL major must never clear")
		}
	})
}

// CHARACTERIZATION of the any-match contract, and the witness for the open question KN-STREAM-1.
//
// This asserts what the comparator DOES, not that it is right: it clears iff SOME same-major
// bound is satisfied. Written as a property so a change to the selection rule fails here
// deliberately rather than silently altering which findings clear.
//
// The bound sets are NOT forced monotonic, which is the point — the generator includes the shape
// the open question is about: a bound above the install beside one below it. The comparator
// clears on the lower bound, and whether that is correct depends on an input-domain invariant
// Themis cannot currently establish (see KN-STREAM-1 and RPMFixedByStream's doc comment):
//
//   - if the bounds are a PROGRESSION (the fix shipped low and every later build carries it),
//     clearing is correct;
//   - if they are PARALLEL module CONTEXTS and the estate never received the lower-numbered
//     build, clearing is an over-clear.
//
// Nothing in the data distinguishes those, so this test deliberately encodes the current answer.
// **If module-context awareness is ever added, this expectation must be revisited, not patched** —
// that is the signal it exists to send.
func TestRPMFixedByStreamClearsOnAnySameMajorBoundProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		major := rapid.IntRange(8, 10).Draw(t, "major")
		// Release/build pairs drawn freely: no monotonicity imposed, so parallel-context shapes
		// (same release, differing build ids) appear alongside progressions.
		n := rapid.IntRange(1, 5).Draw(t, "boundCount")
		bounds := make([]string, 0, n)
		for i := 0; i < n; i++ {
			rel := rapid.IntRange(1, 90).Draw(t, fmt.Sprintf("release%d", i))
			build := rapid.IntRange(1, 50000).Draw(t, fmt.Sprintf("build%d", i))
			bounds = append(bounds,
				fmt.Sprintf("0:2.4.37-%d.module+el%d.10.0+%d+abc", rel, major, build))
		}
		instRel := rapid.IntRange(1, 90).Draw(t, "installedRelease")
		instBuild := rapid.IntRange(1, 50000).Draw(t, "installedBuild")
		installed := fmt.Sprintf("2.4.37-%d.module+el%d.10.0+%d+def", instRel, major, instBuild)

		// The contract, stated independently of the implementation's loop order.
		wantAny := false
		for _, b := range bounds {
			if RPMReleaseMajor(b) == RPMReleaseMajor(installed) &&
				compareRPMVersion(RPMEVR(installed), RPMEVR(b)) >= 0 {
				wantAny = true
				break
			}
		}
		if got := RPMFixedByStream("rpm", installed, bounds); got != wantAny {
			t.Fatalf("RPMFixedByStream=%v, want %v (any same-major bound satisfied) for %q over %v",
				got, wantAny, installed, bounds)
		}
	})
}

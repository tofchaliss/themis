package value

import "strings"

// APK fixed-verdict logic (EDR-VEX-01 D9). Alpine ships a CVE fix per branch, but an apk
// version string ("1.36.0-r2") names no branch and the stored bound carries none either
// (D7 dedups bounds across branches), so the same-stream scoping the rpm verdict reads out
// of `.elN` has nothing to read here. The verdict therefore uses the MAX-BOUND rule: the
// installed build must be at or above EVERY known apk bound for the package — provably
// sound whenever the component's own branch's bound is among them, and erring toward
// "affected" whenever bounds disagree. Every uncertain case resolves to "not fixed" (stays
// affected) — a false "fixed" is the only unsafe direction. Callers pass only bounds
// positively attributed to apk (D9: fail-open is for display, fail-closed is for
// verdicts); a bound from another ecosystem neither proves nor blocks.

// APKFixedByBounds reports whether an installed apk build is at or above EVERY vendor fix
// bound for its package — i.e. whichever branch the component came from, its branch's fix
// is present and the occurrence is NOT affected. It applies only to the apk version class,
// and it decides nothing on an empty or blank bound set: "at or above all of nothing" is
// the absence of evidence, not a verdict.
func APKFixedByBounds(ecosystem, installed string, bounds []string) bool {
	if ClassifyEcosystem(ecosystem) != VersionClassAPK {
		return false
	}
	inst := StripVersionQualifiers(strings.TrimSpace(installed))
	if inst == "" {
		return false // can't place the install anywhere → never claim fixed
	}
	usable := 0
	for _, bound := range bounds {
		bound = StripVersionQualifiers(strings.TrimSpace(bound))
		if bound == "" {
			continue // a blank bound is no evidence in either direction
		}
		if compareAPKVersion(inst, bound) < 0 {
			return false // below one published bound → the fix may be missing on this branch
		}
		usable++
	}
	return usable > 0
}

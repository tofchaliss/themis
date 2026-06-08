// Package gen provides reusable rapid generators for Themis property-based tests.
//
// It is imported only from *_test.go files. It lives outside the domain/usecase/
// adapter/infrastructure layers so it is exempt from the Clean Architecture
// import rules enforced by depguard and go-cleanarch.
package gen

import (
	"unicode"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
)

// knownSeverities are all severities the scorer recognises plus values that fall
// through to the zero base score.
var knownSeverities = []string{"critical", "high", "medium", "low", "none", "unknown", ""}

// effectiveStates enumerates every risk_context effective state.
var effectiveStates = []string{
	domain.EffectiveStateDetected,
	domain.EffectiveStateSuppressed,
	domain.EffectiveStateConfirmed,
	domain.EffectiveStateInTriage,
	domain.EffectiveStateAcceptedRisk,
	domain.EffectiveStateFalsePositive,
	domain.EffectiveStateResolved,
}

// validTriageDecisions enumerates the accepted L4 triage decisions.
var validTriageDecisions = []string{
	domain.TriageDecisionFalsePositive,
	domain.TriageDecisionAcceptedRisk,
	domain.TriageDecisionConfirmed,
	domain.TriageDecisionResolved,
	domain.TriageDecisionEscalate,
}

// AnySeverity draws an arbitrary severity string, mixing recognised values with
// junk so scorers must treat unknown input as the zero base score.
func AnySeverity(t *rapid.T) string {
	if rapid.Bool().Draw(t, "severity_known") {
		return RandomCase(t, rapid.SampledFrom(knownSeverities).Draw(t, "severity_value"))
	}
	return rapid.String().Draw(t, "severity_junk")
}

// AnyEffectiveState draws an effective state, mixing valid states with junk.
func AnyEffectiveState(t *rapid.T) string {
	if rapid.Bool().Draw(t, "state_known") {
		return RandomCase(t, rapid.SampledFrom(effectiveStates).Draw(t, "state_value"))
	}
	return rapid.String().Draw(t, "state_junk")
}

// ValidTriageDecision draws only an accepted triage decision.
func ValidTriageDecision(t *rapid.T) string {
	return rapid.SampledFrom(validTriageDecisions).Draw(t, "valid_decision")
}

// Ecosystem draws a PURL ecosystem token containing no '/' or '@', so PURL
// round-trips are unambiguous.
func Ecosystem(t *rapid.T) string {
	return rapid.StringMatching(`[a-z][a-z0-9.+-]{0,15}`).Draw(t, "ecosystem")
}

// PkgName draws a PURL package name containing no '/' or '@'.
func PkgName(t *rapid.T) string {
	return rapid.StringMatching(`[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}`).Draw(t, "pkg_name")
}

// PkgVersion draws a PURL version containing no '@', so the version splitter
// recovers it exactly.
func PkgVersion(t *rapid.T) string {
	return rapid.StringMatching(`[a-zA-Z0-9][a-zA-Z0-9._+-]{0,15}`).Draw(t, "pkg_version")
}

// DottedVersion draws a dotted version made of numeric and short alphanumeric
// segments, exercising the watch comparator.
func DottedVersion(t *rapid.T) string {
	segs := rapid.SliceOfN(rapid.StringMatching(`[0-9]{1,3}|[a-z]{1,3}`), 1, 4).Draw(t, "version_segments")
	out := segs[0]
	for _, s := range segs[1:] {
		out += "." + s
	}
	return out
}

// RandomCase returns s with each letter independently upper- or lower-cased,
// exercising case-insensitive parsing.
func RandomCase(t *rapid.T, s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if rapid.Bool().Draw(t, "rc_upper") {
			runes[i] = unicode.ToUpper(r)
		} else {
			runes[i] = unicode.ToLower(r)
		}
	}
	return string(runes)
}

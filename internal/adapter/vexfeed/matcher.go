package vexfeed

import (
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// Matcher applies the four-phase PURL matching algorithm (apk + RPM scope).
type Matcher interface {
	Match(sbomPURL, cveID string, assertions []domain.VendorVEXAssertion) MatchOutcome
}

// DefaultMatcher implements Matcher with Phase 2a rules.
type DefaultMatcher struct {
	Logger MismatchLogger
}

// MatchOutcome is the result of matching SBOM PURL against vendor assertions.
type MatchOutcome struct {
	Matched         bool
	PURLMismatch    bool
	MatchType       domain.VEXMatchType
	Assertion       domain.VendorVEXAssertion
	ResolvedStatus  string
	UpstreamVEXPURL string
}

// MismatchLogger records diagnostic purl_mismatch events.
type MismatchLogger interface {
	LogPURLMismatch(cveID, sbomPURL, vexPURL string)
}

// NoOpMismatchLogger ignores mismatch logs.
type NoOpMismatchLogger struct{}

func (NoOpMismatchLogger) LogPURLMismatch(string, string, string) {}

// Match finds the best vendor assertion for an SBOM component PURL and CVE.
func (m *DefaultMatcher) Match(sbomPURL, cveID string, assertions []domain.VendorVEXAssertion) MatchOutcome {
	logger := m.Logger
	if logger == nil {
		logger = NoOpMismatchLogger{}
	}

	var cveAssertions []domain.VendorVEXAssertion
	for _, a := range assertions {
		if strings.EqualFold(a.CVEID, cveID) {
			cveAssertions = append(cveAssertions, a)
		}
	}
	if len(cveAssertions) == 0 {
		return MatchOutcome{}
	}

	sbom := parsePURL(normalizeCase(sbomPURL))
	if sbom.Type == "" {
		return m.purlMismatch(logger, cveID, sbomPURL, cveAssertions[0].ComponentPURL)
	}

	for _, assertion := range cveAssertions {
		if outcome := m.matchAssertion(sbom, assertion); outcome.Matched {
			return outcome
		}
	}

	vexPURL := cveAssertions[0].ComponentPURL
	if cveAssertions[0].Ecosystem == "Alpine" && cveAssertions[0].PackageName != "" {
		vexPURL = cveAssertions[0].PackageName + "@" + sbom.Version
	}
	return m.purlMismatch(logger, cveID, sbomPURL, vexPURL)
}

func (m *DefaultMatcher) matchAssertion(sbom parsedPURL, assertion domain.VendorVEXAssertion) MatchOutcome {
	if assertion.Ecosystem == "Alpine" || sbom.Type == "apk" {
		return m.matchAlpineOSV(sbom, assertion)
	}
	if sbom.Type == "rpm" || strings.Contains(strings.ToLower(assertion.ComponentPURL), "pkg:rpm/") {
		return m.matchRPM(sbom, assertion)
	}
	if sbomPURL := buildPURL(sbom); sbomPURL == normalizeCase(assertion.ComponentPURL) {
		return matchedOutcome(assertion, domain.VEXMatchTypeExact, assertion.Status)
	}
	return MatchOutcome{}
}

func (m *DefaultMatcher) matchRPM(sbom parsedPURL, assertion domain.VendorVEXAssertion) MatchOutcome {
	vex := parsePURL(normalizeCase(assertion.ComponentPURL))
	if vex.Type != "rpm" {
		return MatchOutcome{}
	}

	// Phase 1 — exact
	if buildPURL(sbom) == buildPURL(vex) {
		return matchedOutcome(assertion, domain.VEXMatchTypeExact, assertion.Status)
	}

	// Phase 2 — namespace alias
	sbomNorm := normalizeRPMNamespace(sbom)
	vexNorm := normalizeRPMNamespace(vex)
	if sbomNorm.Name == vexNorm.Name && sbomNorm.Version == vexNorm.Version &&
		namespacesEquivalent(sbomNorm.Namespace, vexNorm.Namespace) {
		return matchedOutcome(assertion, domain.VEXMatchTypeNamespaceNormalised, assertion.Status)
	}

	// Phase 3 — errata direction
	if sbomNorm.Name == vexNorm.Name && namespacesEquivalent(sbomNorm.Namespace, vexNorm.Namespace) {
		installedEVR := stripErrataRevision(sbomNorm.Version)
		assertionEVR := stripErrataRevision(vexNorm.Version)
		cmp := domain.CompareVersionsEco("rpm", installedEVR, assertionEVR)
		if cmp >= 0 {
			return matchedOutcome(assertion, domain.VEXMatchTypeVersionInherited, assertion.Status)
		}
	}
	return MatchOutcome{}
}

func (m *DefaultMatcher) matchAlpineOSV(sbom parsedPURL, assertion domain.VendorVEXAssertion) MatchOutcome {
	if sbom.Type != "apk" {
		return MatchOutcome{}
	}
	pkgName := assertion.PackageName
	if pkgName == "" {
		vex := parsePURL(normalizeCase(assertion.ComponentPURL))
		pkgName = vex.Name
	}
	if !strings.EqualFold(sbom.Name, pkgName) {
		return MatchOutcome{}
	}
	installed := sbom.Version
	status := alpineRangeStatus(installed, assertion.Introduced, assertion.Fixed)
	return matchedOutcome(assertion, domain.VEXMatchTypeRangeMatched, status)
}

func matchedOutcome(assertion domain.VendorVEXAssertion, matchType domain.VEXMatchType, status string) MatchOutcome {
	if status == "" {
		status = assertion.Status
	}
	return MatchOutcome{
		Matched:         true,
		MatchType:       matchType,
		Assertion:       assertion,
		ResolvedStatus:  status,
		UpstreamVEXPURL: assertion.ComponentPURL,
	}
}

func (m *DefaultMatcher) purlMismatch(logger MismatchLogger, cveID, sbomPURL, vexPURL string) MatchOutcome {
	logger.LogPURLMismatch(cveID, sbomPURL, vexPURL)
	return MatchOutcome{PURLMismatch: true, UpstreamVEXPURL: vexPURL}
}

func alpineRangeStatus(installed, introduced, fixed string) string {
	installedForIntroduced := installed
	if introduced != "" && !strings.Contains(introduced, "-r") && strings.Contains(installed, "-r") {
		installedForIntroduced = stripAlpineBuildRevision(installed)
	}
	if introduced != "" && domain.CompareVersionsEco("apk", installedForIntroduced, introduced) < 0 {
		return domain.VEXStatusNotAffected
	}
	installedForFixed := installed
	if fixed != "" && !strings.Contains(fixed, "-r") && strings.Contains(installed, "-r") {
		installedForFixed = stripAlpineBuildRevision(installed)
	}
	if fixed != "" && domain.CompareVersionsEco("apk", installedForFixed, fixed) >= 0 {
		return domain.VEXStatusNotAffected
	}
	return domain.VEXStatusAffected
}

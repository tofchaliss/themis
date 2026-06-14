package domain

// DeterministicLevel is the Layer 1 rule output stored on risk_context.
type DeterministicLevel string

const (
	DeterministicLevelCritical      DeterministicLevel = "Critical"
	DeterministicLevelHighPlus      DeterministicLevel = "High+"
	DeterministicLevelHigh          DeterministicLevel = "High"
	DeterministicLevelElevated      DeterministicLevel = "Elevated"
	DeterministicLevelInformational DeterministicLevel = "Informational"
)

// VEXMatchType records which phase of the four-phase matcher succeeded.
type VEXMatchType string

const (
	VEXMatchTypeExact               VEXMatchType = "exact"
	VEXMatchTypeNamespaceNormalised VEXMatchType = "namespace_normalised"
	VEXMatchTypeVersionInherited    VEXMatchType = "version_inherited"
	VEXMatchTypeRangeMatched        VEXMatchType = "range_matched"
)

// UpstreamVEXCoverage tracks vendor VEX feed match status for a finding.
type UpstreamVEXCoverage string

const (
	UpstreamVEXCoverageCovered      UpstreamVEXCoverage = "covered"
	UpstreamVEXCoverageNotCovered   UpstreamVEXCoverage = "not_covered"
	UpstreamVEXCoveragePURLMismatch UpstreamVEXCoverage = "purl_mismatch"
)

// VendorVEXAssertion is a parsed upstream vendor advisory row before persistence.
type VendorVEXAssertion struct {
	AdvisoryID    string
	Feed          string
	CVEID         string
	ComponentPURL string
	Status        string
	Justification string
	Introduced    string
	Fixed         string
	PackageName   string
	Ecosystem     string
}

// Phase 2a composite risk score formula constants.
const (
	RiskScoreEPSSMultiplierMax = 0.3
	RiskScoreKEVAdjustment     = 15
	RiskScoreBlastRadiusMin    = 1.0
	RiskScoreBlastRadiusMax    = 2.0
	RiskScoreBlastRadiusCap    = 10
	BlastRadiusTraversalDepth  = 7
)

// ComputeBlastRadiusScore maps unique Customer count to a 1.0–2.0 multiplier.
func ComputeBlastRadiusScore(uniqueCustomers int) float64 {
	if uniqueCustomers <= 1 {
		return RiskScoreBlastRadiusMin
	}
	if uniqueCustomers >= RiskScoreBlastRadiusCap {
		return RiskScoreBlastRadiusMax
	}
	score := RiskScoreBlastRadiusMin + 0.1*float64(uniqueCustomers-1)
	return float64(int(score*100+0.5)) / 100
}

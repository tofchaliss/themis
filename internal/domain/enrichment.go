package domain

import (
	"context"
	"time"
)

// Effective risk states stored in risk_context.
const (
	EffectiveStateDetected      = "detected"
	EffectiveStateSuppressed    = "suppressed"
	EffectiveStateConfirmed     = "confirmed"
	EffectiveStateInTriage      = "in_triage"
	EffectiveStateAcceptedRisk  = "accepted_risk"
	EffectiveStateFalsePositive = "false_positive"
	EffectiveStateResolved      = "resolved"
	EffectiveStateNotAffected   = "not_affected"
)

// VEX assertion statuses from interchange documents.
const (
	VEXStatusNotAffected        = "not_affected"
	VEXStatusAffected           = "affected"
	VEXStatusFixed              = "fixed"
	VEXStatusUnderInvestigation = "under_investigation"
)

const (
	AuditActionRiskStateTransition = "RISK_STATE_TRANSITION"
)

// VEX document sources.
const (
	VEXSourceVendor          = "vendor"
	VEXSourceUpstream        = "upstream"
	VEXSourceUpstreamVendor  = "upstream_vendor"
	VEXSourceManual          = "manual"
	VEXSourceThemisGenerated = "themis_generated"
	VEXSourceAIGenerated     = "ai_generated"
)

// EnrichmentFinding is a correlated vulnerability row eligible for VEX overlay.
// It carries the stable identity (ArtifactID, ComponentPURL, CVEID) used to key
// risk_context, plus the per-scan ComponentVulnerabilityID for reference.
type EnrichmentFinding struct {
	ComponentVulnerabilityID string
	ArtifactID               string
	ComponentPURL            string
	CVEID                    string
	VulnerabilityID          string
	ProductID                string
	ScanReportID             string
	ComponentID              string
	RawSeverity              string
	CVSSScore                float64
}

// BlastRadiusResult is the Layer 2 output for a finding.
type BlastRadiusResult struct {
	Score       float64
	CustomerIDs []string
}

// VEXAssertionMatch is a stored assertion applicable during enrichment.
type VEXAssertionMatch struct {
	ID            string
	VEXDocumentID string
	ComponentPURL string
	CVEID         string
	Status        string
	Justification string
	DocumentTime  time.Time
	Source        string
	MatchType     string
}

// RiskContextSnapshot is the enrichment view of a risk_context row's mutable fields.
// Its identity (artifact_id, component_purl, cve_id) is supplied by the caller (via
// EnrichmentFinding or explicit args), not carried on the snapshot.
type RiskContextSnapshot struct {
	EffectiveState      string
	RawSeverity         string
	VEXStatus           string
	VEXAssertionID      string
	SuppressionReason   string
	RiskScore           int
	EPSSScore           *float64
	KEVListed           bool
	ExploitPublic       bool
	DeterministicLevel  DeterministicLevel
	BlastRadiusScore    float64
	UpstreamVEXCoverage UpstreamVEXCoverage
}

// ParsedVEXAssertion is an extracted assertion prior to persistence.
type ParsedVEXAssertion struct {
	CVEID         string
	ComponentPURL string
	Status        string
	Justification string
}

// EnrichmentRepository loads findings and assertions and persists risk_context updates.
// Findings are scoped to a scan report; risk_context is keyed on the stable identity.
type EnrichmentRepository interface {
	ListFindingsForArtifact(ctx context.Context, artifactID string) ([]EnrichmentFinding, error)
	ListAssertionsForArtifact(ctx context.Context, artifactID string) ([]VEXAssertionMatch, error)
	GetRiskContext(ctx context.Context, artifactID, componentPURL, cveID string) (RiskContextSnapshot, error)
	UpsertRiskContext(ctx context.Context, finding EnrichmentFinding, snapshot RiskContextSnapshot) error
	ArtifactForVEX(ctx context.Context, vexDocumentID string) (string, error)
	CountOpenRiskContexts(ctx context.Context) (int, error)
	ListOpenRiskContexts(ctx context.Context, offset, limit int) ([]OpenRiskContextRow, error)
	UpdateRiskContextSignals(ctx context.Context, row OpenRiskContextRow, epssScore *float64, kevListed, exploitPublic bool, deterministicLevel DeterministicLevel, riskScore int) error
}

// OpenRiskContextRow is an open finding eligible for signal re-enrichment, keyed on
// the stable identity (artifact_id, component_purl, cve_id).
type OpenRiskContextRow struct {
	ArtifactID       string
	ComponentPURL    string
	CVEID            string
	RawSeverity      string
	EffectiveState   string
	CVSSScore        float64
	BlastRadiusScore float64
}

// VEXAssertionWriter persists parsed assertions for a VEX document against an artifact.
type VEXAssertionWriter interface {
	SyncAssertions(ctx context.Context, vexDocumentID, artifactID string, assertions []ParsedVEXAssertion) error
}

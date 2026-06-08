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
)

// VEX assertion statuses from interchange documents.
const (
	VEXStatusNotAffected         = "not_affected"
	VEXStatusAffected            = "affected"
	VEXStatusFixed               = "fixed"
	VEXStatusUnderInvestigation  = "under_investigation"
)

const (
	AuditActionRiskStateTransition = "RISK_STATE_TRANSITION"
)

// EnrichmentFinding is a correlated vulnerability row eligible for VEX overlay.
type EnrichmentFinding struct {
	ComponentVulnerabilityID string
	ComponentPURL            string
	CVEID                    string
	RawSeverity              string
}

// VEXAssertionMatch is a stored assertion applicable during enrichment.
type VEXAssertionMatch struct {
	ID              string
	VEXDocumentID   string
	ComponentPURL   string
	CVEID           string
	Status          string
	Justification   string
	DocumentTime    time.Time
}

// RiskContextSnapshot is the enrichment view of a risk_context row.
type RiskContextSnapshot struct {
	ID                       string
	ComponentVulnerabilityID string
	EffectiveState           string
	RawSeverity              string
	VEXStatus                string
	VEXAssertionID           string
	SuppressionReason        string
	RiskScore                int
}

// ParsedVEXAssertion is an extracted assertion prior to persistence.
type ParsedVEXAssertion struct {
	CVEID         string
	ComponentPURL string
	Status        string
	Justification string
}

// EnrichmentRepository loads findings and assertions and persists risk_context updates.
type EnrichmentRepository interface {
	ListFindingsForSBOM(ctx context.Context, sbomDocumentID string) ([]EnrichmentFinding, error)
	ListAssertionsForSBOM(ctx context.Context, sbomDocumentID string) ([]VEXAssertionMatch, error)
	GetRiskContext(ctx context.Context, componentVulnerabilityID string) (RiskContextSnapshot, error)
	UpsertRiskContext(ctx context.Context, finding EnrichmentFinding, snapshot RiskContextSnapshot) error
	SBOMDocumentForVEX(ctx context.Context, vexDocumentID string) (string, error)
}

// VEXAssertionWriter persists parsed assertions for a VEX document.
type VEXAssertionWriter interface {
	SyncAssertions(ctx context.Context, vexDocumentID, sbomDocumentID string, assertions []ParsedVEXAssertion) error
}

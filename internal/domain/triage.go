package domain

import (
	"context"
	"time"
)

// Triage decision types submitted via the L4 API.
const (
	TriageDecisionFalsePositive = "false_positive"
	TriageDecisionAcceptedRisk  = "accepted_risk"
	TriageDecisionConfirmed     = "confirmed"
	TriageDecisionResolved      = "resolved"
	TriageDecisionEscalate      = "escalate"
)

const AuditActionTriageDecision = "TRIAGE_DECISION"

// TriageFindingContext holds finding metadata needed for triage and VEX generation,
// including the stable identity (ArtifactID, ComponentPURL, CVEID).
type TriageFindingContext struct {
	FindingID      string
	ArtifactID     string
	ComponentPURL  string
	CVEID          string
	SBOMChecksum   string
	RawSeverity    string
	EffectiveState string
}

// TriageHistoryRecord is an append-only triage decision row, keyed on the stable
// identity so history is continuous across rescans (D15).
type TriageHistoryRecord struct {
	ArtifactID    string
	ComponentPURL string
	CVEID         string
	Decision      string
	Justification string
	Actor         string
	AcceptedUntil *time.Time
	AssignedTo    string
	RecordedAt    time.Time
}

// RiskContextTriageUpdate applies a human triage outcome to risk_context, keyed on
// the stable identity (artifact_id, component_purl, cve_id).
type RiskContextTriageUpdate struct {
	ArtifactID     string
	ComponentPURL  string
	CVEID          string
	EffectiveState string
	TriagedBy      string
	TriagedAt      time.Time
	AssignedTo     string
	AcceptedUntil  *time.Time
	RiskScore      int
}

// GeneratedVEXInput describes a themis-generated VEX document from triage.
type GeneratedVEXInput struct {
	Finding      TriageFindingContext
	Decision     TriageDecision
	Assertion    ParsedVEXAssertion
	Issuer       string
	DocumentTime time.Time
}

// TriageRepository persists triage decisions and history.
type TriageRepository interface {
	GetFindingScope(ctx context.Context, findingID string) (productID string, err error)
	GetFindingContext(ctx context.Context, findingID string) (TriageFindingContext, error)
	AppendHistory(ctx context.Context, record TriageHistoryRecord) error
	ListHistory(ctx context.Context, findingID string, page PageRequest) ([]TriageHistoryEntry, PageResult, error)
	UpdateRiskContext(ctx context.Context, update RiskContextTriageUpdate) error
	ListExpiredAcceptedRiskFindings(ctx context.Context, now time.Time) ([]string, error)
	LatestDecision(ctx context.Context, findingID string) (string, error)
}

// TriageVEXGenerator creates themis_generated VEX documents from triage decisions.
type TriageVEXGenerator interface {
	CreateFromDecision(ctx context.Context, input GeneratedVEXInput) (documentID string, err error)
}

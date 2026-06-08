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

// TriageFindingContext holds finding metadata needed for triage and VEX generation.
type TriageFindingContext struct {
	FindingID      string
	ComponentPURL  string
	CVEID          string
	SBOMDocumentID string
	SBOMChecksum   string
	RawSeverity    string
	EffectiveState string
}

// TriageHistoryRecord is an append-only triage decision row.
type TriageHistoryRecord struct {
	FindingID     string
	Decision      string
	Justification string
	Actor         string
	AcceptedUntil *time.Time
	AssignedTo    string
	RecordedAt    time.Time
}

// RiskContextTriageUpdate applies a human triage outcome to risk_context.
type RiskContextTriageUpdate struct {
	FindingID      string
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

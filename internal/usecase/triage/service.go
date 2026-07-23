package triage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// Service records human triage decisions.
type Service interface {
	Submit(ctx context.Context, decision domain.TriageDecision) (domain.TriageDecision, error)
	History(ctx context.Context, findingID string, page domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error)
	ProcessExpiredAcceptedRisk(ctx context.Context, now time.Time) error
}

// Handler implements triage use cases.
type Handler struct {
	Repo  domain.TriageRepository
	VEX   domain.TriageVEXGenerator
	Audit domain.AuditRecorder
}

var _ Service = (*Handler)(nil)

// Submit validates and persists a triage decision.
func (h *Handler) Submit(ctx context.Context, decision domain.TriageDecision) (domain.TriageDecision, error) {
	if err := validateDecision(decision); err != nil {
		return domain.TriageDecision{}, err
	}

	finding, err := h.Repo.GetFindingContext(ctx, decision.FindingID)
	if err != nil {
		return domain.TriageDecision{}, err
	}

	effectiveState := MapDecisionToEffectiveState(decision.Decision)
	now := time.Now().UTC()
	record := domain.TriageHistoryRecord{
		ArtifactID:    finding.ArtifactID,
		ComponentPURL: finding.ComponentPURL,
		CVEID:         finding.CVEID,
		Decision:      decision.Decision,
		Justification: strings.TrimSpace(decision.Justification),
		Actor:         decision.Actor,
		AcceptedUntil: decision.AcceptedUntil,
		AssignedTo:    strings.TrimSpace(decision.AssignedTo),
		RecordedAt:    now,
	}
	if err := h.Repo.AppendHistory(ctx, record); err != nil {
		return domain.TriageDecision{}, err
	}

	score := ComputeRiskScore(finding.RawSeverity, effectiveState)
	update := domain.RiskContextTriageUpdate{
		ArtifactID:     finding.ArtifactID,
		ComponentPURL:  finding.ComponentPURL,
		CVEID:          finding.CVEID,
		EffectiveState: effectiveState,
		TriagedBy:      decision.Actor,
		TriagedAt:      now,
		AssignedTo:     record.AssignedTo,
		AcceptedUntil:  decision.AcceptedUntil,
		RiskScore:      score,
	}
	if err := h.Repo.UpdateRiskContext(ctx, update); err != nil {
		return domain.TriageDecision{}, err
	}

	if vexStatus, ok := MapDecisionToVEXStatus(decision.Decision); ok {
		if h.VEX == nil {
			return domain.TriageDecision{}, errors.New("vex generator not configured")
		}
		_, err := h.VEX.CreateFromDecision(ctx, domain.GeneratedVEXInput{
			Finding: finding,
			Decision: domain.TriageDecision{
				FindingID:     decision.FindingID,
				Decision:      decision.Decision,
				Justification: record.Justification,
				Actor:         decision.Actor,
			},
			Assertion: domain.ParsedVEXAssertion{
				CVEID:         finding.CVEID,
				ComponentPURL: finding.ComponentPURL,
				Status:        vexStatus,
				Justification: record.Justification,
			},
			Issuer:       decision.Actor,
			DocumentTime: now,
		})
		if err != nil {
			return domain.TriageDecision{}, err
		}
	}

	if h.Audit != nil {
		_ = h.Audit.Record(ctx, domain.AuditEntry{
			Actor:        decision.Actor,
			Action:       domain.AuditActionTriageDecision,
			ResourceType: "component_vulnerability",
			ResourceID:   decision.FindingID,
			SourceIP:     decision.SourceIP,
			Details: map[string]string{
				"decision":      decision.Decision,
				"justification": record.Justification,
				"new_state":     effectiveState,
			},
		})
		if finding.EffectiveState != effectiveState {
			_ = h.Audit.Record(ctx, domain.AuditEntry{
				Actor:        decision.Actor,
				Action:       domain.AuditActionRiskStateTransition,
				ResourceType: "component_vulnerability",
				ResourceID:   decision.FindingID,
				SourceIP:     decision.SourceIP,
				Details: map[string]string{
					"previous_state": finding.EffectiveState,
					"new_state":      effectiveState,
					"trigger":        "triage_decision",
				},
			})
		}
	}

	decision.EffectiveState = effectiveState
	return decision, nil
}

// History returns append-only triage history for a finding.
func (h *Handler) History(ctx context.Context, findingID string, page domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	return h.Repo.ListHistory(ctx, findingID, page)
}

// ProcessExpiredAcceptedRisk reverts expired accepted_risk findings to detected.
func (h *Handler) ProcessExpiredAcceptedRisk(ctx context.Context, now time.Time) error {
	findingIDs, err := h.Repo.ListExpiredAcceptedRiskFindings(ctx, now)
	if err != nil {
		return err
	}
	for _, findingID := range findingIDs {
		latest, err := h.Repo.LatestDecision(ctx, findingID)
		if err != nil {
			return err
		}
		if latest != domain.TriageDecisionAcceptedRisk {
			continue
		}
		finding, err := h.Repo.GetFindingContext(ctx, findingID)
		if err != nil {
			return err
		}
		if finding.EffectiveState == domain.EffectiveStateDetected {
			continue
		}
		if err := h.Repo.UpdateRiskContext(ctx, domain.RiskContextTriageUpdate{
			ArtifactID:     finding.ArtifactID,
			ComponentPURL:  finding.ComponentPURL,
			CVEID:          finding.CVEID,
			EffectiveState: domain.EffectiveStateDetected,
			TriagedBy:      "triage-expiry",
			TriagedAt:      now,
			RiskScore:      ComputeRiskScore(finding.RawSeverity, domain.EffectiveStateDetected),
		}); err != nil {
			return err
		}
		if h.Audit != nil {
			_ = h.Audit.Record(ctx, domain.AuditEntry{
				Actor:        "triage-expiry",
				Action:       domain.AuditActionRiskStateTransition,
				ResourceType: "component_vulnerability",
				ResourceID:   findingID,
				Details: map[string]string{
					"previous_state": finding.EffectiveState,
					"new_state":      domain.EffectiveStateDetected,
					"trigger":        "accepted_risk_expired",
				},
			})
		}
	}
	return nil
}

func validateDecision(decision domain.TriageDecision) error {
	if strings.TrimSpace(decision.Decision) == "" {
		return errors.New("decision is required")
	}
	if strings.TrimSpace(decision.Justification) == "" {
		return errors.New("justification is required")
	}
	switch decision.Decision {
	case domain.TriageDecisionFalsePositive,
		domain.TriageDecisionAcceptedRisk,
		domain.TriageDecisionConfirmed,
		domain.TriageDecisionResolved,
		domain.TriageDecisionEscalate:
	default:
		return fmt.Errorf("unsupported decision %q", decision.Decision)
	}
	if decision.Decision == domain.TriageDecisionAcceptedRisk && decision.AcceptedUntil == nil {
		return errors.New("accepted_until is required for accepted_risk")
	}
	return nil
}

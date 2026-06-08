package enrichment

import (
	"context"
	"fmt"
	"sort"

	"github.com/themis-project/themis/internal/domain"
)

// Service applies VEX overlays and recomputes risk_context.
type Service interface {
	ApplyVEX(ctx context.Context, sbomDocumentID string) error
	ReenrichVEX(ctx context.Context, vexDocumentID string) error
}

// Handler implements enrichment use cases.
type Handler struct {
	Repo  domain.EnrichmentRepository
	Audit domain.AuditRecorder
}

var _ Service = (*Handler)(nil)

// ApplyVEX creates or updates risk_context rows for every finding on an SBOM.
func (h *Handler) ApplyVEX(ctx context.Context, sbomDocumentID string) error {
	findings, err := h.Repo.ListFindingsForSBOM(ctx, sbomDocumentID)
	if err != nil {
		return err
	}
	assertions, err := h.Repo.ListAssertionsForSBOM(ctx, sbomDocumentID)
	if err != nil {
		return err
	}
	index := indexAssertions(assertions)
	for _, finding := range findings {
		if err := h.applyFinding(ctx, finding, index); err != nil {
			return err
		}
	}
	return nil
}

// ReenrichVEX recomputes risk_context for the SBOM referenced by a VEX document.
func (h *Handler) ReenrichVEX(ctx context.Context, vexDocumentID string) error {
	sbomDocumentID, err := h.Repo.SBOMDocumentForVEX(ctx, vexDocumentID)
	if err != nil {
		return err
	}
	return h.ApplyVEX(ctx, sbomDocumentID)
}

func (h *Handler) applyFinding(ctx context.Context, finding domain.EnrichmentFinding, index map[string][]domain.VEXAssertionMatch) error {
	key := assertionKey(finding.ComponentPURL, finding.CVEID)
	winner := pickWinningAssertion(index[key])

	previous, err := h.Repo.GetRiskContext(ctx, finding.ComponentVulnerabilityID)
	if err != nil {
		return err
	}

	nextState, vexStatus, suppressionReason, assertionID := ResolveEffectiveState(winner)
	score := ComputeRiskScore(finding.RawSeverity, nextState)
	snapshot := domain.RiskContextSnapshot{
		ComponentVulnerabilityID: finding.ComponentVulnerabilityID,
		EffectiveState:           nextState,
		RawSeverity:              finding.RawSeverity,
		VEXStatus:                vexStatus,
		VEXAssertionID:           assertionID,
		SuppressionReason:        suppressionReason,
		RiskScore:                score,
	}
	if err := h.Repo.UpsertRiskContext(ctx, finding, snapshot); err != nil {
		return err
	}
	if h.Audit != nil && previous.EffectiveState != nextState {
		trigger := "vex_applied"
		if winner == nil {
			trigger = "vex_revoked"
		}
		vexDocID := ""
		if winner != nil {
			vexDocID = winner.VEXDocumentID
		}
		_ = h.Audit.Record(ctx, domain.AuditEntry{
			Actor:        "enrichment",
			Action:       domain.AuditActionRiskStateTransition,
			ResourceType: "component_vulnerability",
			ResourceID:   finding.ComponentVulnerabilityID,
			Details: map[string]string{
				"previous_state": previous.EffectiveState,
				"new_state":      nextState,
				"trigger":        trigger,
				"vex_document_id": vexDocID,
			},
		})
	}
	return nil
}

func indexAssertions(assertions []domain.VEXAssertionMatch) map[string][]domain.VEXAssertionMatch {
	out := make(map[string][]domain.VEXAssertionMatch)
	for _, assertion := range assertions {
		key := assertionKey(assertion.ComponentPURL, assertion.CVEID)
		out[key] = append(out[key], assertion)
	}
	return out
}

func assertionKey(purl, cveID string) string {
	return purl + "|" + cveID
}

func pickWinningAssertion(matches []domain.VEXAssertionMatch) *domain.VEXAssertionMatch {
	if len(matches) == 0 {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].DocumentTime.After(matches[j].DocumentTime)
	})
	winner := matches[0]
	return &winner
}

// ResolveEffectiveState maps the winning VEX assertion to effective risk state fields.
func ResolveEffectiveState(winner *domain.VEXAssertionMatch) (state, vexStatus, suppressionReason, assertionID string) {
	if winner == nil {
		return domain.EffectiveStateDetected, "", "", ""
	}
	vexStatus = winner.Status
	assertionID = winner.ID
	switch winner.Status {
	case domain.VEXStatusNotAffected:
		state = domain.EffectiveStateSuppressed
		suppressionReason = fmt.Sprintf("VEX doc %s: %s — %s", winner.VEXDocumentID, winner.Status, winner.Justification)
	case domain.VEXStatusAffected:
		state = domain.EffectiveStateConfirmed
	case domain.VEXStatusFixed:
		state = domain.EffectiveStateResolved
	case domain.VEXStatusUnderInvestigation:
		state = domain.EffectiveStateDetected
	default:
		state = domain.EffectiveStateDetected
	}
	return state, vexStatus, suppressionReason, assertionID
}

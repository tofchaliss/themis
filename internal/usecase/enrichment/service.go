package enrichment

import (
	"context"
	"fmt"
	"sort"

	"github.com/themis-project/themis/internal/domain"
)

// Service applies VEX overlays and recomputes risk_context.
type Service interface {
	ApplyVEX(ctx context.Context, artifactID string) error
	ReenrichVEX(ctx context.Context, vexDocumentID string) error
}

// Handler implements enrichment use cases.
type Handler struct {
	Repo        domain.EnrichmentRepository
	Audit       domain.AuditRecorder
	Layer2      Layer2Enricher
	Layer3      Layer3Enricher
	TeamNotify  TeamNotifier
	VendorVEX   VendorAssertionReader
	VendorMatch VendorMatcher
	Metrics     MetricsRecorder
}

var _ Service = (*Handler)(nil)

// ApplyVEX creates or updates risk_context rows for every current finding of an
// artifact (its latest scan).
func (h *Handler) ApplyVEX(ctx context.Context, artifactID string) error {
	findings, err := h.Repo.ListFindingsForArtifact(ctx, artifactID)
	if err != nil {
		return err
	}
	assertions, err := h.Repo.ListAssertionsForArtifact(ctx, artifactID)
	if err != nil {
		return err
	}
	index := indexAssertions(assertions)
	vendorCache := map[string][]domain.VendorVEXAssertion{}
	for _, finding := range findings {
		var vendorAssertions []domain.VendorVEXAssertion
		if h.VendorVEX != nil {
			var ok bool
			vendorAssertions, ok = vendorCache[finding.CVEID]
			if !ok {
				var err error
				vendorAssertions, err = h.VendorVEX.ListVendorAssertionsForCVE(ctx, finding.CVEID)
				if err != nil {
					return err
				}
				vendorCache[finding.CVEID] = vendorAssertions
			}
		}
		if err := h.applyFinding(ctx, finding, index, vendorAssertions); err != nil {
			return err
		}
	}
	return nil
}

// ReenrichVEX recomputes risk_context for the artifact referenced by a VEX document.
func (h *Handler) ReenrichVEX(ctx context.Context, vexDocumentID string) error {
	artifactID, err := h.Repo.ArtifactForVEX(ctx, vexDocumentID)
	if err != nil {
		return err
	}
	return h.ApplyVEX(ctx, artifactID)
}

func (h *Handler) applyFinding(ctx context.Context, finding domain.EnrichmentFinding, index map[string][]domain.VEXAssertionMatch, vendorAssertions []domain.VendorVEXAssertion) error {
	key := assertionKey(finding.ComponentPURL, finding.CVEID)
	winner := pickWinningAssertion(index[key])

	coverage := domain.UpstreamVEXCoverageNotCovered
	var vendorMatch VendorMatchResult
	if len(vendorAssertions) > 0 {
		if h.VendorMatch != nil {
			vendorMatch = h.VendorMatch.Match(finding.ComponentPURL, finding.CVEID, vendorAssertions)
			switch {
			case vendorMatch.Matched:
				coverage = domain.UpstreamVEXCoverageCovered
				vendorWinner := vendorAssertionMatch(finding, vendorMatch)
				winner = pickWinningAssertion(append(index[key], vendorWinner))
			case vendorMatch.PURLMismatch:
				coverage = domain.UpstreamVEXCoveragePURLMismatch
			default:
				coverage = domain.UpstreamVEXCoverageNotCovered
			}
		}
	}

	previous, err := h.Repo.GetRiskContext(ctx, finding.ArtifactID, finding.ComponentPURL, finding.CVEID)
	if err != nil {
		return err
	}

	nextState, vexStatus, suppressionReason, assertionID := ResolveEffectiveState(winner)
	cvss := ResolveCVSSScore(finding)
	level := ComputeDeterministicLevel(Layer1Input{
		CVSSScore:     cvss,
		EPSSScore:     previous.EPSSScore,
		KEVListed:     previous.KEVListed,
		ExploitPublic: previous.ExploitPublic,
	})
	blast, err := layer2Enricher(h).Enrich(ctx, finding)
	if err != nil {
		return err
	}
	h.recordMetrics(level, blast, vendorMatch, vendorAssertions)
	score := ComputeRiskScoreV2(
		finding.RawSeverity,
		nextState,
		previous.EPSSScore,
		previous.KEVListed,
		previous.ExploitPublic,
		string(level),
		blast.Score,
	)
	snapshot := domain.RiskContextSnapshot{
		EffectiveState:      nextState,
		RawSeverity:         finding.RawSeverity,
		VEXStatus:           vexStatus,
		VEXAssertionID:      assertionID,
		SuppressionReason:   suppressionReason,
		RiskScore:           score,
		EPSSScore:           previous.EPSSScore,
		KEVListed:           previous.KEVListed,
		ExploitPublic:       previous.ExploitPublic,
		DeterministicLevel:  level,
		BlastRadiusScore:    blast.Score,
		UpstreamVEXCoverage: coverage,
	}
	if err := h.Repo.UpsertRiskContext(ctx, finding, snapshot); err != nil {
		return err
	}
	if err := layer3Enricher(h).Enrich(ctx, finding); err != nil {
		return err
	}
	if h.TeamNotify != nil {
		for _, customerID := range blast.CustomerIDs {
			_ = h.TeamNotify.NotifyTeam(ctx, domain.NotificationEvent{
				Type:             domain.NotificationEventBlastRadiusTeam,
				ProductID:        finding.ProductID,
				CustomerID:       customerID,
				CVEID:            finding.CVEID,
				ComponentPURL:    finding.ComponentPURL,
				BlastRadiusScore: blast.Score,
				Message:          fmt.Sprintf("CVE %s affects a deployment owned by customer team", finding.CVEID),
			})
		}
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
				"previous_state":  previous.EffectiveState,
				"new_state":       nextState,
				"trigger":         trigger,
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
	return PickWinningAssertion(matches)
}

// PickWinningAssertion selects the highest-precedence VEX assertion for export and enrichment.
func PickWinningAssertion(matches []domain.VEXAssertionMatch) *domain.VEXAssertionMatch {
	if len(matches) == 0 {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool {
		if SourceRank(matches[i].Source) != SourceRank(matches[j].Source) {
			return SourceRank(matches[i].Source) < SourceRank(matches[j].Source)
		}
		return matches[i].DocumentTime.After(matches[j].DocumentTime)
	})
	winner := matches[0]
	return &winner
}

// SourceRank orders VEX sources for precedence (lower wins).
func SourceRank(source string) int {
	switch source {
	case domain.VEXSourceThemisGenerated:
		return 0
	case domain.VEXSourceManual, domain.VEXSourceVendor:
		return 1
	case domain.VEXSourceAIGenerated:
		return 2
	case domain.VEXSourceUpstreamVendor, domain.VEXSourceUpstream:
		return 3
	default:
		return 2
	}
}

func vendorAssertionMatch(finding domain.EnrichmentFinding, match VendorMatchResult) domain.VEXAssertionMatch {
	return domain.VEXAssertionMatch{
		ComponentPURL: finding.ComponentPURL,
		CVEID:         finding.CVEID,
		Status:        match.Status,
		Justification: match.Assertion.Justification,
		Source:        domain.VEXSourceUpstreamVendor,
		MatchType:     string(match.MatchType),
	}
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
		if winner.Source == domain.VEXSourceUpstreamVendor || winner.Source == domain.VEXSourceUpstream {
			state = domain.EffectiveStateNotAffected
			suppressionReason = fmt.Sprintf("Upstream vendor VEX: %s — %s", winner.Status, winner.Justification)
		} else {
			state = domain.EffectiveStateSuppressed
			suppressionReason = fmt.Sprintf("VEX doc %s: %s — %s", winner.VEXDocumentID, winner.Status, winner.Justification)
		}
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

func (h *Handler) recordMetrics(level domain.DeterministicLevel, blast domain.BlastRadiusResult, match VendorMatchResult, vendorAssertions []domain.VendorVEXAssertion) {
	if h.Metrics == nil {
		return
	}
	h.Metrics.RecordLayer1Rule(string(level))
	h.Metrics.RecordBlastRadiusScore(blast.Score)
	if match.PURLMismatch && len(vendorAssertions) > 0 {
		h.Metrics.RecordPURLMismatch(vendorAssertions[0].Feed)
	}
}

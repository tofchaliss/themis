package enrichment

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// SignalReader loads EPSS/KEV and ExploitDB values for a CVE.
type SignalReader interface {
	GetEPSSForCVE(ctx context.Context, cveID string) (*float64, error)
	IsKEVListed(ctx context.Context, cveID string) (bool, error)
	HasPublicExploit(ctx context.Context, cveID string) (bool, error)
}

// ReEnrichSignalsBatch refreshes signal fields and risk scores for open findings.
func (h *Handler) ReEnrichSignalsBatch(ctx context.Context, offset, limit int, signals SignalReader) error {
	if h.Repo == nil {
		return nil
	}
	rows, err := h.Repo.ListOpenRiskContexts(ctx, offset, limit)
	if err != nil {
		return err
	}
	for _, row := range rows {
		var epssScore *float64
		kevListed := false
		exploitPublic := false
		if signals != nil {
			epssScore, err = signals.GetEPSSForCVE(ctx, row.CVEID)
			if err != nil {
				return err
			}
			kevListed, err = signals.IsKEVListed(ctx, row.CVEID)
			if err != nil {
				return err
			}
			exploitPublic, err = signals.HasPublicExploit(ctx, row.CVEID)
			if err != nil {
				return err
			}
		}
		level := ComputeDeterministicLevel(Layer1Input{
			CVSSScore:     ResolveCVSSScore(domain.EnrichmentFinding{RawSeverity: row.RawSeverity, CVSSScore: row.CVSSScore}),
			EPSSScore:     epssScore,
			KEVListed:     kevListed,
			ExploitPublic: exploitPublic,
		})
		score := ComputeRiskScoreV2(
			row.RawSeverity,
			row.EffectiveState,
			epssScore,
			kevListed,
			exploitPublic,
			string(level),
			row.BlastRadiusScore,
		)
		if err := h.Repo.UpdateRiskContextSignals(ctx, row, epssScore, kevListed, exploitPublic, level, score); err != nil {
			return err
		}
	}
	return nil
}

// ComputeRiskScoreWithSignals is a compatibility wrapper for callers that lack
// deterministic level and blast-radius context; prefer ComputeRiskScoreV2.
func ComputeRiskScoreWithSignals(rawSeverity, effectiveState string, epssScore *float64, kevListed bool) int {
	return ComputeRiskScoreV2(
		rawSeverity,
		effectiveState,
		epssScore,
		kevListed,
		false,
		"",
		domain.RiskScoreBlastRadiusMin,
	)
}

package app

import "context"

// VexFeedSource fetches one CVE's vendor CSAF-VEX statements across the configured vendor feeds
// and returns the source Proposals to fold — `not_affected` applicability (parity B4, EDR-VEX-01
// D2). It is per-CVE, so the caller's iteration over the already-carded CVEs keeps it
// relevance-bounded (EDR-KNOWLEDGE-01 D5 — never a bulk feed mirror). A CVE no configured feed
// covers yields no Proposals (nil), not an error.
type VexFeedSource interface {
	FetchCVE(ctx context.Context, cve string) ([]ProposalFor, error)
}

// VexEnrichmentService folds vendor CSAF-VEX statements onto EXISTING Faultline cards (D5): it
// iterates the known cards and fetches each CVE's VEX across the configured vendor feeds, folding
// each `not_affected` applicability Proposal. Those statements ride the Governance suppression
// overlay (EDR-VEX-01 Phase 2). Idempotent — re-folding a VEX applicability converges.
type VexEnrichmentService struct {
	source VexFeedSource
	known  KnownCVEs
	fold   *FaultlineService
}

// NewVexEnrichmentService wires the enrichment ports.
func NewVexEnrichmentService(source VexFeedSource, known KnownCVEs, fold *FaultlineService) *VexEnrichmentService {
	return &VexEnrichmentService{source: source, known: known, fold: fold}
}

// Enrich runs one CSAF-VEX enrichment sweep and returns how many Proposals were folded. It
// iterates the known cards and fetches each CVE's vendor VEX; a per-CVE fetch error is skipped (a
// CVE no feed covers is normal, and a transient error is retried next sweep), so one gap never
// aborts the sweep. A fold (store) error IS fatal to the sweep — a real persistence fault.
func (s *VexEnrichmentService) Enrich(ctx context.Context) (int, error) {
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return 0, err
	}
	if len(known) == 0 {
		return 0, nil // nothing carded yet — no relevant CVE to enrich
	}
	folded := 0
	for cve := range known {
		props, err := s.source.FetchCVE(ctx, cve)
		if err != nil {
			continue // no vendor VEX for this CVE, or a transient fetch error — skip it
		}
		for _, p := range props {
			if _, ferr := s.fold.FoldProposal(ctx, p.CVE, p.Proposal); ferr != nil {
				return folded, ferr
			}
			folded++
		}
	}
	return folded, nil
}

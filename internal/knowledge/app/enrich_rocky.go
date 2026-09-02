package app

import "context"

// RockyFixSource returns the Rocky RXSA fix Proposals for the CARDED CVEs only (EDR-VEX-01
// D11). Like the Alpine secdb (D7), the errata set is fetched whole and the known set travels
// INTO the source — the RXSA universe is tiny (29 advisories measured 2026-08-27), so the D5
// filter lives at the data: uncarded records are discarded in memory and no Proposal about an
// irrelevant CVE is ever materialized.
type RockyFixSource interface {
	ProposalsForKnown(ctx context.Context, known map[string]struct{}) ([]ProposalFor, error)
}

// RockyEnrichmentService folds Rocky RXSA errata fix bounds onto EXISTING Faultline cards
// (D5). RXSA advisories cover Rocky-exclusive/SIG packages that exist in no Red Hat data —
// the one Rocky gap the clone-covering Red Hat feed cannot reach (GUI-5). The Proposals carry
// source-package `rpm` Fixes only (SeverityUnknown — `rocky` never contends for the severity
// headline, mirroring `alpine`). Idempotent — re-folding converges.
type RockyEnrichmentService struct {
	source RockyFixSource
	known  KnownCVEs
	fold   *FaultlineService
}

// NewRockyEnrichmentService wires the enrichment ports.
func NewRockyEnrichmentService(source RockyFixSource, known KnownCVEs, fold *FaultlineService) *RockyEnrichmentService {
	return &RockyEnrichmentService{source: source, known: known, fold: fold}
}

// Enrich runs one RXSA sweep and returns how many Proposals were folded. Like the Alpine
// sweep, a source error aborts: the errata set is fetched as one paginated walk, so its
// failure IS the sweep failing — feed health records it and the next interval retries. A fold
// (store) error is fatal as everywhere: a persistence fault is not a feed gap.
func (s *RockyEnrichmentService) Enrich(ctx context.Context) (int, error) {
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return 0, err
	}
	if len(known) == 0 {
		return 0, nil // nothing carded yet — no relevant CVE to enrich
	}
	props, err := s.source.ProposalsForKnown(ctx, known)
	if err != nil {
		return 0, err
	}
	folded := 0
	for _, p := range props {
		if _, _, ferr := s.fold.FoldProposal(ctx, p.CVE, p.Proposal); ferr != nil {
			return folded, ferr
		}
		folded++
	}
	return folded, nil
}

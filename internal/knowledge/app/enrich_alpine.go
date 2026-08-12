package app

import "context"

// AlpineFixSource returns the Alpine secdb fix Proposals for the CARDED CVEs only
// (EDR-VEX-01 D7). The known set travels INTO the source — the secdb is not per-CVE
// addressable, so the adapter fetches whole branch DBs and must discard uncarded records
// before anything reaches the fold. Passing the bound in keeps the D5 filter at the data:
// no Proposal about an irrelevant CVE is ever materialized, let alone persisted.
type AlpineFixSource interface {
	ProposalsForKnown(ctx context.Context, known map[string]struct{}) ([]ProposalFor, error)
}

// AlpineEnrichmentService folds Alpine secdb fixed-version bounds onto EXISTING Faultline
// cards (D5): Alpine is the one distro with correlation but no vendor fix data — RHEL/Rocky/
// Alma ride the Red Hat feed, Ubuntu/Debian ride OSV, and an apk card carried no published
// fix version at all (GUI-2). The Proposals carry Fixes only (SeverityUnknown — the secdb
// states no severity, and the reconciled headline skips unknown), so the feed contributes
// bounds and never contends for the severity headline. Idempotent — re-folding converges.
type AlpineEnrichmentService struct {
	source AlpineFixSource
	known  KnownCVEs
	fold   *FaultlineService
}

// NewAlpineEnrichmentService wires the enrichment ports.
func NewAlpineEnrichmentService(source AlpineFixSource, known KnownCVEs, fold *FaultlineService) *AlpineEnrichmentService {
	return &AlpineEnrichmentService{source: source, known: known, fold: fold}
}

// Enrich runs one Alpine secdb sweep and returns how many Proposals were folded. Unlike the
// per-CVE feeds (where one CVE's fetch gap is skipped), a source error here aborts the sweep:
// there is one branch-DB fetch, so its failure IS the sweep failing — feed health records it
// and the next interval retries. A fold (store) error is fatal as everywhere: a persistence
// fault is not a feed gap.
func (s *AlpineEnrichmentService) Enrich(ctx context.Context) (int, error) {
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

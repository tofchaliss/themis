package app

import "context"

// RedHatCVESource fetches one CVE's Red Hat vendor data and returns the source Proposals to
// fold — the vendor-severity vuln-facts Proposal plus any `not_affected` applicability
// statements (EDR-VEX-01 D2 / parity B3). It is per-CVE, so the caller's iteration over the
// already-carded CVEs keeps it relevance-bounded (EDR-KNOWLEDGE-01 D5 — never a full-feed
// mirror). A CVE Red Hat does not track yields no Proposals (nil), not an error.
type RedHatCVESource interface {
	FetchCVE(ctx context.Context, cve string) ([]ProposalFor, error)
}

// RedHatEnrichmentService folds Red Hat vendor data onto EXISTING Faultline cards (D5): it
// iterates the known cards (the bounded set) and fetches each CVE's Red Hat record, folding the
// vendor-severity vuln-facts and any `not_affected` applicability Proposals. Precedence ranks
// `redhat` distro-authoritative, so its statements headline the reconciled distro view; the
// applicability rides the Phase-2 suppression overlay in Governance. It covers RHEL and its 1:1
// rebuilds (Rocky, Alma) because the vendor verdict keys on the RPM package, not the distro
// label. Idempotent — re-folding a Red Hat Proposal converges.
type RedHatEnrichmentService struct {
	source RedHatCVESource
	known  KnownCVEs
	fold   *FaultlineService
}

// NewRedHatEnrichmentService wires the enrichment ports.
func NewRedHatEnrichmentService(source RedHatCVESource, known KnownCVEs, fold *FaultlineService) *RedHatEnrichmentService {
	return &RedHatEnrichmentService{source: source, known: known, fold: fold}
}

// Enrich runs one Red Hat enrichment sweep and returns how many Proposals were folded. It
// iterates the known cards and fetches each CVE's Red Hat data; a per-CVE fetch error is
// skipped (a CVE Red Hat does not track is normal, and a transient fetch error is retried next
// sweep), so one gap never aborts the whole sweep. A fold (store) error IS fatal to the sweep —
// it signals a real persistence fault, not a feed gap.
func (s *RedHatEnrichmentService) Enrich(ctx context.Context) (int, error) {
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
			continue // no Red Hat data for this CVE, or a transient fetch error — skip it
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

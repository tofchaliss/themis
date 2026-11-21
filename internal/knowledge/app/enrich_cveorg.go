package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// CVERecordSource fetches one CVE's CVE.org record as a source revision (EDR-SCORING-01 S2,
// F13): the CNA's ratings and every ADP's (CISA ADP among them). found=false when CVE.org has no
// published record for the id.
type CVERecordSource interface {
	FetchRecord(ctx context.Context, cve value.CVEID) (obs domain.ObservationInput, found bool, err error)
}

// CVEOrgEnrichmentService records CVE.org ratings for the CVEs already carded (the D5 bound: it
// never mirrors the feed). It records source truth only: no Proposal, so the card's headline
// and everything that reads it are unchanged.
type CVEOrgEnrichmentService struct {
	source  CVERecordSource
	known   KnownCVEs
	ratings RatingRecorder
}

// NewCVEOrgEnrichmentService wires the CVE.org sweep.
func NewCVEOrgEnrichmentService(source CVERecordSource, known KnownCVEs, ratings RatingRecorder) *CVEOrgEnrichmentService {
	return &CVEOrgEnrichmentService{source: source, known: known, ratings: ratings}
}

// Enrich runs one sweep and returns how many records it recorded. A fetch error skips that CVE
// (retried next sweep); a store error ends the sweep, because it is a persistence fault.
func (s *CVEOrgEnrichmentService) Enrich(ctx context.Context) (int, error) {
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return 0, err
	}
	recorded := 0
	for raw := range known {
		cve, perr := value.NewCVEID(raw)
		if perr != nil {
			continue
		}
		obs, found, ferr := s.source.FetchRecord(ctx, cve)
		if ferr != nil || !found {
			continue
		}
		if err := s.ratings.Record(ctx, cve, obs); err != nil {
			return recorded, err
		}
		recorded++
	}
	return recorded, nil
}

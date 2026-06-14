package vexfeed

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// EnrichmentAssertionReader adapts PostgresAssertionStore to enrichment.VendorAssertionReader.
type EnrichmentAssertionReader struct {
	Store *PostgresAssertionStore
}

// ListVendorAssertionsForCVE implements enrichment.VendorAssertionReader.
func (r EnrichmentAssertionReader) ListVendorAssertionsForCVE(ctx context.Context, cveID string) ([]domain.VendorVEXAssertion, error) {
	if r.Store == nil {
		return nil, nil
	}
	return r.Store.ListAssertionsForCVE(ctx, cveID)
}

var _ enrichment.VendorAssertionReader = EnrichmentAssertionReader{}

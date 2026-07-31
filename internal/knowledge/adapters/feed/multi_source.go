package feed

import (
	"context"
	"errors"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// MultiSource fans a component out to several discovery sources and concatenates their
// Proposals — reconciliation converges duplicates by CVE, so no dedup is needed here. It is
// **best-effort**: a single source's failure does not block the others, and it returns an
// error only when EVERY source failed. This is what lets NVD discovery (A2) sit beside OSV
// without an NVD outage stopping OSV-driven correlation.
type MultiSource struct {
	sources []app.PackageVulnSource
}

// NewMultiSource composes discovery sources into one PackageVulnSource. With a single source it
// behaves exactly like that source.
func NewMultiSource(sources ...app.PackageVulnSource) *MultiSource {
	return &MultiSource{sources: sources}
}

// VulnsForPackage queries every source, accumulating the Proposals of those that succeed. It
// returns an error only if every source errored (so a total discovery outage still surfaces,
// but one source failing never blocks the rest).
func (m *MultiSource) VulnsForPackage(ctx context.Context, comp app.InventoryComponent) ([]app.ProposalFor, error) {
	var (
		out   []app.ProposalFor
		errs  []error
		anyOK bool
	)
	for _, s := range m.sources {
		pfs, err := s.VulnsForPackage(ctx, comp)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		anyOK = true
		out = append(out, pfs...)
	}
	if !anyOK && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

var _ app.PackageVulnSource = (*MultiSource)(nil)

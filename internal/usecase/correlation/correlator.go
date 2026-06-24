// Package correlation is the single correlation core (CR-2). It runs every
// configured CorrelationSource for a component, stamps each result with its
// source (CR-3 provenance), and merges them by distro-authoritative precedence —
// replacing the bespoke per-feed match paths that used to live in ingest and
// watch. It implements domain.VulnerabilityFetcher so the ingestion pipeline
// consumes it unchanged; new feeds (NVD-by-CVE, distro OSV, RHSA) are added by
// appending a source, with no caller changes.
package correlation

import (
	"context"
	"fmt"
	"sort"

	"github.com/themis-project/themis/internal/domain"
)

// Correlator fans a component query out across sources and merges the results.
type Correlator struct {
	sources []domain.CorrelationSource
	logger  domain.Logger
}

var (
	_ domain.VulnerabilityFetcher      = (*Correlator)(nil)
	_ domain.CorrelationSummaryEmitter = (*Correlator)(nil)
)

// NewCorrelator builds a Correlator over the given sources (queried in order).
func NewCorrelator(logger domain.Logger, sources ...domain.CorrelationSource) *Correlator {
	return &Correlator{sources: sources, logger: domain.LoggerOrNop(logger)}
}

// FetchForComponent queries every source, tags provenance, and returns one merged
// record per CVE — the highest-precedence source's verdict for this component's
// ecosystem. Output is sorted by CVE ID for deterministic, idempotent findings.
func (c *Correlator) FetchForComponent(ctx context.Context, component domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	best := make(map[string]domain.VulnerabilityRecord)
	for _, src := range c.sources {
		records, err := src.FetchForComponent(ctx, component)
		if err != nil {
			return nil, fmt.Errorf("correlation source %s: %w", src.Name(), err)
		}
		for _, rec := range records {
			if rec.Source == "" {
				rec.Source = src.Name()
			}
			if rec.CVEID == "" {
				continue
			}
			existing, ok := best[rec.CVEID]
			if !ok || higherPrecedence(component.Ecosystem, rec, existing) {
				best[rec.CVEID] = rec
			}
		}
	}
	if len(best) == 0 {
		return nil, nil
	}
	out := make([]domain.VulnerabilityRecord, 0, len(best))
	for _, rec := range best {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVEID < out[j].CVEID })
	c.logger.Debug("component correlated",
		domain.LogString("purl", component.PURL),
		domain.LogInt("findings", len(out)),
		domain.LogInt("sources", len(c.sources)))
	return out, nil
}

func higherPrecedence(ecosystem string, candidate, existing domain.VulnerabilityRecord) bool {
	return domain.FindingSourcePrecedence(ecosystem, candidate.Source) >
		domain.FindingSourcePrecedence(ecosystem, existing.Source)
}

// EmitCorrelationSummary flushes any deferred per-source skip summaries
// (preserves the OSV skip-summary logging through the unified core).
func (c *Correlator) EmitCorrelationSummary() {
	for _, src := range c.sources {
		if emitter, ok := src.(domain.CorrelationSummaryEmitter); ok {
			emitter.EmitCorrelationSummary()
		}
	}
}

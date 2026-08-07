package feed

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// RelevanceFilteredSource wraps a raw modified-since ChangedVulnSource (the NVD watch) and
// drops changed CVEs that have no existing card, so the watch ENRICHES known-relevant cards
// rather than mirroring the whole feed (EDR-KNOWLEDGE-01 D5 — bounded by relevance). The card
// set is loaded once per poll from KnownCVEs. Because every surviving Proposal targets a CVE
// that already has a card, the downstream fold find-and-enriches, never creates.
type RelevanceFilteredSource struct {
	raw    app.ChangedVulnSource
	known  app.KnownCVEs
	source string // the feed id these counts are attributed to
}

// NewRelevanceFilteredSource composes a raw modified-since source with the known-CVE set.
// `source` is the feed id the discovered/folded counts are recorded under.
func NewRelevanceFilteredSource(source string, raw app.ChangedVulnSource, known app.KnownCVEs) *RelevanceFilteredSource {
	return &RelevanceFilteredSource{source: source, raw: raw, known: known}
}

// ChangedSince fetches the raw source's changed-CVE Proposals and returns only those whose
// CVE already has a card. An empty known set yields no Proposals (nothing relevant to enrich).
func (s *RelevanceFilteredSource) ChangedSince(ctx context.Context, since time.Time) ([]app.ProposalFor, error) {
	changed, err := s.raw.ChangedSince(ctx, since)
	if err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return nil, nil
	}
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]app.ProposalFor, 0, len(changed))
	for _, pf := range changed {
		if _, ok := known[pf.CVE.String()]; ok {
			out = append(out, pf)
		}
	}
	// Both numbers are recorded HERE because this is the only place that knows both. The watch
	// downstream sees only the survivors, so `folded: 0` was ambiguous — either the feed
	// returned nothing, or it returned plenty and none of it was about this enterprise. Those
	// need opposite responses (fix the client vs. do nothing), and for months the system could
	// not tell an operator which had happened.
	observability.Default().RecordFeedRecords(s.source, observability.FeedRecordsDiscovered, len(changed))
	observability.Default().RecordFeedRecords(s.source, observability.FeedRecordsRelevant, len(out))
	return out, nil
}

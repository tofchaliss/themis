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
func (s *RelevanceFilteredSource) ChangedSince(ctx context.Context, since time.Time) ([]app.ProposalFor, time.Time, error) {
	changed, coveredThrough, err := s.raw.ChangedSince(ctx, since)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(changed) == 0 {
		// Recorded BEFORE returning, and with zeroes. "The feed returned nothing" is one of the
		// two cases these counters exist to tell apart, so it is the last case that may go
		// unrecorded — an absent series would be indistinguishable from a poll that never ran.
		s.record(0, 0)
		return nil, coveredThrough, nil
	}
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	out := make([]app.ProposalFor, 0, len(changed))
	for _, pf := range changed {
		if _, ok := known[pf.CVE.String()]; ok {
			out = append(out, pf)
		}
	}
	s.record(len(changed), len(out))
	return out, coveredThrough, nil
}

// record emits both counts. They are recorded HERE because this is the only place that knows
// both: the watch downstream sees only the survivors, so `folded: 0` alone was ambiguous —
// either the feed returned nothing, or it returned plenty and none of it was about this
// enterprise. Those need opposite responses (fix the client vs. do nothing).
func (s *RelevanceFilteredSource) record(discovered, relevant int) {
	observability.Default().RecordFeedRecords(s.source, observability.FeedRecordsDiscovered, discovered)
	observability.Default().RecordFeedRecords(s.source, observability.FeedRecordsRelevant, relevant)
}

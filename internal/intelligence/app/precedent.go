package app

import (
	"context"
	"errors"
	"sort"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// defaultTopK is the neighbour count when a caller supplies none.
const defaultTopK = 5

// PrecedentQuery is the query semantics of a precedent search — WHICH neighbours are
// candidates. Everything that changes the candidate set lives here; nothing that changes
// how a result is DISPLAYED does (redaction is an output-boundary concern, applied by each
// consumer — see PrecedentService).
type PrecedentQuery struct {
	// Severity + Components compose the embedded subject text (domain.SubjectText).
	Severity   string
	Components []string
	// FaultlineID keys the exact-CVE fallback; empty disables it.
	FaultlineID string
	// ReleaseID is the subject's own Release. It is excluded from results unless
	// IncludeSameRelease is set — a Finding is not precedent for itself, and neither are
	// its siblings on the same Release, which were usually decided in one sitting.
	ReleaseID string
	// IncludeSameRelease keeps the subject's own Release in the candidate set. Off for the
	// AI path (self-reference is not precedent); a human may explicitly ask for it, because
	// "what else did we decide on this release" is a real question that precedent framing
	// happens to exclude.
	IncludeSameRelease bool
	// TopK bounds the semantic neighbours returned; <=0 uses the service default.
	TopK int
}

// PrecedentService is the ONE retrieval seam over the Operational Semantic Index (KS2, Δ3a).
//
// It answers a single question — "what past Enterprise Positions most resemble this subject?"
// — and it is deliberately the only place that answers it. Two consumers depend on that:
//
//   - the Gateway, which feeds the result to a model as grounding for recommend_position, and
//   - the read API, which shows the same result to a security engineer with no model involved.
//
// Before this existed the answer was an emergent property of statement order inside
// Gateway.invoke: a semantic search in the plan walk, and an exact-CVE fallback several
// branches later, joined by the unwritten rule "fall back only when semantic found nothing".
// A second consumer would have had to reimplement that rule, and the two copies would drift —
// which is how the same claim comes to have two answers depending on who asked.
//
// It is pure retrieval: no model, no generation, no decision. The result is derived and
// rebuildable (KS2 is never truth), every element traces back to the KS1 Position it came
// from, and the whole thing degrades to "no precedent" on any failure rather than erroring —
// a missing precedent must never block a recommendation OR a page load.
//
// Redaction is NOT applied here, on purpose. What may be shown differs by consumer and by
// destination — a prompt bound for a provider and an HTTP response to an authenticated
// engineer are different boundaries with different rules. Applying it here would bake one
// consumer's policy into a shared seam, and would silently redact the copy the Gateway
// already redacts on its own path. The rule: filters are query semantics and live here;
// redaction is an output boundary and lives at each consumer's edge.
type PrecedentService struct {
	embedder   Embedder
	index      VectorIndex
	fallback   PrecedentReader
	projection ProjectionReader
	// comparisons enables delta-aware ranking (G-AI-3): each precedent is weighted by how much
	// its release's posture overlaps the subject's, via the deterministic comparison read
	// (EDR-GOVERNANCE-01 D16). Optional like every other port: nil ⇒ ranking is pure retrieval
	// order, and ANY comparison failure leaves that precedent unweighted — a missing delta must
	// never block retrieval or penalize a precedent.
	comparisons ComparisonReader
	topK        int
}

// ComparisonReader is the slice of the projection reader the delta ranking needs — narrow on
// purpose, so a test fakes two-release comparisons without faking the whole read surface.
type ComparisonReader interface {
	GetReleaseComparison(ctx context.Context, baselineID, candidateID string) (domain.ReleaseComparison, error)
}

// WithComparisons wires the delta-ranking seam (G-AI-3) and returns the service for chaining.
func (s *PrecedentService) WithComparisons(r ComparisonReader) *PrecedentService {
	s.comparisons = r
	return s
}

// NewPrecedentService builds the seam. Every dependency is optional and a nil one simply
// removes that source: no embedder or index ⇒ no semantic retrieval (a stateless Gateway,
// which is the supported no-store deployment); no fallback reader ⇒ no exact-CVE pull.
// topK<=0 defaults to 5.
func NewPrecedentService(embedder Embedder, index VectorIndex, fallback PrecedentReader, topK int) *PrecedentService {
	if topK <= 0 {
		topK = defaultTopK
	}
	return &PrecedentService{embedder: embedder, index: index, fallback: fallback, topK: topK}
}

// WithProjection supplies the reader used by RetrieveForFinding to turn a bare Finding id into
// a query. The Gateway does not need it — it already holds the projection it grounded on — so
// it is a builder option rather than a constructor argument: a Gateway-only wiring stays
// exactly as simple as it was.
func (s *PrecedentService) WithProjection(p ProjectionReader) *PrecedentService {
	s.projection = p
	return s
}

// QueryFromAssessment composes the precedent query from a Finding's Domain Projection. It is
// the single definition of "what about this Finding do we match on", used by both consumers —
// the Gateway (which already holds the projection) and RetrieveForFinding (which fetches it).
// Two call sites building a PrecedentQuery by hand is exactly the drift this seam exists to
// prevent, one level up.
func QueryFromAssessment(a domain.FindingAssessment) PrecedentQuery {
	return PrecedentQuery{
		Severity:    a.Knowledge.Severity,
		Components:  a.Finding.Components,
		FaultlineID: a.Finding.FaultlineID,
		ReleaseID:   a.Finding.ReleaseID,
	}
}

// ErrNoSubject reports that the Finding a precedent query names does not exist, or that no
// projection reader is wired. It is the ONLY error this service returns: retrieval itself
// always degrades to an empty result, but "that Finding is not there" is a caller mistake and
// must surface as a 404 rather than as an empty list, which would read as "no precedent".
var ErrNoSubject = errors.New("precedent: no such finding")

// RetrieveForFinding is the read-API entry point: it resolves the Finding to its authoritative
// projection, composes the query, and retrieves. topK and includeSameRelease are the caller's
// query semantics; redaction is applied by the caller at its own output boundary.
func (s *PrecedentService) RetrieveForFinding(ctx context.Context, findingID string, topK int, includeSameRelease bool) ([]domain.PrecedentPosition, error) {
	if s.projection == nil {
		return nil, ErrNoSubject
	}
	a, err := s.projection.GetAssessment(ctx, findingID)
	if err != nil || a.Finding.ID == "" {
		return nil, ErrNoSubject
	}
	q := QueryFromAssessment(a)
	q.TopK = topK
	q.IncludeSameRelease = includeSameRelease
	return s.Retrieve(ctx, q), nil
}

// Retrieve returns the precedent Positions most similar to the query subject, ranked by the
// index (descending cosine similarity), UNREDACTED.
//
// Order of sources is load-bearing and is the rule that used to be implicit:
//
//  1. Semantic neighbours from KS2 — a DIFFERENT CVE on a similar component is the whole
//     point of RC-1, and it is what a cold exact-CVE lookup can never produce.
//  2. The exact-CVE fallback, consulted ONLY when semantic retrieval produced nothing. That
//     covers a cold or incomplete index (the first decision on a fresh deployment has no
//     neighbours) without paying for a read on every call.
//
// Never an error: an embed failure, an unwired index and a failing fallback read all return
// an empty slice. A caller cannot distinguish "nothing similar" from "retrieval broke", and
// deliberately so — both mean the same thing to a consumer, which is "decide without
// precedent". Operators see the difference in telemetry, not in the return value.
func (s *PrecedentService) Retrieve(ctx context.Context, q PrecedentQuery) []domain.PrecedentPosition {
	if found := s.semantic(ctx, q); len(found) > 0 {
		return s.deltaRank(ctx, q.ReleaseID, found)
	}
	if s.fallback == nil || q.FaultlineID == "" {
		return nil
	}
	// The fallback excludes the subject's Release for the same reason the semantic search
	// does; IncludeSameRelease widens it by passing no exclusion.
	prec, err := s.fallback.GetPrecedents(ctx, q.FaultlineID, s.excluded(q))
	if err != nil {
		return nil
	}
	return s.deltaRank(ctx, q.ReleaseID, prec)
}

// deltaRank is the G-AI-3 remainder: weight each precedent by the release-to-release delta and
// re-sort. The delta signal is posture overlap from the deterministic comparison read —
// |persisting| / (|fixed|+|new|+|persisting|), the Jaccard of the two releases' Finding sets.
// One comparison per DISTINCT precedent release (topK bounds it), cached within the call; the
// subject's own release (IncludeSameRelease) trivially overlaps 1.0 without a read. Any failed
// or empty comparison leaves that precedent unweighted (weight 1.0): degrading a rank because a
// read failed would punish precedent for an outage. The sort is stable, so equal rank scores
// keep the retriever's order.
func (s *PrecedentService) deltaRank(ctx context.Context, subjectRelease string, prec []domain.PrecedentPosition) []domain.PrecedentPosition {
	if s.comparisons == nil || subjectRelease == "" {
		return prec
	}
	type verdict struct {
		overlap float64
		known   bool
	}
	cache := make(map[string]verdict, len(prec))
	for i := range prec {
		rel := prec[i].ReleaseID
		if rel == "" {
			continue
		}
		v, seen := cache[rel]
		if !seen {
			if rel == subjectRelease {
				v = verdict{overlap: 1.0, known: true}
			} else {
				cmp, err := s.comparisons.GetReleaseComparison(ctx, subjectRelease, rel)
				if total := len(cmp.Fixed) + len(cmp.New) + len(cmp.Persisting); err == nil && total > 0 {
					v = verdict{overlap: float64(len(cmp.Persisting)) / float64(total), known: true}
				}
			}
			cache[rel] = v
		}
		prec[i].ReleaseOverlap, prec[i].OverlapKnown = v.overlap, v.known
	}
	sort.SliceStable(prec, func(i, j int) bool { return prec[i].RankScore() > prec[j].RankScore() })
	return prec
}

// semantic embeds the subject and searches KS2. An empty subject text short-circuits before
// the embedder is called — there is nothing to be similar to, and an embedding of "" is a
// vector pointing at everything.
func (s *PrecedentService) semantic(ctx context.Context, q PrecedentQuery) []domain.PrecedentPosition {
	if s.embedder == nil || s.index == nil {
		return nil
	}
	text := domain.SubjectText(q.Severity, q.Components)
	if text == "" {
		return nil
	}
	vec, err := s.embedder.Embed(ctx, text)
	if err != nil {
		return nil
	}
	k := q.TopK
	if k <= 0 {
		k = s.topK
	}
	return s.index.Search(vec, k, s.excluded(q))
}

// excluded returns the Release id the search must skip — empty when the caller explicitly
// asked to include the subject's own Release.
func (s *PrecedentService) excluded(q PrecedentQuery) string {
	if q.IncludeSameRelease {
		return ""
	}
	return q.ReleaseID
}

// RedactPrecedents returns a copy with each Rationale scrubbed through r — the output-boundary
// half of the split described on PrecedentService. It is a projection: the stored Position is
// never modified, and re-reading it yields the original text.
//
// Only Rationale is scrubbed. The other fields are identifiers, a stance, a component and a
// score — structural facts a caller needs to act on. Rationale is the one free-text field, so
// it is the one that can carry a secret somebody pasted into a decision note years ago.
//
// A nil redactor returns the input unchanged, matching every other optional port here.
func RedactPrecedents(r Redactor, in []domain.PrecedentPosition) []domain.PrecedentPosition {
	if r == nil || len(in) == 0 {
		return in
	}
	out := make([]domain.PrecedentPosition, len(in))
	copy(out, in)
	for i := range out {
		out[i].Rationale = r.Redact(out[i].Rationale)
	}
	return out
}

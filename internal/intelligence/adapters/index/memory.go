// Package index is the Intelligence Gateway's in-memory nearest-neighbour search over the
// Operational Semantic Index (KS2, Δ3a) — a brute-force cosine scan behind the app.VectorIndex
// port. At the enterprise's own <=~50k Positions this is ~47 ms/query (measured), negligible
// beside the LLM call, and needs no pgvector extension. The index is loaded from the store on
// boot and kept fresh by the population consumer; it is derived and rebuildable (D12), never
// truth.
package index

import (
	"math"
	"sort"
	"sync"

	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

var _ app.VectorIndex = (*Memory)(nil)

type indexed struct {
	rec  store.EmbeddingRecord
	norm float64 // precomputed L2 norm, so cosine is one dot product per query
}

// Memory is a concurrency-safe in-memory vector index. Reads (Search) and writes (Load / Upsert
// from the population consumer) are guarded by a RWMutex, so retrieval during a live event
// stream is safe.
type Memory struct {
	mu   sync.RWMutex
	byID map[string]int // findingID → slice position, for upsert-in-place
	recs []indexed
}

// NewMemory returns an empty index.
func NewMemory() *Memory { return &Memory{byID: map[string]int{}} }

// Load replaces the whole index — the boot path, from store.LoadAll.
func (m *Memory) Load(records []store.EmbeddingRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID = make(map[string]int, len(records))
	m.recs = make([]indexed, 0, len(records))
	for _, r := range records {
		m.byID[r.FindingID] = len(m.recs)
		m.recs = append(m.recs, indexed{rec: r, norm: l2(r.Vector)})
	}
}

// Upsert adds or replaces one entry, keyed by Finding id — the population consumer calls it
// when a PositionEstablished/Revised event is applied, so the live index matches the store.
func (m *Memory) Upsert(r store.EmbeddingRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := indexed{rec: r, norm: l2(r.Vector)}
	if i, ok := m.byID[r.FindingID]; ok {
		m.recs[i] = e
		return
	}
	m.byID[r.FindingID] = len(m.recs)
	m.recs = append(m.recs, e)
}

// Len returns the number of indexed vectors (telemetry / tests).
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.recs)
}

// Search returns up to k past Positions most cosine-similar to query, excluding
// excludeReleaseID, each with its Score. A zero-magnitude query or a non-positive k returns
// nothing; entries of a different dimensionality (a stale embedding model) are skipped rather
// than mismatched, so a model swap degrades gracefully until the index is rebuilt.
func (m *Memory) Search(query []float32, k int, excludeReleaseID string) []domain.PrecedentPosition {
	if k <= 0 {
		return nil
	}
	qn := l2(query)
	if qn == 0 {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	hits := make([]domain.PrecedentPosition, 0, len(m.recs))
	for _, e := range m.recs {
		if excludeReleaseID != "" && e.rec.ReleaseID == excludeReleaseID {
			continue
		}
		if e.norm == 0 || len(e.rec.Vector) != len(query) {
			continue
		}
		score := dot(query, e.rec.Vector) / (qn * e.norm)
		hits = append(hits, domain.PrecedentPosition{
			ReleaseID: e.rec.ReleaseID,
			Stance:    e.rec.Stance,
			Rationale: e.rec.Rationale,
			SourceCVE: e.rec.CVE,
			Component: e.rec.Component,
			Score:     score,
		})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

func dot(a, b []float32) float64 {
	var s float64
	for i := range a {
		s += float64(a[i]) * float64(b[i])
	}
	return s
}

func l2(v []float32) float64 {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	return math.Sqrt(s)
}

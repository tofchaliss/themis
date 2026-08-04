package index_test

import (
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/index"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
)

func rec(id, release string, stance string, vec []float32) store.EmbeddingRecord {
	return store.EmbeddingRecord{
		FindingID: id,
		ReleaseID: release,
		CVE:       "CVE-" + id,
		Component: "pkg:golang/example/" + id,
		Stance:    stance,
		Rationale: "because " + id,
		Vector:    vec,
	}
}

func TestSearchRanksBySimilarityDescending(t *testing.T) {
	m := index.NewMemory()
	m.Load([]store.EmbeddingRecord{
		rec("a", "rel-a", "not_affected", []float32{1, 0, 0}),
		rec("b", "rel-b", "affected", []float32{0, 1, 0}),
		rec("c", "rel-c", "mitigated", []float32{0.9, 0.1, 0}),
	})

	got := m.Search([]float32{1, 0, 0}, 3, "")
	if len(got) != 3 {
		t.Fatalf("results: got %d want 3", len(got))
	}
	if got[0].SourceCVE != "CVE-a" {
		t.Fatalf("top hit: got %q want CVE-a", got[0].SourceCVE)
	}
	// scores must be non-increasing
	for i := 1; i < len(got); i++ {
		if got[i-1].Score < got[i].Score {
			t.Fatalf("not sorted: %v", got)
		}
	}
	// the retrieved precedent carries its labels
	if got[0].Stance != "not_affected" || got[0].ReleaseID != "rel-a" {
		t.Fatalf("labels: got %+v", got[0])
	}
}

func TestSearchExcludesRelease(t *testing.T) {
	m := index.NewMemory()
	m.Load([]store.EmbeddingRecord{
		rec("a", "rel-a", "affected", []float32{1, 0, 0}),
		rec("b", "rel-b", "affected", []float32{0.99, 0.01, 0}),
	})
	got := m.Search([]float32{1, 0, 0}, 5, "rel-a")
	if len(got) != 1 || got[0].ReleaseID != "rel-b" {
		t.Fatalf("expected only rel-b, got %+v", got)
	}
}

func TestSearchKLimit(t *testing.T) {
	m := index.NewMemory()
	m.Load([]store.EmbeddingRecord{
		rec("a", "rel-a", "affected", []float32{1, 0}),
		rec("b", "rel-b", "affected", []float32{0.9, 0.1}),
		rec("c", "rel-c", "affected", []float32{0.8, 0.2}),
	})
	if got := m.Search([]float32{1, 0}, 2, ""); len(got) != 2 {
		t.Fatalf("k=2: got %d results", len(got))
	}
}

func TestSearchEmptyQueryOrK(t *testing.T) {
	m := index.NewMemory()
	m.Load([]store.EmbeddingRecord{rec("a", "rel-a", "affected", []float32{1, 0})})
	if got := m.Search([]float32{0, 0}, 5, ""); got != nil {
		t.Errorf("zero query should return nil, got %v", got)
	}
	if got := m.Search([]float32{1, 0}, 0, ""); got != nil {
		t.Errorf("k=0 should return nil, got %v", got)
	}
}

func TestSearchSkipsDimensionMismatch(t *testing.T) {
	m := index.NewMemory()
	m.Load([]store.EmbeddingRecord{
		rec("a", "rel-a", "affected", []float32{1, 0, 0}), // dim 3
		rec("b", "rel-b", "affected", []float32{1, 0}),    // dim 2 — a stale model
	})
	got := m.Search([]float32{1, 0}, 5, "") // query dim 2
	if len(got) != 1 || got[0].ReleaseID != "rel-b" {
		t.Fatalf("expected only the dim-2 entry, got %+v", got)
	}
}

func TestUpsertReplacesInPlaceAndAppends(t *testing.T) {
	m := index.NewMemory()
	m.Upsert(rec("a", "rel-a", "affected", []float32{1, 0}))
	m.Upsert(rec("a", "rel-a", "not_affected", []float32{0, 1})) // same id → replace
	if m.Len() != 1 {
		t.Fatalf("len after replace: got %d want 1", m.Len())
	}
	m.Upsert(rec("b", "rel-b", "affected", []float32{1, 0})) // new id → append
	if m.Len() != 2 {
		t.Fatalf("len after append: got %d want 2", m.Len())
	}
	// the replaced record 'a' must now reflect the new stance + vector.
	for _, p := range m.Search([]float32{0, 1}, 5, "") {
		if p.ReleaseID == "rel-a" && p.Stance != "not_affected" {
			t.Fatalf("upsert did not replace in place: %+v", p)
		}
	}
}

func TestLoadResetsIndex(t *testing.T) {
	m := index.NewMemory()
	m.Load([]store.EmbeddingRecord{rec("a", "rel-a", "affected", []float32{1, 0})})
	m.Load([]store.EmbeddingRecord{rec("b", "rel-b", "affected", []float32{0, 1})})
	if m.Len() != 1 {
		t.Fatalf("load should replace, len got %d want 1", m.Len())
	}
	got := m.Search([]float32{0, 1}, 5, "")
	if len(got) != 1 || got[0].ReleaseID != "rel-b" {
		t.Fatalf("expected the reloaded entry, got %+v", got)
	}
}

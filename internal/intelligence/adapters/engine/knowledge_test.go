package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

type stubEmbedder struct {
	vec []float32
	err error
}

func (s stubEmbedder) Embed(context.Context, string) ([]float32, error) { return s.vec, s.err }
func (s stubEmbedder) Model() string                                    { return "stub" }

type stubIndex struct {
	gotQuery []float32
	gotK     int
	gotExcl  string
	ret      []domain.PrecedentPosition
	called   bool
}

func (s *stubIndex) Search(q []float32, k int, excl string) []domain.PrecedentPosition {
	s.called, s.gotQuery, s.gotK, s.gotExcl = true, q, k, excl
	return s.ret
}

func groundingFor(release string, components []string) domain.AssembledContext {
	return domain.AssembledContext{
		Finding:   domain.FindingView{ID: "f1", ReleaseID: release, Components: components},
		Faultline: domain.FaultlineView{Severity: "high"},
	}
}

func TestKnowledgeEngineKind(t *testing.T) {
	e := engine.NewKnowledgeEngine(stubEmbedder{}, &stubIndex{}, 5)
	if e.Kind() != domain.EngineKnowledge {
		t.Fatalf("kind: got %q want %q", e.Kind(), domain.EngineKnowledge)
	}
}

func TestKnowledgeEngineHappyPath(t *testing.T) {
	idx := &stubIndex{ret: []domain.PrecedentPosition{
		{ReleaseID: "rel-x", Stance: "not_affected", SourceCVE: "CVE-9", Score: 0.9},
	}}
	e := engine.NewKnowledgeEngine(stubEmbedder{vec: []float32{1, 2, 3}}, idx, 0) // 0 → default 5

	res, err := e.Execute(context.Background(), app.ExecInput{
		Context: groundingFor("rel-subject", []string{"pkg:golang/openssl"}),
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.Precedents) != 1 || res.Precedents[0].SourceCVE != "CVE-9" {
		t.Fatalf("precedents: got %+v", res.Precedents)
	}
	if !idx.called {
		t.Fatal("index.Search was not called")
	}
	if idx.gotK != 5 {
		t.Errorf("topK default: got %d want 5", idx.gotK)
	}
	if idx.gotExcl != "rel-subject" {
		t.Errorf("exclude release: got %q want rel-subject", idx.gotExcl)
	}
	if len(idx.gotQuery) != 3 {
		t.Errorf("query vector not forwarded: got %v", idx.gotQuery)
	}
}

func TestKnowledgeEngineEmptyTextSkipsRetrieval(t *testing.T) {
	idx := &stubIndex{}
	e := engine.NewKnowledgeEngine(stubEmbedder{vec: []float32{1}}, idx, 5)

	// No components and no severity → empty embed text → no retrieval.
	res, err := e.Execute(context.Background(), app.ExecInput{
		Context: domain.AssembledContext{Finding: domain.FindingView{ReleaseID: "r"}},
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Precedents != nil {
		t.Fatalf("expected no precedents, got %+v", res.Precedents)
	}
	if idx.called {
		t.Fatal("index.Search must not be called for empty subject text")
	}
}

func TestKnowledgeEngineEmbedErrorDegradesToNoPrecedent(t *testing.T) {
	idx := &stubIndex{}
	e := engine.NewKnowledgeEngine(stubEmbedder{err: errors.New("embedder down")}, idx, 5)

	res, err := e.Execute(context.Background(), app.ExecInput{
		Context: groundingFor("r", []string{"pkg:golang/openssl"}),
	})
	if err != nil {
		t.Fatalf("execute must not error on embed failure: %v", err)
	}
	if res.Precedents != nil {
		t.Fatalf("expected no precedents on embed error, got %+v", res.Precedents)
	}
	if idx.called {
		t.Fatal("index.Search must not be called when embedding failed")
	}
}

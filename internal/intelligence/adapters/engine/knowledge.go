package engine

import (
	"context"

	"github.com/themis-project/themis/internal/intelligence/adapters/embed"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

var _ app.Engine = (*KnowledgeEngine)(nil)

// KnowledgeEngine is the retrieval step (Δ3a, EngineKnowledge): it embeds the subject Finding's
// text and searches the Operational Semantic Index (KS2) for the top-k semantically similar
// past Enterprise Positions, returning them as precedent to enrich the grounding. It decides
// nothing and calls no LLM — precedent is context for the LLM step (Book IV Ch 8, RC-1). It
// generalises the Δ2 exact-CVE precedent seam to similar-CVE precedent (G-AI-3).
type KnowledgeEngine struct {
	embedder app.Embedder
	index    app.VectorIndex
	topK     int
}

// NewKnowledgeEngine builds the engine over an embedder and a vector index; topK<=0 defaults
// to 5.
func NewKnowledgeEngine(embedder app.Embedder, index app.VectorIndex, topK int) *KnowledgeEngine {
	if topK <= 0 {
		topK = 5
	}
	return &KnowledgeEngine{embedder: embedder, index: index, topK: topK}
}

// Kind reports that this is the Knowledge (retrieval) engine.
func (e *KnowledgeEngine) Kind() domain.EngineKind { return domain.EngineKnowledge }

// Execute embeds the subject Finding and fills EngineResult.Precedents with similar past
// Positions. Retrieval is best-effort grounding: an empty subject text or an embed failure
// returns no precedent (nil), never an error — a missing precedent must not block the
// recommendation (the same degrade-to-none contract as the Δ2 exact-CVE precedent pull).
func (e *KnowledgeEngine) Execute(ctx context.Context, in app.ExecInput) (app.EngineResult, error) {
	text := embed.SubjectText(in.Context.Faultline().Severity, in.Context.Finding().Components)
	if text == "" {
		return app.EngineResult{}, nil
	}
	vec, err := e.embedder.Embed(ctx, text)
	if err != nil {
		return app.EngineResult{}, nil
	}
	return app.EngineResult{Precedents: e.index.Search(vec, e.topK, in.Context.Finding().ReleaseID)}, nil
}

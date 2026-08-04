package embed

import (
	"context"
	"hash/fnv"
	"math"
	"strings"
	"unicode"

	"github.com/themis-project/themis/internal/intelligence/app"
)

var _ app.Embedder = (*FakeEmbedder)(nil)

// FakeEmbedder is a deterministic, model-free embedder for CI and the Δ3a e2e. It is a
// feature-hashing embedder: each token maps to a dimension (by hash) and its occurrences
// accumulate, then the vector is L2-normalized. Unlike a plain hash-to-random, cosine
// similarity therefore tracks TOKEN OVERLAP — so "openssl heap overflow" lands nearer
// "openssl buffer overflow" than "python yaml bug". Crude, but enough to prove retrieval
// end-to-end without a running model (R5 stays a demo-gate, not a build-gate).
type FakeEmbedder struct {
	dim int
}

// NewFakeEmbedder returns a fake producing dim-dimensional unit vectors (dim<=0 defaults to
// 64). A larger dim reduces hash collisions.
func NewFakeEmbedder(dim int) *FakeEmbedder {
	if dim <= 0 {
		dim = 64
	}
	return &FakeEmbedder{dim: dim}
}

// Model identifies the fake for telemetry and index model-stamping.
func (f *FakeEmbedder) Model() string { return "fake-hash" }

// Embed returns a deterministic unit vector whose direction reflects text's token set. Empty
// or token-less text returns an all-zero vector (the index treats a zero vector as unmatchable).
func (f *FakeEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	v := make([]float32, f.dim)
	for _, tok := range tokenize(text) {
		v[tokenHash(tok)%uint32(f.dim)]++
	}
	normalize(v)
	return v, nil
}

// tokenize lowercases and splits on any non-alphanumeric run, so punctuation and case never
// change the token set.
func tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
}

func tokenHash(tok string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tok))
	return h.Sum32()
}

// normalize scales v to unit L2 length in place; an all-zero vector is left unchanged.
func normalize(v []float32) {
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	if sum == 0 {
		return
	}
	inv := float32(1 / math.Sqrt(sum))
	for i := range v {
		v[i] *= inv
	}
}

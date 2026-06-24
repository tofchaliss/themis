package correlation

import (
	"context"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
)

// The merged finding set must be independent of the order in which sources are
// queried: for a given (component, cve) the highest-precedence source always
// wins (CR-2/CR-3). This is the property the per-source-order table test
// generalises — a regression here means a finding's verdict depends on wiring
// order, exactly the non-determinism the single Correlator removes.
func TestCorrelatorMergeOrderIndependentProperty(t *testing.T) {
	sources := []string{
		domain.FindingSourceOSV, domain.FindingSourceNVD,
		domain.FindingSourceDistroOSV, domain.FindingSourceRHSA, domain.FindingSourceCatalog,
	}
	ecosystems := []string{"npm", "apk", "rpm"}

	rapid.Check(t, func(t *rapid.T) {
		ecosystem := rapid.SampledFrom(ecosystems).Draw(t, "ecosystem")
		// Each stub source reports CVE-1 with its own source label.
		picks := rapid.SliceOfNDistinct(rapid.SampledFrom(sources), 1, len(sources),
			func(s string) string { return s }).Draw(t, "sources")

		build := func(order []string) []*stubSource {
			out := make([]*stubSource, 0, len(order))
			for _, s := range order {
				out = append(out, &stubSource{name: s, records: []domain.VulnerabilityRecord{
					{CVEID: "CVE-1", Source: s},
				}})
			}
			return out
		}

		component := domain.CanonicalComponent{Ecosystem: ecosystem}

		forward := build(picks)
		out1, err := NewCorrelator(nil, toSources(forward)...).FetchForComponent(context.Background(), component)
		if err != nil {
			t.Fatal(err)
		}

		reversed := make([]string, len(picks))
		for i, s := range picks {
			reversed[len(picks)-1-i] = s
		}
		out2, err := NewCorrelator(nil, toSources(build(reversed))...).FetchForComponent(context.Background(), component)
		if err != nil {
			t.Fatal(err)
		}

		if len(out1) != 1 || len(out2) != 1 {
			t.Fatalf("expected 1 merged finding, got %d/%d", len(out1), len(out2))
		}
		if out1[0].Source != out2[0].Source {
			t.Fatalf("merge order-dependent: %q vs %q (ecosystem %s, sources %v)",
				out1[0].Source, out2[0].Source, ecosystem, picks)
		}
		// And the winner must be the highest-precedence source present.
		want := picks[0]
		for _, s := range picks[1:] {
			if domain.FindingSourcePrecedence(ecosystem, s) > domain.FindingSourcePrecedence(ecosystem, want) {
				want = s
			}
		}
		if out1[0].Source != want {
			t.Fatalf("merge winner = %q, want highest-precedence %q (ecosystem %s)", out1[0].Source, want, ecosystem)
		}
	})
}

func toSources(in []*stubSource) []domain.CorrelationSource {
	out := make([]domain.CorrelationSource, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

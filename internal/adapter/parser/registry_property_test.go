package parser

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/testutil/gen"
)

// TestParseRobustnessProperty asserts the registry never panics on arbitrary
// input and always returns a self-consistent outcome.
func TestParseRobustnessProperty(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	rapid.Check(t, func(t *rapid.T) {
		format := rapid.SampledFrom([]string{
			domain.SBOMFormatCycloneDX,
			domain.SBOMFormatSPDX,
			domain.SBOMFormatTrivy,
			domain.SBOMFormatGrype,
			"bogus",
		}).Draw(t, "format")
		specVersion := rapid.SampledFrom([]string{"", "1.6", "1.5", "2.3", "3.0", "1", "99"}).Draw(t, "spec")
		raw := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "raw")

		outcome := reg.Parse(context.Background(), format, specVersion, raw)

		acceptedFromStatus := outcome.Status == domain.ParseStatusAccepted
		acceptedFromCode := outcome.HTTPStatus == 200
		if outcome.Accepted != acceptedFromStatus || outcome.Accepted != acceptedFromCode {
			t.Fatalf("inconsistent outcome: accepted=%v status=%q code=%d",
				outcome.Accepted, outcome.Status, outcome.HTTPStatus)
		}
		if !outcome.Accepted && outcome.Status == domain.ParseStatusAccepted {
			t.Fatalf("rejected outcome marked accepted status")
		}
	})
}

// TestParseIdempotencyProperty asserts parsing identical bytes twice yields an
// identical canonical result.
func TestParseIdempotencyProperty(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	rapid.Check(t, func(t *rapid.T) {
		format := rapid.SampledFrom(domain.SupportedSBOMFormats()).Draw(t, "format")
		raw := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "raw")

		first := reg.Parse(context.Background(), format, "", raw)
		second := reg.Parse(context.Background(), format, "", raw)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("non-idempotent parse for format=%q", format)
		}
	})
}

// TestCycloneDXValidComponentsProperty asserts that for generated-valid CycloneDX
// documents every emitted component carries a non-empty, parseable PURL.
func TestCycloneDXValidComponentsProperty(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 8).Draw(t, "components")
		doc := cycloneDXDocument{BOMFormat: "CycloneDX", SpecVersion: "1.6"}
		for i := 0; i < n; i++ {
			eco := gen.Ecosystem(t)
			name := gen.PkgName(t)
			version := gen.PkgVersion(t)
			doc.Components = append(doc.Components, cycloneDXComponent{
				Name:    name,
				Version: version,
				PURL:    buildPURL(eco, name, version),
			})
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		outcome := reg.Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.6", raw)
		if !outcome.Accepted {
			t.Fatalf("valid document rejected: %s", outcome.Message)
		}
		if len(outcome.SBOM.Components) != n {
			t.Fatalf("component count = %d want %d", len(outcome.SBOM.Components), n)
		}
		for _, c := range outcome.SBOM.Components {
			if c.PURL == "" {
				t.Fatalf("empty PURL in canonical component %+v", c)
			}
			if _, ok := ecosystemFromPURL(c.PURL); !ok {
				t.Fatalf("unparseable canonical PURL %q", c.PURL)
			}
			if c.Ecosystem == "" {
				t.Fatalf("empty ecosystem for component %+v", c)
			}
		}
	})
}

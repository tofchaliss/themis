package parser

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestSyftAdapterFormat(t *testing.T) {
	if (SyftAdapter{}).Format() != domain.SBOMFormatSyft {
		t.Fatalf("Format() = %q", (SyftAdapter{}).Format())
	}
}

func TestSyftAdapterParse(t *testing.T) {
	raw := []byte(`{
	  "artifacts": [
	    {"id": "a", "name": "app",    "version": "1", "purl": "pkg:npm/app@1"},
	    {"id": "b", "name": "lodash", "version": "4", "purl": "pkg:npm/lodash@4"},
	    {"id": "c", "name": "dup",    "version": "4", "purl": "pkg:npm/lodash@4"},
	    {"id": "",  "name": "noid",   "version": "1", "purl": "pkg:npm/noid@1"},
	    {"id": "z", "name": "nopurl", "version": "1", "purl": ""}
	  ],
	  "artifactRelationships": [
	    {"parent": "a", "child": "b", "type": "dependency-of"},
	    {"parent": "a", "child": "b", "type": "contains"},
	    {"parent": "a", "child": "missing", "type": "dependency-of"}
	  ]
	}`)
	sbom, err := SyftAdapter{}.Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 3 {
		t.Fatalf("components = %d, want 3 (dedup + skip empty purl)", len(sbom.Components))
	}
	if len(sbom.Dependencies) != 1 {
		t.Fatalf("dependencies = %d, want 1 (only resolvable dependency-of)", len(sbom.Dependencies))
	}
	edge := sbom.Dependencies[0]
	if edge.FromPURL != "pkg:npm/app@1" || edge.ToPURL != "pkg:npm/lodash@4" || edge.RelationshipType != "depends_on" {
		t.Fatalf("edge = %+v", edge)
	}
}

func TestSyftAdapterParseInvalidJSON(t *testing.T) {
	if _, err := (SyftAdapter{}).Parse(context.Background(), []byte("{bad"), ""); err == nil {
		t.Fatal("want json error")
	}
}

func TestSyftAdapterParseNoArtifacts(t *testing.T) {
	if _, err := (SyftAdapter{}).Parse(context.Background(), []byte(`{"artifacts":[{"purl":""}]}`), ""); err == nil {
		t.Fatal("want no-artifacts error")
	}
}

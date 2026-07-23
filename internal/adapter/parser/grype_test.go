package parser

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestGrypeAdapterFormat(t *testing.T) {
	if (GrypeAdapter{}).Format() != domain.SBOMFormatGrype {
		t.Fatalf("Format() = %q", (GrypeAdapter{}).Format())
	}
}

func TestGrypeAdapterParse(t *testing.T) {
	raw := []byte(`{
	  "artifacts": [
	    {"name": "busybox", "version": "1.36.1-r19", "purl": "pkg:apk/alpine/busybox@1.36.1-r19"},
	    {"name": "lodash",  "version": "4.17.21",    "purl": "pkg:npm/lodash@4.17.21"},
	    {"name": "dupe",     "version": "1",          "purl": "pkg:npm/lodash@4.17.21"},
	    {"name": "nopurl",   "version": "9",          "purl": ""}
	  ]
	}`)
	sbom, err := GrypeAdapter{}.Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if sbom.Format != domain.SBOMFormatGrype {
		t.Fatalf("format = %q", sbom.Format)
	}
	if len(sbom.Components) != 2 {
		t.Fatalf("components = %d, want 2 (dedup + skip empty purl)", len(sbom.Components))
	}
	if sbom.Components[0].PURL != "pkg:apk/alpine/busybox@1.36.1-r19" || sbom.Components[0].Ecosystem == "" {
		t.Fatalf("first component wrong: %+v", sbom.Components[0])
	}
}

func TestGrypeAdapterParseInvalidJSON(t *testing.T) {
	if _, err := (GrypeAdapter{}).Parse(context.Background(), []byte("{not json"), ""); err == nil {
		t.Fatal("want json error")
	}
}

func TestGrypeAdapterParseNoArtifacts(t *testing.T) {
	if _, err := (GrypeAdapter{}).Parse(context.Background(), []byte(`{"artifacts":[{"purl":""}]}`), ""); err == nil {
		t.Fatal("want no-artifacts error")
	}
}

package parser

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSPDX23Adapter(t *testing.T) {
	raw := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"packages":[
			{
				"SPDXID":"SPDXRef-A",
				"name":"lodash",
				"versionInfo":"1.0.0",
				"licenseConcluded":"MIT",
				"licenseDeclared":"Apache-2.0",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/lodash@1.0.0"}]
			},
			{
				"SPDXID":"SPDXRef-B",
				"name":"express",
				"versionInfo":"2.0.0",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/express@2.0.0"}]
			},
			{"SPDXID":"SPDXRef-C","name":"orphan","versionInfo":"0.1"}
		],
		"relationships":[
			{"spdxElementId":"SPDXRef-B","relatedSpdxElement":"SPDXRef-A","relationshipType":"DEPENDS_ON"},
			{"spdxElementId":"SPDXRef-B","relatedSpdxElement":"SPDXRef-C","relationshipType":"DESCRIBES"}
		]
	}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 2 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	if len(sbom.Dependencies) != 1 {
		t.Fatalf("dependencies = %+v", sbom.Dependencies)
	}
	if len(sbom.Components[0].Licenses) != 2 {
		t.Fatalf("licenses = %v", sbom.Components[0].Licenses)
	}
}

func TestSPDX30Adapter(t *testing.T) {
	raw := []byte(`{
		"spdxVersion":"SPDX-3.0",
		"elements":[
			{
				"type":"software_Package",
				"SPDXID":"SPDXRef-A",
				"name":"lodash",
				"version":"1.0.0",
				"licenseConcluded":"MIT",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:npm/lodash@1.0.0"}]
			},
			{
				"type":"Relationship",
				"from":"SPDXRef-B",
				"to":["SPDXRef-A"],
				"relationshipType":"dependsOn"
			},
			{
				"type":"software_Package",
				"SPDXID":"SPDXRef-B",
				"name":"express",
				"version":"2.0.0",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:npm/express@2.0.0"}]
			}
		]
	}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "3.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 2 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	if len(sbom.Dependencies) != 1 {
		t.Fatalf("dependencies = %+v", sbom.Dependencies)
	}
}

func TestSPDXAdapterErrors(t *testing.T) {
	_, err := (SPDXAdapter{}).Parse(context.Background(), []byte("{"), "2.3")
	if err == nil {
		t.Fatal("expected json error")
	}
	_, err = (SPDXAdapter{}).Parse(context.Background(), []byte(`{"spdxVersion":"SPDX-9.9"}`), "9.9")
	if err == nil {
		t.Fatal("expected unsupported version")
	}
}

func TestSPDXAdapterInvalidJSONDetectingVersion(t *testing.T) {
	_, err := (SPDXAdapter{}).Parse(context.Background(), []byte("{"), "")
	if err == nil || !strings.Contains(err.Error(), "invalid spdx json") {
		t.Fatalf("err = %v", err)
	}
}

func TestSPDX30InvalidJSON(t *testing.T) {
	_, err := (SPDXAdapter{}).Parse(context.Background(), []byte("{"), "3.0")
	if err == nil || !strings.Contains(err.Error(), "invalid spdx json") {
		t.Fatalf("err = %v", err)
	}
}

func TestSPDX30SkipsNonDependencyRelationships(t *testing.T) {
	raw := []byte(`{
		"spdxVersion":"SPDX-3.0",
		"elements":[
			{"type":"software_Package","SPDXID":"A","name":"a","version":"1","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:npm/a@1"}]},
			{"type":"Relationship","from":"A","to":["A"],"relationshipType":"describes"}
		]
	}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "3.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Dependencies) != 0 {
		t.Fatalf("dependencies = %+v", sbom.Dependencies)
	}
}

func TestSPDXAdapterUnsupportedDefaultVersion(t *testing.T) {
	_, err := (SPDXAdapter{}).Parse(context.Background(), []byte(`{"spdxVersion":""}`), "")
	if err == nil || !strings.Contains(err.Error(), "unsupported spdx spec version") {
		t.Fatalf("err = %v", err)
	}
}

func TestSPDXAdapterDetectsVersionFromDocument(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"A","name":"x","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:npm/x@1"}]}]}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if sbom.SpecVersion != "2.3" {
		t.Fatalf("spec version = %q", sbom.SpecVersion)
	}
}

func TestSPDXMalformedPURL(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"A","name":"x","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"bad"}]}]}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 0 || len(sbom.Warnings) != 1 {
		t.Fatalf("components=%d warnings=%d", len(sbom.Components), len(sbom.Warnings))
	}
}

func TestSPDX23MalformedPURL(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"A","name":"x","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:"}]}]}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 0 || len(sbom.Warnings) != 1 || !strings.Contains(sbom.Warnings[0], "malformed") {
		t.Fatalf("components=%d warnings=%v", len(sbom.Components), sbom.Warnings)
	}
}

func TestSPDX30PackageWithoutPURL(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-3.0","elements":[{"type":"software_Package","SPDXID":"A","name":"x","version":"1"}]}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "3.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Warnings) != 1 || !strings.Contains(sbom.Warnings[0], "without package-manager purl") {
		t.Fatalf("warnings = %v", sbom.Warnings)
	}
}

func TestPurlFromExternalRefsSkipsOtherCategories(t *testing.T) {
	if _, ok := purlFromExternalRefs([]spdxExternalRef{{
		ReferenceCategory: "SECURITY",
		ReferenceLocator:  "pkg:npm/a@1",
	}}); ok {
		t.Fatal("expected false for non package-manager ref")
	}
	if purl, ok := purlFromExternalRefs([]spdxExternalRef{{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceLocator:  "pkg:npm/a@1",
	}}); !ok || purl != "pkg:npm/a@1" {
		t.Fatalf("purl = %q ok=%v", purl, ok)
	}
}

func TestNormalizeSPDXVersionDefault(t *testing.T) {
	if got := normalizeSPDXVersion("custom-version"); got != "custom-version" {
		t.Fatalf("normalize = %q", got)
	}
}

func TestSPDXLicenseHelpers(t *testing.T) {
	if got := spdxLicenses("NOASSERTION", "MIT"); len(got) != 1 || got[0] != "MIT" {
		t.Fatalf("licenses = %v", got)
	}
	if got := normalizeSPDXVersion("SPDX-3.0"); got != "3.0" {
		t.Fatalf("normalize = %q", got)
	}
	if err := validateSPDXVersion("2.3"); err != nil {
		t.Fatal(err)
	}
	if err := validateSPDXVersion("bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPurlFromExternalRefsReferenceType(t *testing.T) {
	purl, ok := purlFromExternalRefs([]spdxExternalRef{{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "npm/lodash@1",
	}})
	if !ok || purl != "npm/lodash@1" {
		t.Fatalf("purl = %q ok=%v", purl, ok)
	}
}

func TestSPDXRelationshipSkipsUnknownIDs(t *testing.T) {
	raw := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"packages":[{"SPDXID":"A","name":"x","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:npm/x@1"}]}],
		"relationships":[{"spdxElementId":"A","relatedSpdxElement":"missing","relationshipType":"DEPENDS_ON"}]
	}`)
	sbom, err := (SPDXAdapter{}).Parse(context.Background(), raw, "2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Dependencies) != 0 {
		t.Fatalf("dependencies = %+v", sbom.Dependencies)
	}
}

func TestCycloneDXLicenseHelpers(t *testing.T) {
	licenses := cycloneDXLicenses([]cycloneDXLicense{{License: cycloneDXLicenseChoice{ID: "MIT"}}})
	if len(licenses) != 1 {
		t.Fatalf("licenses = %v", licenses)
	}
	if err := validateCycloneDXVersion("1.4"); err != nil {
		t.Fatal(err)
	}
	if err := validateCycloneDXVersion("bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSPDX30MalformedPackage(t *testing.T) {
	doc := spdx30Document{
		Elements: []spdx30Element{{
			Type: "software_Package", SPDXID: "A", Name: "x", Version: "1",
			ExternalRefs: []spdxExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceLocator: "pkg:"}},
		}},
	}
	raw, _ := json.Marshal(doc)
	sbom, err := parseSPDX30(raw, "3.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Warnings) != 1 || !strings.Contains(sbom.Warnings[0], "malformed") {
		t.Fatalf("warnings = %v", sbom.Warnings)
	}
}

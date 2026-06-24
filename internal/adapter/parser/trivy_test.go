package parser

import (
	"context"
	"testing"
)

func TestTrivyAdapterBuildsComponents(t *testing.T) {
	raw := []byte(`{
		"Results":[
			{
				"Target":"node_modules/lodash (npm)",
				"Type":"npm",
				"Vulnerabilities":[
					{"VulnerabilityID":"CVE-2021-23337","Severity":"HIGH","FixedVersion":"4.17.22","PkgName":"lodash","InstalledVersion":"4.17.21"}
				]
			}
		]
	}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("components = %+v", sbom.Components)
	}
}

// TestTrivyAdapterMultiplePackagesPerResult locks in the CR-9 fix: a result with
// several packages yields one component each, not just the first.
func TestTrivyAdapterMultiplePackagesPerResult(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"app","Type":"npm","Vulnerabilities":[
		{"VulnerabilityID":"CVE-1","PkgName":"lodash","InstalledVersion":"4.17.21"},
		{"VulnerabilityID":"CVE-2","PkgName":"express","InstalledVersion":"4.18.2"},
		{"VulnerabilityID":"CVE-3","PkgName":"lodash","InstalledVersion":"4.17.21"}
	]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 2 {
		t.Fatalf("want 2 distinct components, got %+v", sbom.Components)
	}
}

func TestTrivyAdapterEmptyResults(t *testing.T) {
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), []byte(`{"Results":[]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 0 {
		t.Fatalf("sbom = %+v", sbom)
	}
}

func TestTrivyAdapterDedupesComponentsAcrossResults(t *testing.T) {
	raw := []byte(`{"Results":[
		{"Target":"a","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"lodash","InstalledVersion":"1.0.0"}]},
		{"Target":"b","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2","PkgName":"lodash","InstalledVersion":"1.0.0"}]}
	]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
}

func TestTrivyAdapterTargetWithoutVulnerabilities(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"my-app (npm)","Type":"npm","Vulnerabilities":[]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].PURL != "pkg:npm/my-app" {
		t.Fatalf("components = %+v", sbom.Components)
	}
}

func TestTrivyAdapterEmptyTypeSkipped(t *testing.T) {
	raw := []byte(`{"Results":[{"Type":"","Vulnerabilities":[{"VulnerabilityID":"CVE-4","PkgName":"lib","InstalledVersion":"1.0"}]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 0 {
		t.Fatalf("components = %+v", sbom.Components)
	}
}

func TestTrivyAdapterSkipsEmptyPkgName(t *testing.T) {
	// A result mixing a packaged vuln with an empty-PkgName entry: the empty one
	// is skipped, the packaged one yields a component (exercises the inner skip).
	raw := []byte(`{"Results":[{"Target":"app","Type":"npm","Vulnerabilities":[
		{"VulnerabilityID":"CVE-1","PkgName":"","InstalledVersion":""},
		{"VulnerabilityID":"CVE-2","PkgName":"lodash","InstalledVersion":"1.0.0"}
	]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].PURL != "pkg:npm/lodash@1.0.0" {
		t.Fatalf("components = %+v", sbom.Components)
	}
}

func TestTrivyAdapterMalformedJSON(t *testing.T) {
	_, err := (TrivyAdapter{}).Parse(context.Background(), []byte("{"), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrivyTargetPURL(t *testing.T) {
	if got := trivyTargetPURL(trivyResult{Target: "my-app (npm)", Type: "npm"}); got != "pkg:npm/my-app" {
		t.Fatalf("purl = %q", got)
	}
	if got := trivyTargetPURL(trivyResult{Target: "app"}); got != "" {
		t.Fatalf("empty type purl = %q", got)
	}
	if got := trivyTargetPURL(trivyResult{Type: "npm", Target: ""}); got != "pkg:npm/npm" {
		t.Fatalf("type-only purl = %q", got)
	}
}

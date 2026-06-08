package parser

import (
	"context"
	"testing"
)

func TestTrivyAdapterMapsVulnerabilities(t *testing.T) {
	raw := []byte(`{
		"Results":[
			{
				"Target":"node_modules/lodash (npm)",
				"Type":"npm",
				"Vulnerabilities":[
					{
						"VulnerabilityID":"CVE-2021-23337",
						"Severity":"HIGH",
						"FixedVersion":"4.17.22",
						"PkgName":"lodash",
						"InstalledVersion":"4.17.21",
						"CVSS":{"nvd":{"V3Score":7.2,"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
					}
				]
			}
		]
	}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %+v", sbom.Vulnerabilities)
	}
	v := sbom.Vulnerabilities[0]
	if v.CVEID != "CVE-2021-23337" || v.Severity != "high" || v.CVSSScore != 7.2 || len(v.FixVersions) != 1 {
		t.Fatalf("vuln = %+v", v)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("components = %+v", sbom.Components)
	}
}

func TestTrivyAdapterEmptyResults(t *testing.T) {
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), []byte(`{"Results":[]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 0 || len(sbom.Vulnerabilities) != 0 {
		t.Fatalf("sbom = %+v", sbom)
	}
}

func TestTrivyAdapterUnknownSeverity(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"app","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"x","InstalledVersion":"1"}]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if sbom.Vulnerabilities[0].Severity != "unknown" {
		t.Fatalf("severity = %q", sbom.Vulnerabilities[0].Severity)
	}
	if len(sbom.Warnings) != 1 {
		t.Fatalf("warnings = %v", sbom.Warnings)
	}
}

func TestTrivyAdapterBuildsAffectedWhenComponentMissing(t *testing.T) {
	raw := []byte(`{"Results":[{"Type":"","Vulnerabilities":[{"VulnerabilityID":"CVE-4","Severity":"LOW","PkgName":"lib","InstalledVersion":"1.0"}]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 0 {
		t.Fatalf("components = %+v", sbom.Components)
	}
	if len(sbom.Vulnerabilities) != 1 || sbom.Vulnerabilities[0].AffectedPURLs[0] != "" {
		t.Fatalf("vuln = %+v", sbom.Vulnerabilities[0])
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

func TestTrivyAdapterDedupesComponents(t *testing.T) {
	raw := []byte(`{"Results":[
		{"Target":"a","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"LOW","PkgName":"lodash","InstalledVersion":"1.0.0"}]},
		{"Target":"b","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"lodash","InstalledVersion":"1.0.0"}]}
	]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	if len(sbom.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d", len(sbom.Vulnerabilities))
	}
}

func TestTrivyAdapterMalformedJSON(t *testing.T) {
	_, err := (TrivyAdapter{}).Parse(context.Background(), []byte("{"), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrivyComponentPURLFromTarget(t *testing.T) {
	purl := trivyComponentPURL(trivyResult{Target: "my-app (npm)", Type: "npm"})
	if purl != "pkg:npm/my-app" {
		t.Fatalf("purl = %q", purl)
	}
}

func TestTrivyComponentPURLEmptyType(t *testing.T) {
	if purl := trivyComponentPURL(trivyResult{Target: "app"}); purl != "" {
		t.Fatalf("purl = %q", purl)
	}
}

func TestTrivyComponentPURLFromTypeOnly(t *testing.T) {
	purl := trivyComponentPURL(trivyResult{Type: "npm", Target: ""})
	if purl != "pkg:npm/npm" {
		t.Fatalf("purl = %q", purl)
	}
}

func TestTrivyAffectedPURLWithoutComponent(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2","PkgName":"lib","InstalledVersion":"1.2.3"}]}]}`)
	sbom, err := (TrivyAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if sbom.Vulnerabilities[0].AffectedPURLs[0] != "pkg:npm/lib@1.2.3" {
		t.Fatalf("affected = %v", sbom.Vulnerabilities[0].AffectedPURLs)
	}
}

package api

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestToScanVulnerabilityListEnrichment(t *testing.T) {
	epss := 0.42
	kev := true
	exploit := true
	risk := 88.5
	blast := 1.5
	level := "High"
	coverage := "covered"
	items := []domain.ScanVulnerability{{
		ID: "550e8400-e29b-41d4-a716-446655440000", CVEID: "CVE-2024-0001", Severity: "critical",
		EffectiveState: "detected", ComponentPURL: "pkg:apk/alpine/busybox@1.0",
		InstalledVersion: "1.0", FixedVersion: "1.36.1-r2",
		Enrichment: &domain.ScanVulnerabilityEnrichment{
			EPSSScore: &epss, KEVListed: &kev, ExploitPublic: &exploit,
			RiskScore: &risk, BlastRadiusScore: &blast, DeterministicLevel: &level,
			UpstreamVEXCoverage: &coverage,
		},
	}}
	out := toScanVulnerabilityList(items, domain.PageResult{})
	if out.Items == nil || len(*out.Items) != 1 {
		t.Fatalf("items = %#v", out.Items)
	}
	item := (*out.Items)[0]
	if item.Enrichment == nil || item.Enrichment.EpssScore == nil || *item.Enrichment.EpssScore != epss {
		t.Fatalf("enrichment = %#v", item.Enrichment)
	}
	if item.Enrichment.UpstreamVexCoverage == nil || string(*item.Enrichment.UpstreamVexCoverage) != coverage {
		t.Fatalf("upstream_vex_coverage = %#v", item.Enrichment.UpstreamVexCoverage)
	}
	if item.InstalledVersion == nil || *item.InstalledVersion != "1.0" {
		t.Fatalf("installed_version = %#v", item.InstalledVersion)
	}
	if item.FixedVersion == nil || *item.FixedVersion != "1.36.1-r2" {
		t.Fatalf("fixed_version = %#v", item.FixedVersion)
	}
}

// TestToScanVulnerabilityListNoFix verifies an empty fixed/installed version is
// omitted (nil), so "no published fix" surfaces as an absent field rather than "".
func TestToScanVulnerabilityListNoFix(t *testing.T) {
	items := []domain.ScanVulnerability{{
		ID: "550e8400-e29b-41d4-a716-446655440000", CVEID: "CVE-2024-0002", Severity: "high",
		EffectiveState: "detected", ComponentPURL: "pkg:rpm/rocky/openssl@1.1.1k-15.el8_10",
	}}
	out := toScanVulnerabilityList(items, domain.PageResult{})
	item := (*out.Items)[0]
	if item.FixedVersion != nil || item.InstalledVersion != nil {
		t.Fatalf("expected nil fixed/installed, got fixed=%#v installed=%#v", item.FixedVersion, item.InstalledVersion)
	}
}

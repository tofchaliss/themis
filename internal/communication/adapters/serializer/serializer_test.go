package serializer_test

import (
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/domain"
)

func art(t *testing.T, typ domain.ArtifactType) domain.Artifact {
	t.Helper()
	snap := domain.PositionSnapshot{
		FindingID: "fnd-1", Version: 2, Stance: domain.StanceNotAffected, Rationale: "vendor VEX confirms",
		Lineage: domain.Lineage{ReleaseID: "rel-1", FindingID: "fnd-1", FaultlineID: "fl-1", CVE: "CVE-2024-1"},
	}
	a, err := domain.Materialize(snap, typ)
	if err != nil {
		t.Fatalf("materialize(%s): %v", typ, err)
	}
	return a
}

func render(t *testing.T, s serializer.Serializer, typ domain.ArtifactType) string {
	t.Helper()
	b, err := s.Render(art(t, typ))
	if err != nil {
		t.Fatalf("%s render: %v", s.Format(), err)
	}
	// Determinism: re-rendering yields identical bytes (D1 regenerability).
	b2, _ := s.Render(art(t, typ))
	if string(b) != string(b2) {
		t.Fatalf("%s render not deterministic", s.Format())
	}
	return string(b)
}

func TestOpenVEX(t *testing.T) {
	want := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://themis.example/vex/fl-1",
  "author": "Themis",
  "version": 2,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2024-1"
      },
      "products": [
        "rel-1"
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "status_notes": "vendor VEX confirms"
    }
  ]
}`
	if got := render(t, serializer.OpenVEX{}, domain.ArtifactVEX); got != want {
		t.Errorf("openvex:\n got=%s\nwant=%s", got, want)
	}
}

func TestCycloneDXVEX(t *testing.T) {
	want := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "vulnerabilities": [
    {
      "id": "CVE-2024-1",
      "analysis": {
        "state": "not_affected",
        "detail": "vendor VEX confirms"
      },
      "affects": [
        {
          "ref": "rel-1"
        }
      ]
    }
  ]
}`
	if got := render(t, serializer.CycloneDXVEX{}, domain.ArtifactVEX); got != want {
		t.Errorf("cyclonedx-vex:\n got=%s\nwant=%s", got, want)
	}
}

func TestCSAF(t *testing.T) {
	want := `{
  "document": {
    "category": "csaf_vex",
    "title": "Security advisory for CVE-2024-1",
    "publisher": "Themis"
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-1",
      "product_status": {
        "known_not_affected": [
          "rel-1"
        ]
      },
      "notes": [
        {
          "category": "description",
          "text": "vendor VEX confirms"
        }
      ]
    }
  ]
}`
	if got := render(t, serializer.CSAF{}, domain.ArtifactAdvisory); got != want {
		t.Errorf("csaf:\n got=%s\nwant=%s", got, want)
	}
}

func TestMarkdownAdvisory(t *testing.T) {
	want := "# Security advisory for CVE-2024-1\n\n" +
		"Release rel-1 is not affected with respect to CVE-2024-1.\n\n" +
		"- **CVE:** CVE-2024-1\n" +
		"- **Release:** rel-1\n" +
		"- **Status:** not affected\n\n" +
		"## Rationale\n\nvendor VEX confirms\n"
	if got := render(t, serializer.MarkdownAdvisory{}, domain.ArtifactAdvisory); got != want {
		t.Errorf("markdown:\n got=%q\nwant=%q", got, want)
	}
}

func TestJSONReport(t *testing.T) {
	want := `{
  "title": "Audit report for CVE-2024-1",
  "cve": "CVE-2024-1",
  "release_id": "rel-1",
  "finding_id": "fnd-1",
  "faultline_id": "fl-1",
  "position_version": 2,
  "stance": "not_affected",
  "rationale": "vendor VEX confirms"
}`
	if got := render(t, serializer.JSONReport{}, domain.ArtifactAuditReport); got != want {
		t.Errorf("json-report:\n got=%s\nwant=%s", got, want)
	}
}

func TestTextNotification(t *testing.T) {
	want := "Security notification: CVE-2024-1\n" +
		"Release rel-1 is not affected with respect to CVE-2024-1.\n\n" +
		"Rationale: vendor VEX confirms\n"
	if got := render(t, serializer.TextNotification{}, domain.ArtifactNotification); got != want {
		t.Errorf("text:\n got=%q\nwant=%q", got, want)
	}
}

func TestStanceMappingsAcrossSerializers(t *testing.T) {
	// The VEX/CSAF status vocabularies present the same conclusion for each stance.
	vexWant := map[domain.Stance]string{
		domain.StanceAffected: "affected", domain.StanceNotAffected: "not_affected",
		domain.StanceMitigated: "fixed", domain.StanceUnderInvestigation: "under_investigation",
	}
	for s, status := range vexWant {
		snap := domain.PositionSnapshot{FindingID: "f", Stance: s, Lineage: domain.Lineage{CVE: "CVE-1", ReleaseID: "r"}}
		a, _ := domain.Materialize(snap, domain.ArtifactVEX)
		b, _ := serializer.OpenVEX{}.Render(a)
		if !contains(string(b), `"status": "`+status+`"`) {
			t.Errorf("openvex stance %q missing status %q: %s", s, status, b)
		}
	}

	// CSAF product_status keys across every stance band.
	csafWant := map[domain.Stance]string{
		domain.StanceAffected: "known_affected", domain.StanceAcceptedRisk: "known_affected",
		domain.StanceNotAffected: "known_not_affected", domain.StanceMitigated: "fixed",
		domain.StanceUnderInvestigation: "under_investigation", domain.StanceDeferred: "under_investigation",
	}
	for s, key := range csafWant {
		snap := domain.PositionSnapshot{FindingID: "f", Stance: s, Lineage: domain.Lineage{CVE: "CVE-1", ReleaseID: "r"}}
		a, _ := domain.Materialize(snap, domain.ArtifactAdvisory)
		b, _ := serializer.CSAF{}.Render(a)
		if !contains(string(b), `"`+key+`"`) {
			t.Errorf("csaf stance %q missing product_status %q: %s", s, key, b)
		}
	}
}

func TestMarkdownFallbacks(t *testing.T) {
	// Empty CVE / release exercise the fallback wording, and no rationale drops the section.
	snap := domain.PositionSnapshot{FindingID: "f", Stance: domain.StanceAffected}
	a, _ := domain.Materialize(snap, domain.ArtifactAdvisory)
	md, _ := serializer.MarkdownAdvisory{}.Render(a)
	if !contains(string(md), "**CVE:** unspecified") || !contains(string(md), "**Release:** unspecified") {
		t.Errorf("markdown fallback missing: %s", md)
	}
	if contains(string(md), "## Rationale") {
		t.Errorf("empty rationale should omit the section: %s", md)
	}
	// Text notification with no rationale likewise omits the rationale line.
	txt, _ := serializer.TextNotification{}.Render(a)
	if contains(string(txt), "Rationale:") {
		t.Errorf("empty rationale should omit the line: %s", txt)
	}
}

func TestRegistry(t *testing.T) {
	reg := serializer.Default()
	// All six formats registered, sorted.
	got := reg.Formats()
	want := []string{"csaf", "cyclonedx-vex", "json-report", "markdown", "openvex", "text"}
	if len(got) != len(want) {
		t.Fatalf("formats = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("formats = %v, want %v", got, want)
		}
	}
	// Render via the registry.
	if _, err := reg.Render("openvex", art(t, domain.ArtifactVEX)); err != nil {
		t.Errorf("registry render: %v", err)
	}
	// Unknown format.
	if _, err := reg.Render("nope", art(t, domain.ArtifactVEX)); !errors.Is(err, serializer.ErrUnknownFormat) {
		t.Errorf("unknown format err = %v, want ErrUnknownFormat", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

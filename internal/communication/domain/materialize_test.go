package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/communication/domain"
)

func snapshot(stance domain.Stance) domain.PositionSnapshot {
	return domain.PositionSnapshot{
		FindingID: "fnd-1",
		Version:   2,
		Stance:    stance,
		Rationale: "vendor VEX confirms",
		Lineage:   domain.Lineage{ReleaseID: "rel-1", FindingID: "fnd-1", FaultlineID: "fl-1", CVE: "CVE-2024-1"},
	}
}

func TestMaterialize_StanceEqualityInvariant(t *testing.T) {
	stances := []domain.Stance{
		domain.StanceAffected, domain.StanceNotAffected, domain.StanceUnderInvestigation,
		domain.StanceMitigated, domain.StanceAcceptedRisk, domain.StanceDeferred,
	}
	types := []domain.ArtifactType{
		domain.ArtifactVEX, domain.ArtifactAdvisory, domain.ArtifactNotification, domain.ArtifactAuditReport,
	}
	for _, s := range stances {
		for _, typ := range types {
			art, err := domain.Materialize(snapshot(s), typ)
			if err != nil {
				t.Fatalf("materialize(%s,%s): %v", s, typ, err)
			}
			// The hard invariant: the artifact's stance equals the Position's stance.
			if art.Stance != s {
				t.Errorf("materialize(%s,%s) stance = %q, want %q", s, typ, art.Stance, s)
			}
			if art.Type != typ || art.PositionVersion != 2 || art.Lineage.CVE != "CVE-2024-1" {
				t.Errorf("artifact = %+v", art)
			}
			if art.Title == "" || art.Summary == "" {
				t.Errorf("presentation not rendered: %+v", art)
			}
		}
	}
}

func TestMaterialize_Deterministic(t *testing.T) {
	a, _ := domain.Materialize(snapshot(domain.StanceNotAffected), domain.ArtifactAdvisory)
	b, _ := domain.Materialize(snapshot(domain.StanceNotAffected), domain.ArtifactAdvisory)
	if a != b {
		t.Errorf("materialization not deterministic:\n a=%+v\n b=%+v", a, b)
	}
}

func TestMaterialize_TitleAndSummaryFallbacks(t *testing.T) {
	// Empty CVE / release exercise the fallback wording for every artifact type.
	snap := domain.PositionSnapshot{FindingID: "fnd-1", Stance: domain.StanceAffected}
	for _, typ := range []domain.ArtifactType{domain.ArtifactVEX, domain.ArtifactAdvisory, domain.ArtifactNotification, domain.ArtifactAuditReport} {
		art, err := domain.Materialize(snap, typ)
		if err != nil {
			t.Fatalf("materialize(%s): %v", typ, err)
		}
		if art.Title == "" || art.Summary == "" {
			t.Errorf("%s fallback empty: %+v", typ, art)
		}
	}
}

func TestMaterialize_Errors(t *testing.T) {
	if _, err := domain.Materialize(snapshot(domain.StanceAffected), domain.ArtifactType("bogus")); err == nil {
		t.Error("unknown artifact type should error")
	}
	if _, err := domain.Materialize(snapshot(domain.Stance("nope")), domain.ArtifactVEX); err == nil {
		t.Error("invalid stance should error")
	}
	badSnap := snapshot(domain.StanceAffected)
	badSnap.FindingID = ""
	if _, err := domain.Materialize(badSnap, domain.ArtifactVEX); err == nil {
		t.Error("empty finding id should error")
	}
}

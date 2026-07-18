package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func mustPURL(t *testing.T, s string) value.PURL {
	t.Helper()
	p, err := value.NewPURL(s)
	if err != nil {
		t.Fatalf("purl %q: %v", s, err)
	}
	return p
}

func sampleInventory(t *testing.T) domain.Inventory {
	t.Helper()
	return domain.NewInventory(
		[]domain.Component{{
			PURL:      mustPURL(t, "pkg:deb/debian/openssl@3.0.11"),
			Name:      "openssl",
			Version:   "3.0.11",
			Ecosystem: "debian",
		}},
		[]domain.DependencyEdge{{
			From:         mustPURL(t, "pkg:deb/debian/app@1.0.0"),
			To:           mustPURL(t, "pkg:deb/debian/openssl@3.0.11"),
			Relationship: "depends_on",
		}},
	)
}

func validSBOM(t *testing.T) domain.Evidence {
	t.Helper()
	e, err := domain.NewEvidence(
		"ev-1",
		domain.KindSBOM,
		value.NewContentFingerprint([]byte("raw sbom bytes")),
		domain.SubjectRef{ReleaseID: "rel-1"},
		domain.Provenance{Source: "trivy", ImageDigest: "sha256:deadbeef"},
		domain.TrustAccepted,
		sampleInventory(t),
		time.Unix(1_700_000_000, 0),
	)
	if err != nil {
		t.Fatalf("validSBOM: %v", err)
	}
	return e
}

func TestKindValid(t *testing.T) {
	for _, k := range []domain.Kind{domain.KindSBOM, domain.KindVEX, domain.KindScannerReport} {
		if !k.Valid() {
			t.Errorf("%q should be valid", k)
		}
	}
	for _, k := range []domain.Kind{"", "bogus"} {
		if k.Valid() {
			t.Errorf("%q should be invalid", k)
		}
	}
}

func TestTrustStatusValid(t *testing.T) {
	if !domain.TrustAccepted.Valid() || !domain.TrustRejected.Valid() {
		t.Error("accepted/rejected should be valid")
	}
	if domain.TrustStatus("maybe").Valid() {
		t.Error("unknown trust status should be invalid")
	}
}

func TestInventory_CopySemantics(t *testing.T) {
	comps := []domain.Component{{PURL: mustPURL(t, "pkg:npm/a@1.0.0"), Name: "a"}}
	edges := []domain.DependencyEdge{{From: mustPURL(t, "pkg:npm/a@1.0.0"), To: mustPURL(t, "pkg:npm/b@1.0.0")}}
	inv := domain.NewInventory(comps, edges)

	// Mutating the input slices must not affect the inventory.
	comps[0].Name = "mutated"
	edges[0].Relationship = "mutated"
	if got := inv.Components()[0].Name; got != "a" {
		t.Errorf("input mutation leaked in: Name=%q", got)
	}
	if got := inv.Dependencies()[0].Relationship; got != "" {
		t.Errorf("input mutation leaked in: Relationship=%q", got)
	}

	// Mutating a returned slice must not affect the inventory.
	inv.Components()[0].Name = "mutated"
	inv.Dependencies()[0].Relationship = "mutated"
	if got := inv.Components()[0].Name; got != "a" {
		t.Errorf("returned-slice mutation leaked in: Name=%q", got)
	}
	if got := inv.Dependencies()[0].Relationship; got != "" {
		t.Errorf("returned-slice mutation leaked in: Relationship=%q", got)
	}

	if inv.IsEmpty() {
		t.Error("inventory with a component reports IsEmpty")
	}
	if !domain.NewInventory(nil, nil).IsEmpty() {
		t.Error("empty inventory should report IsEmpty")
	}
}

func TestNewEvidence_Accessors(t *testing.T) {
	e := validSBOM(t)
	if e.ID() != "ev-1" {
		t.Errorf("ID = %q", e.ID())
	}
	if e.Kind() != domain.KindSBOM {
		t.Errorf("Kind = %q", e.Kind())
	}
	if e.Fingerprint().IsZero() {
		t.Error("Fingerprint is zero")
	}
	if e.Subject().ReleaseID != "rel-1" {
		t.Errorf("Subject = %+v", e.Subject())
	}
	if e.Provenance().Source != "trivy" || e.Provenance().ImageDigest != "sha256:deadbeef" {
		t.Errorf("Provenance = %+v", e.Provenance())
	}
	if e.Trust() != domain.TrustAccepted {
		t.Errorf("Trust = %q", e.Trust())
	}
	if e.Inventory().IsEmpty() {
		t.Error("Inventory empty")
	}
	if e.FiledAt().IsZero() {
		t.Error("FiledAt zero")
	}
}

func TestNewEvidence_VEXAllowsEmptyInventory(t *testing.T) {
	_, err := domain.NewEvidence(
		"ev-vex",
		domain.KindVEX,
		value.NewContentFingerprint([]byte("vex")),
		domain.SubjectRef{ReleaseID: "rel-1"},
		domain.Provenance{Source: "vendor"},
		domain.TrustAccepted,
		domain.NewInventory(nil, nil),
		time.Unix(1, 0),
	)
	if err != nil {
		t.Fatalf("VEX with empty inventory should be valid: %v", err)
	}
}

func TestNewEvidence_Validation(t *testing.T) {
	fp := value.NewContentFingerprint([]byte("x"))
	subj := domain.SubjectRef{ReleaseID: "rel-1"}
	now := time.Unix(1, 0)
	inv := sampleInventory(t)

	cases := map[string]struct {
		id      domain.EvidenceID
		kind    domain.Kind
		fp      value.ContentFingerprint
		subject domain.SubjectRef
		trust   domain.TrustStatus
		filedAt time.Time
		inv     domain.Inventory
	}{
		"emptyID":         {"", domain.KindSBOM, fp, subj, domain.TrustAccepted, now, inv},
		"invalidKind":     {"ev", "bogus", fp, subj, domain.TrustAccepted, now, inv},
		"zeroFingerprint": {"ev", domain.KindSBOM, value.ContentFingerprint{}, subj, domain.TrustAccepted, now, inv},
		"emptyRelease":    {"ev", domain.KindSBOM, fp, domain.SubjectRef{}, domain.TrustAccepted, now, inv},
		"invalidTrust":    {"ev", domain.KindSBOM, fp, subj, "maybe", now, inv},
		"zeroFiledAt":     {"ev", domain.KindSBOM, fp, subj, domain.TrustAccepted, time.Time{}, inv},
		"sbomEmptyInv":    {"ev", domain.KindSBOM, fp, subj, domain.TrustAccepted, now, domain.NewInventory(nil, nil)},
	}
	for name, c := range cases {
		if _, err := domain.NewEvidence(c.id, c.kind, c.fp, c.subject, domain.Provenance{}, c.trust, c.inv, c.filedAt); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewEvidenceRegistered(t *testing.T) {
	e := validSBOM(t)
	occurred := time.Unix(1_700_000_500, 0)
	ev := domain.NewEvidenceRegistered(e, occurred)

	if ev.EvidenceID != e.ID() {
		t.Errorf("EvidenceID = %q, want %q", ev.EvidenceID, e.ID())
	}
	if ev.Kind != domain.KindSBOM {
		t.Errorf("Kind = %q", ev.Kind)
	}
	if ev.SubjectReleaseID != "rel-1" {
		t.Errorf("SubjectReleaseID = %q", ev.SubjectReleaseID)
	}
	if ev.Fingerprint != e.Fingerprint().String() {
		t.Errorf("Fingerprint = %q", ev.Fingerprint)
	}
	if !ev.OccurredAt.Equal(occurred) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, occurred)
	}
}

package store

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Note: the DB-backed methods (New, Save, Get*, List*, Relay) are exercised by the
// integration tests (build tag "integration"). deadcode runs without that tag, so
// it reports them as unreachable until the app layer wires them (Group 5); that is
// expected and informational (deadcode does not fail the gate).

func mustPURL(t *testing.T, s string) value.PURL {
	t.Helper()
	p, err := value.NewPURL(s)
	if err != nil {
		t.Fatalf("purl %q: %v", s, err)
	}
	return p
}

func TestInventoryCodec_RoundTrip(t *testing.T) {
	inv := domain.NewInventory(
		[]domain.Component{{PURL: mustPURL(t, "pkg:rpm/rocky/openssl-libs@1.1.1k-15.el8_10"), Name: "openssl-libs", Version: "1:1.1.1k-15.el8_10", Ecosystem: "rpm", Source: "openssl"}},
		[]domain.DependencyEdge{{From: mustPURL(t, "pkg:deb/debian/app@1"), To: mustPURL(t, "pkg:rpm/rocky/openssl-libs@1.1.1k-15.el8_10"), Relationship: "depends_on"}},
	)
	data, err := marshalInventory(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := unmarshalInventory(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Components()) != 1 || got.Components()[0].Name != "openssl-libs" {
		t.Errorf("components round-trip: %+v", got.Components())
	}
	if got.Components()[0].Source != "openssl" {
		t.Errorf("Source round-trip = %q, want openssl", got.Components()[0].Source)
	}
	if len(got.Dependencies()) != 1 || got.Dependencies()[0].Relationship != "depends_on" {
		t.Errorf("dependencies round-trip: %+v", got.Dependencies())
	}
}

func TestInventoryCodec_Empty(t *testing.T) {
	for _, in := range [][]byte{nil, []byte(`{}`)} {
		got, err := unmarshalInventory(in)
		if err != nil || !got.IsEmpty() {
			t.Errorf("empty(%q): got %+v err %v", in, got, err)
		}
	}
}

func TestInventoryCodec_Invalid(t *testing.T) {
	for _, bad := range []string{
		`{bad json`,
		`{"components":[{"purl":"not-a-purl"}]}`,
		`{"dependencies":[{"from":"bad","to":"pkg:x/y@1"}]}`,
		`{"dependencies":[{"from":"pkg:x/y@1","to":"bad"}]}`,
	} {
		if _, err := unmarshalInventory([]byte(bad)); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}

// TestEvidenceCodecRoundTripsBuildID — the build id survives the trip through the
// stored columns and back. The pair is tested together because a column written and
// never read is the exact failure mode a deliberately inert label has (EDR-INTAKE-01
// B5): nothing consults `build_id` to decide anything, so a half-wired codec would
// look identical to a working one until an operator asked which build produced a
// document.
func TestEvidenceCodecRoundTripsBuildID(t *testing.T) {
	const buildID = "Jenkins/OAMP-core/1917"
	in := domain.Provenance{Source: "trivy", ImageDigest: "sha256:deadbeef", BuildID: buildID}

	source, digest, stored := provenanceColumns(in)
	if stored != buildID {
		t.Fatalf("provenance_build_id column = %q, want %q", stored, buildID)
	}
	got := provenanceFromColumns(source, digest, stored)
	if got.BuildID != buildID {
		t.Errorf("BuildID round-trip = %q, want %q", got.BuildID, buildID)
	}
	if got.Source != in.Source || got.ImageDigest != in.ImageDigest {
		t.Errorf("the new column disturbed its neighbours: %+v", got)
	}

	// An absent build id round-trips as the empty string, never as a NULL-shaped
	// surprise: a build id nobody asserted is the fact "none", not an unknown.
	if _, _, none := provenanceColumns(domain.Provenance{Source: "trivy"}); none != "" {
		t.Errorf("absent build id = %q, want empty", none)
	}
}

func TestNewEventPayload(t *testing.T) {
	ev := domain.EvidenceRegistered{
		EvidenceID: "ev-1", Kind: domain.KindSBOM, SubjectReleaseID: "rel-1",
		Fingerprint: "fp", OccurredAt: time.Unix(1, 0),
	}
	p := newEventPayload(ev)
	if p.EvidenceID != "ev-1" || p.Kind != "sbom" || p.SubjectReleaseID != "rel-1" || p.Fingerprint != "fp" {
		t.Errorf("payload: %+v", p)
	}
}

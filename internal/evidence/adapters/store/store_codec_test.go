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
		[]domain.Component{{PURL: mustPURL(t, "pkg:deb/debian/openssl@3.0.11"), Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}},
		[]domain.DependencyEdge{{From: mustPURL(t, "pkg:deb/debian/app@1"), To: mustPURL(t, "pkg:deb/debian/openssl@3.0.11"), Relationship: "depends_on"}},
	)
	data, err := marshalInventory(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := unmarshalInventory(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Components()) != 1 || got.Components()[0].Name != "openssl" {
		t.Errorf("components round-trip: %+v", got.Components())
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

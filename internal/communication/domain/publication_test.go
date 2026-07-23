package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

var epoch = time.Unix(1_700_000_000, 0).UTC()

func artifact(t *testing.T) domain.Artifact {
	t.Helper()
	a, err := domain.Materialize(snapshot(domain.StanceNotAffected), domain.ArtifactVEX)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	return a
}

func newPub(t *testing.T) domain.Publication {
	t.Helper()
	p, err := domain.NewPublication("pub-1", artifact(t), "openvex", "tooling", "export", []byte(`{"x":1}`), "", epoch)
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	return p
}

func TestNewPublication(t *testing.T) {
	p := newPub(t)
	if p.ID() != "pub-1" || p.Format() != "openvex" || p.Audience() != "tooling" || p.Channel() != "export" {
		t.Errorf("publication = %+v", p)
	}
	if p.Type() != domain.ArtifactVEX || p.Stance() != domain.StanceNotAffected {
		t.Errorf("artifact fields = %q / %q", p.Type(), p.Stance())
	}
	if art := p.Artifact(); art.Type != domain.ArtifactVEX || art.Title == "" {
		t.Errorf("Artifact() = %+v", art)
	}
	if p.Delivery().Status != domain.DeliveryPending || p.Version() != 1 {
		t.Errorf("delivery/version = %+v / %d", p.Delivery(), p.Version())
	}
	if string(p.Payload()) != `{"x":1}` || p.PayloadPruned() {
		t.Errorf("payload = %q pruned=%v", p.Payload(), p.PayloadPruned())
	}
	if p.IsSuperseded() || p.Supersedes() != "" || p.SupersededBy() != "" {
		t.Error("fresh publication must not be superseded")
	}
	if !p.CreatedAt().Equal(epoch) || p.Lineage().CVE != "CVE-2024-1" {
		t.Errorf("createdAt/lineage = %v / %+v", p.CreatedAt(), p.Lineage())
	}
	// Defensive copy: mutating the returned payload must not affect the aggregate.
	pl := p.Payload()
	pl[0] = 'X'
	if p.Payload()[0] == 'X' {
		t.Error("Payload() must return a defensive copy")
	}
}

func TestNewPublicationRejectsBadInput(t *testing.T) {
	good := artifact(t)
	badType := good
	badType.Type = "bogus"
	badStance := good
	badStance.Stance = "nope"
	cases := []struct {
		name   string
		id     domain.PublicationID
		art    domain.Artifact
		format string
	}{
		{"empty id", "", good, "openvex"},
		{"bad type", "pub-1", badType, "openvex"},
		{"bad stance", "pub-1", badStance, "openvex"},
		{"empty format", "pub-1", good, ""},
	}
	for _, c := range cases {
		if _, err := domain.NewPublication(c.id, c.art, c.format, "a", "c", nil, "", epoch); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestPublicationDeliveryStateMachine(t *testing.T) {
	p := newPub(t)

	// Fail then retry to delivered.
	p.MarkFailed("smtp timeout")
	if d := p.Delivery(); d.Status != domain.DeliveryFailed || d.Attempts != 1 || d.LastError != "smtp timeout" {
		t.Errorf("after fail = %+v", d)
	}
	v := p.Version()
	if !p.MarkDelivered(epoch.Add(time.Minute)) {
		t.Error("MarkDelivered should report a change")
	}
	if d := p.Delivery(); d.Status != domain.DeliveryDelivered || d.LastError != "" || !d.DeliveredAt.Equal(epoch.Add(time.Minute)) {
		t.Errorf("after deliver = %+v", d)
	}
	if p.Version() != v+1 {
		t.Error("delivery should bump version")
	}
	// Idempotent: re-delivering is a no-op.
	if p.MarkDelivered(epoch.Add(time.Hour)) {
		t.Error("re-deliver should be a no-op")
	}
}

func TestPublicationSupersede(t *testing.T) {
	p := newPub(t)
	if err := p.Supersede("pub-2"); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if !p.IsSuperseded() || p.SupersededBy() != "pub-2" {
		t.Errorf("supersededBy = %q", p.SupersededBy())
	}
	// Set once.
	if err := p.Supersede("pub-3"); !errors.Is(err, domain.ErrAlreadySuperseded) {
		t.Errorf("re-supersede err = %v, want ErrAlreadySuperseded", err)
	}
}

func TestPublicationPrunePayload(t *testing.T) {
	p := newPub(t)
	if !p.PrunePayload() {
		t.Error("prune should report a change")
	}
	if !p.PayloadPruned() || p.Payload() != nil {
		t.Error("payload should be pruned to nil")
	}
	// No-op when already pruned.
	if p.PrunePayload() {
		t.Error("re-prune should be a no-op")
	}
}

func TestReconstitutePublication(t *testing.T) {
	delivery := domain.DeliveryOutcome{Status: domain.DeliveryDelivered, Attempts: 2, DeliveredAt: epoch}
	p := domain.ReconstitutePublication("pub-9", artifact(t), "csaf", "customers", "advisory",
		[]byte("bytes"), delivery, "pub-8", "pub-10", 7, epoch)
	if p.ID() != "pub-9" || p.Format() != "csaf" || p.Version() != 7 {
		t.Errorf("reconstituted = %+v", p)
	}
	if p.Supersedes() != "pub-8" || p.SupersededBy() != "pub-10" || !p.IsSuperseded() {
		t.Errorf("supersession = %q / %q", p.Supersedes(), p.SupersededBy())
	}
	if p.Delivery().Status != domain.DeliveryDelivered || p.Delivery().Attempts != 2 {
		t.Errorf("delivery = %+v", p.Delivery())
	}
}

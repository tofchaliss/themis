package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/communication/domain"
)

func TestCommunicationEvents(t *testing.T) {
	p := newPub(t)

	created := domain.NewPublicationCreated(p, epoch)
	if created.PublicationID != "pub-1" || created.Type != domain.ArtifactVEX ||
		created.Stance != domain.StanceNotAffected || created.ReleaseID != "rel-1" ||
		created.FaultlineID != "fl-1" || created.CVE != "CVE-2024-1" || !created.OccurredAt.Equal(epoch) {
		t.Errorf("created = %+v", created)
	}

	delivered := domain.NewPublicationDelivered(p, epoch)
	if delivered.PublicationID != "pub-1" || delivered.Channel != "export" || !delivered.OccurredAt.Equal(epoch) {
		t.Errorf("delivered = %+v", delivered)
	}

	_ = p.Supersede("pub-2")
	superseded := domain.NewPublicationSuperseded(p, epoch)
	if superseded.PublicationID != "pub-1" || superseded.SupersededByID != "pub-2" || !superseded.OccurredAt.Equal(epoch) {
		t.Errorf("superseded = %+v", superseded)
	}
}

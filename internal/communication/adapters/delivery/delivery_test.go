package delivery_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/domain"
)

func TestLogDelivererAndRedactor(t *testing.T) {
	art, err := domain.Materialize(domain.PositionSnapshot{
		FindingID: "fnd-1", Stance: domain.StanceNotAffected,
		Lineage: domain.Lineage{ReleaseID: "rel-1", CVE: "CVE-1"},
	}, domain.ArtifactVEX)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	pub, err := domain.NewPublication("pub-1", art, "openvex", "tooling", "export", []byte(`{"vex":true}`), "", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}

	payload := delivery.PassThroughRedactor{}.Redact([]byte("secret"))
	if string(payload) != "secret" {
		t.Errorf("redactor changed payload: %q", payload)
	}
	if err := delivery.NewLogDeliverer(nil).Deliver(context.Background(), pub, payload); err != nil {
		t.Errorf("deliver: %v", err)
	}
}

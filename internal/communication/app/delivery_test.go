package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

type fakeDeliverer struct {
	failFirst bool
	calls     int
	lastBytes []byte
}

func (d *fakeDeliverer) Deliver(_ context.Context, _ domain.Publication, payload []byte) error {
	d.calls++
	d.lastBytes = payload
	if d.failFirst {
		d.failFirst = false
		return errors.New("smtp timeout")
	}
	return nil
}

type markRedactor struct{ called bool }

func (r *markRedactor) Redact(payload []byte) []byte {
	r.called = true
	return payload
}

func pending(t *testing.T, id string) domain.Publication {
	t.Helper()
	p, err := domain.NewPublication(domain.PublicationID(id), mustArt(t, domain.StanceNotAffected, domain.ArtifactVEX),
		"openvex", "tooling", "export", []byte(`{"vex":true}`), "", fixedClock{}.Now())
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	return p
}

func TestDeliverPending(t *testing.T) {
	repo := newRepo()
	repo.saved["pub-1"] = pending(t, "pub-1")
	del := &fakeDeliverer{}
	red := &markRedactor{}

	n, err := app.NewDeliveryService(repo, del, red, fixedClock{}).DeliverPending(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("deliver: n=%d err=%v", n, err)
	}
	if !red.called {
		t.Error("redactor must run before delivery")
	}
	if repo.saved["pub-1"].Delivery().Status != domain.DeliveryDelivered {
		t.Errorf("publication not marked delivered: %+v", repo.saved["pub-1"].Delivery())
	}
	if got := noteTypes(repo.lastUpdateNotes); len(got) != 1 || got[0] != app.EventPublicationDelivered {
		t.Errorf("notes = %v, want [publication_delivered]", got)
	}

	// A delivered publication is not re-delivered.
	del.calls = 0
	if n, _ := app.NewDeliveryService(repo, del, red, fixedClock{}).DeliverPending(context.Background()); n != 0 || del.calls != 0 {
		t.Errorf("re-deliver n=%d calls=%d, want 0/0", n, del.calls)
	}

	// Defensive: an already-delivered publication that slips into the queue is skipped
	// (MarkDelivered is idempotent).
	alreadyDelivered := pending(t, "pub-2")
	alreadyDelivered.MarkDelivered(fixedClock{}.Now())
	over := newRepo()
	over.undeliveredOverride = []domain.Publication{alreadyDelivered}
	if n, err := app.NewDeliveryService(over, &fakeDeliverer{}, &markRedactor{}, fixedClock{}).DeliverPending(context.Background()); err != nil || n != 0 {
		t.Errorf("already-delivered skip: n=%d err=%v, want 0", n, err)
	}
}

func TestDeliverPending_FailureRecordedAndRetried(t *testing.T) {
	repo := newRepo()
	repo.saved["pub-1"] = pending(t, "pub-1")
	del := &fakeDeliverer{failFirst: true}
	svc := app.NewDeliveryService(repo, del, &markRedactor{}, fixedClock{})

	// First pass fails → recorded failed, nothing delivered.
	if n, err := svc.DeliverPending(context.Background()); err != nil || n != 0 {
		t.Fatalf("first pass: n=%d err=%v", n, err)
	}
	if d := repo.saved["pub-1"].Delivery(); d.Status != domain.DeliveryFailed || d.Attempts != 1 {
		t.Errorf("after fail = %+v", d)
	}
	// Second pass (still undelivered) succeeds.
	if n, err := svc.DeliverPending(context.Background()); err != nil || n != 1 {
		t.Fatalf("second pass: n=%d err=%v", n, err)
	}
	if repo.saved["pub-1"].Delivery().Status != domain.DeliveryDelivered {
		t.Error("retry should deliver")
	}
}

func TestDeliverPending_Errors(t *testing.T) {
	// Load error.
	le := newRepo()
	le.undeliveredErr = errors.New("db down")
	if _, err := app.NewDeliveryService(le, &fakeDeliverer{}, &markRedactor{}, fixedClock{}).DeliverPending(context.Background()); err == nil {
		t.Error("load error: expected error")
	}
	// Update error on the success path.
	ue := newRepo()
	ue.saved["pub-1"] = pending(t, "pub-1")
	ue.updateErr = errors.New("write failed")
	if _, err := app.NewDeliveryService(ue, &fakeDeliverer{}, &markRedactor{}, fixedClock{}).DeliverPending(context.Background()); err == nil {
		t.Error("update error: expected error")
	}
	// Update error on the failure path.
	fe := newRepo()
	fe.saved["pub-1"] = pending(t, "pub-1")
	fe.updateErr = errors.New("write failed")
	if _, err := app.NewDeliveryService(fe, &fakeDeliverer{failFirst: true}, &markRedactor{}, fixedClock{}).DeliverPending(context.Background()); err == nil {
		t.Error("failure-path update error: expected error")
	}
}

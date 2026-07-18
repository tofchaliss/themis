package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

func readSvc(repo app.Repository, pos app.PositionReader) *app.ReadService {
	return app.NewReadService(repo, pos, fakeSerializers{})
}

func TestReadService_GetPublication(t *testing.T) {
	repo := newRepo()
	repo.saved["pub-1"] = pending(t, "pub-1")
	rs := readSvc(repo, fakePositions{})

	pub, payload, err := rs.GetPublication(context.Background(), "pub-1")
	if err != nil || pub.ID() != "pub-1" || string(payload) != `{"vex":true}` {
		t.Fatalf("get = %q err=%v", payload, err)
	}

	// Error propagates.
	if _, _, err := rs.GetPublication(context.Background(), "ghost"); err == nil {
		t.Error("unknown id: expected error")
	}
}

func TestReadService_GetPublicationRegeneratesPrunedPayload(t *testing.T) {
	repo := newRepo()
	pruned := pending(t, "pub-1")
	pruned.PrunePayload()
	repo.saved["pub-1"] = pruned
	rs := readSvc(repo, fakePositions{})

	pub, payload, err := rs.GetPublication(context.Background(), "pub-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !pub.PayloadPruned() {
		t.Error("stored publication should still be pruned")
	}
	// Regenerated deterministically from the persisted artifact + serializer (openvex).
	want, _ := fakeSerializers{}.Render("openvex", pruned.Artifact())
	if string(payload) != string(want) {
		t.Errorf("regenerated payload = %q, want %q", payload, want)
	}
}

func TestReadService_GetPublicationRegenerateError(t *testing.T) {
	repo := newRepo()
	// A pruned publication whose format has no serializer cannot be regenerated.
	bad, _ := domain.NewPublication("pub-1", mustArt(t, domain.StanceAffected, domain.ArtifactVEX),
		"bogus-format", "tooling", "export", []byte("x"), "", fixedClock{}.Now())
	bad.PrunePayload()
	repo.saved["pub-1"] = bad
	if _, _, err := readSvc(repo, fakePositions{}).GetPublication(context.Background(), "pub-1"); err == nil {
		t.Error("unknown format regeneration: expected error")
	}
}

func TestReadService_ListAndQueue(t *testing.T) {
	repo := newRepo()
	repo.saved["pub-1"] = pending(t, "pub-1")
	repo.queue = []app.QueueEntry{{FindingID: "fnd-1", Stance: domain.StanceAffected}}
	rs := readSvc(repo, fakePositions{})
	ctx := context.Background()

	if pubs, err := rs.ListByRelease(ctx, "rel-1"); err != nil || len(pubs) != 1 {
		t.Errorf("list = %d err=%v", len(pubs), err)
	}
	if q, err := rs.PublishableQueue(ctx); err != nil || len(q) != 1 || q[0].FindingID != "fnd-1" {
		t.Errorf("queue = %+v err=%v", q, err)
	}

	// Errors propagate.
	le := newRepo()
	le.listErr = errors.New("db down")
	if _, err := readSvc(le, fakePositions{}).ListByRelease(ctx, "rel-1"); err == nil {
		t.Error("list error: expected error")
	}
	qe := newRepo()
	qe.queueErr = errors.New("db down")
	if _, err := readSvc(qe, fakePositions{}).PublishableQueue(ctx); err == nil {
		t.Error("queue error: expected error")
	}
}

func TestReadService_Preview(t *testing.T) {
	pos := fakePositions{snap: snapshot(domain.StanceNotAffected), found: true}
	rs := readSvc(newRepo(), pos)
	ctx := context.Background()

	// Non-recording render.
	payload, found, err := rs.Preview(ctx, "fnd-1", domain.ArtifactVEX, "openvex")
	if err != nil || !found || len(payload) == 0 {
		t.Fatalf("preview: found=%v err=%v", found, err)
	}

	// No position → not found.
	if _, found, _ := readSvc(newRepo(), fakePositions{found: false}).Preview(ctx, "fnd-1", domain.ArtifactVEX, "openvex"); found {
		t.Error("no position should be not found")
	}
	// GetPosition error.
	if _, _, err := readSvc(newRepo(), fakePositions{err: errors.New("gov down")}).Preview(ctx, "fnd-1", domain.ArtifactVEX, "openvex"); err == nil {
		t.Error("position error: expected error")
	}
	// Unknown artifact type → Materialize error.
	if _, _, err := rs.Preview(ctx, "fnd-1", domain.ArtifactType("bogus"), "openvex"); err == nil {
		t.Error("bad type: expected error")
	}
	// Unknown format → serializer error.
	if _, _, err := rs.Preview(ctx, "fnd-1", domain.ArtifactVEX, "nope"); err == nil {
		t.Error("bad format: expected error")
	}
}

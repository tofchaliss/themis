package inbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// memRepo records only the publishable-queue upserts; the other Repository methods are
// unused by the inbound path.
type memRepo struct{ queue []app.QueueEntry }

func (r *memRepo) CurrentPublication(context.Context, string, string, domain.ArtifactType, string) (domain.Publication, bool, error) {
	return domain.Publication{}, false, nil
}
func (r *memRepo) GetByID(context.Context, domain.PublicationID) (domain.Publication, error) {
	return domain.Publication{}, nil
}
func (r *memRepo) Save(context.Context, domain.Publication, *domain.Publication, int, []app.OutboxNote) error {
	return nil
}
func (r *memRepo) MarkPublishable(_ context.Context, e app.QueueEntry) error {
	r.queue = append(r.queue, e)
	return nil
}
func (r *memRepo) UndeliveredPublications(context.Context, int) ([]domain.Publication, error) {
	return nil, nil
}
func (r *memRepo) UpdateDelivery(context.Context, domain.Publication, int, []app.OutboxNote) error {
	return nil
}
func (r *memRepo) ListByRelease(context.Context, string) ([]domain.Publication, error) {
	return nil, nil
}
func (r *memRepo) PublishableQueue(context.Context) ([]app.QueueEntry, error) { return nil, nil }
func (r *memRepo) PrunePayloads(context.Context, time.Time) (int, error)      { return 0, nil }

type ids struct{}

func (ids) NewID() string { return "pub-x" }

type clk struct{}

func (clk) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func consumer(repo *memRepo) *inbound.Consumer {
	svc := app.NewPublicationService(repo, nil, serializer.Default(), ids{}, clk{})
	return inbound.NewConsumer(svc)
}

func TestConsumer_PositionEstablished(t *testing.T) {
	repo := &memRepo{}
	payload := []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-2024-1","Version":1,"Stance":"not_affected"}`)
	if err := consumer(repo).Handle(context.Background(), "governance.position_established", payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.queue) != 1 {
		t.Fatalf("queue = %d, want 1", len(repo.queue))
	}
	e := repo.queue[0]
	if e.FindingID != "fnd-1" || e.ReleaseID != "rel-1" || e.CVE != "CVE-2024-1" || e.Stance != domain.StanceNotAffected || e.Stale {
		t.Errorf("entry = %+v", e)
	}
}

func TestConsumer_PositionRevisedMarksStale(t *testing.T) {
	repo := &memRepo{}
	payload := []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-1","Version":2,"Stance":"mitigated"}`)
	if err := consumer(repo).Handle(context.Background(), "governance.position_revised", payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.queue) != 1 || !repo.queue[0].Stale || repo.queue[0].Version != 2 {
		t.Errorf("revised entry = %+v", repo.queue)
	}
}

func TestConsumer_UnknownTypeIgnored(t *testing.T) {
	repo := &memRepo{}
	if err := consumer(repo).Handle(context.Background(), "governance.finding_opened", []byte(`{}`)); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if len(repo.queue) != 0 {
		t.Error("unknown event must not touch the queue")
	}
}

func TestConsumer_MalformedPayloads(t *testing.T) {
	c := consumer(&memRepo{})
	for _, evt := range []string{"governance.position_established", "governance.position_revised"} {
		if err := c.Handle(context.Background(), evt, []byte("{not json")); err == nil {
			t.Errorf("%s: malformed payload should error", evt)
		}
	}
}

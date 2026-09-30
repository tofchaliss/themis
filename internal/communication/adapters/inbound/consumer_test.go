package inbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/kernel/event"
)

// mkEnv wraps an event type + payload in the kernel Envelope the consumer now handles
// (M5 EB-02). The other envelope fields are transport metadata the ACL does not read.
func mkEnv(typ string, payload []byte) event.Envelope {
	return event.Envelope{Type: typ, Payload: payload}
}

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
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.position_established", payload)); err != nil {
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
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.position_revised", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.queue) != 1 || !repo.queue[0].Stale || repo.queue[0].Version != 2 {
		t.Errorf("revised entry = %+v", repo.queue)
	}
}

func TestConsumer_UnknownTypeIgnored(t *testing.T) {
	repo := &memRepo{}
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.proposal_rejected", []byte(`{}`))); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if len(repo.queue) != 0 {
		t.Error("unknown event must not touch the queue")
	}
}

func TestConsumer_MalformedPayloads(t *testing.T) {
	c := consumer(&memRepo{}).WithDeliveryIntents(newIntentService(newIntentRepo()))
	for _, evt := range []string{
		"governance.position_established", "governance.position_revised",
		"governance.finding_opened", "governance.proposal_accepted",
	} {
		if err := c.Handle(context.Background(), mkEnv(evt, []byte("{not json"))); err == nil {
			t.Errorf("%s: malformed payload should error", evt)
		}
	}
}

// --- outward actions (N-M1a) ---------------------------------------------------------
//
// The whole point of the milestone is what these tests DO NOT observe: the consumer records
// intents and never calls a sender. There is no sender to call — the Consumer holds a
// repository and a clock and nothing that can reach a network — so the assertion is
// structural, and the tests below pin the rest: which kinds, one per event, and no second
// intent from a redelivery.

// intentRepo records saved intents and enforces the same (origin event, type, kind,
// destination) uniqueness the UNIQUE index does.
type intentRepo struct {
	saved []domain.DeliveryIntent
	dedup map[string]bool
}

func newIntentRepo() *intentRepo { return &intentRepo{dedup: map[string]bool{}} }

func (r *intentRepo) SaveIntent(_ context.Context, in domain.DeliveryIntent) (bool, error) {
	o := in.Origin()
	key := o.EventID + "|" + o.EventType + "|" + string(in.Kind()) + "|" + in.Destination()
	if r.dedup[key] {
		return false, nil
	}
	r.dedup[key] = true
	r.saved = append(r.saved, in)
	return true, nil
}

func (r *intentRepo) DueIntents(context.Context, domain.DeliveryKind, time.Time, int) ([]domain.DeliveryIntent, error) {
	return nil, nil
}
func (r *intentRepo) RecordAttempt(context.Context, domain.DeliveryIntent, domain.DeliveryAttempt) error {
	return nil
}
func (r *intentRepo) SaveIntentState(context.Context, domain.DeliveryIntent) error { return nil }
func (r *intentRepo) GetIntent(context.Context, string) (domain.DeliveryIntent, error) {
	return domain.DeliveryIntent{}, app.ErrIntentNotFound
}
func (r *intentRepo) IntentAttempts(context.Context, string) ([]domain.DeliveryAttempt, error) {
	return nil, nil
}
func (r *intentRepo) ListIntents(context.Context, app.IntentFilter) ([]domain.DeliveryIntent, error) {
	return nil, nil
}
func (r *intentRepo) CountIntentsByStatus(context.Context) (map[domain.IntentStatus]int, error) {
	return nil, nil
}

func (r *intentRepo) kinds() []domain.DeliveryKind {
	out := make([]domain.DeliveryKind, 0, len(r.saved))
	for _, in := range r.saved {
		out = append(out, in.Kind())
	}
	return out
}

func newIntentService(repo *intentRepo) *app.DeliveryIntentService {
	return app.NewDeliveryIntentService(repo, ids{}, clk{}, app.DeliveryIntentConfig{MaxAttempts: 3})
}

func intentConsumer(repo *intentRepo) *inbound.Consumer {
	return consumer(&memRepo{}).WithDeliveryIntents(newIntentService(repo))
}

func TestConsumer_FindingOpenedRecordsOneJiraIntent(t *testing.T) {
	repo := newIntentRepo()
	env := event.Envelope{
		ID: "env-1", Type: "governance.finding_opened", OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		Payload: []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-2026-7","OccurredAt":"2026-09-30T09:00:00Z"}`),
	}
	if err := intentConsumer(repo).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.saved) != 1 {
		t.Fatalf("saved %d intents, want 1", len(repo.saved))
	}
	in := repo.saved[0]
	o := in.Origin()
	if in.Kind() != domain.DeliveryJiraIssue || in.Status() != domain.IntentPending || in.PayloadHash() == "" {
		t.Errorf("intent = %s/%s hash=%q", in.Kind(), in.Status(), in.PayloadHash())
	}
	if o.EventID != "env-1" || o.EventType != "governance.finding_opened" ||
		o.FindingID != "fnd-1" || o.ReleaseID != "rel-1" || o.FaultlineID != "fl-1" || o.CVE != "CVE-2026-7" {
		t.Errorf("snapshot lineage = %+v", o)
	}
	if !o.EventTime.Equal(env.OccurredAt) {
		t.Errorf("event time = %v, want the envelope's %v", o.EventTime, env.OccurredAt)
	}
}

// The transport is at-least-once: the same envelope must not produce a second Jira issue,
// and the redelivery must not ERROR either, or the reader would retry an applied fact.
func TestConsumer_RedeliveredEnvelopeRecordsNoSecondIntent(t *testing.T) {
	repo := newIntentRepo()
	c := intentConsumer(repo)
	env := event.Envelope{ID: "env-1", Type: "governance.finding_opened",
		Payload: []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","OccurredAt":"2026-09-30T09:00:00Z"}`)}

	for i := 0; i < 3; i++ {
		if err := c.Handle(context.Background(), env); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if len(repo.saved) != 1 {
		t.Errorf("saved %d intents for one envelope, want 1", len(repo.saved))
	}
}

func TestConsumer_ProposalAcceptedRecordsMailAndOptionallyCI(t *testing.T) {
	plain := newIntentRepo()
	if err := intentConsumer(plain).Handle(context.Background(), event.Envelope{
		ID: "env-2", Type: "governance.proposal_accepted",
		Payload: []byte(`{"FindingID":"fnd-2","ProposalID":"prop-2","PositionVersion":4,"OccurredAt":"2026-09-30T09:00:00Z"}`),
	}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := plain.kinds(); len(got) != 1 || got[0] != domain.DeliveryEmail {
		t.Errorf("without harness evidence = %v, want [email]", got)
	}

	// The harness-execution case. NOTE: the frozen v1 payload does not carry EvidenceSchema
	// (its schema is additionalProperties:false over four fields), so this shape is stubbed
	// here and is what the field will look like when Governance states it — see the DTO's
	// comment for why N-M1a does not change that schema.
	harness := newIntentRepo()
	if err := intentConsumer(harness).Handle(context.Background(), event.Envelope{
		ID: "env-3", Type: "governance.proposal_accepted",
		Payload: []byte(`{"FindingID":"fnd-3","ProposalID":"prop-3","PositionVersion":1,"EvidenceSchema":"harness-execution/v1","OccurredAt":"2026-09-30T09:00:00Z"}`),
	}); err != nil {
		t.Fatalf("handle harness: %v", err)
	}
	got := harness.kinds()
	if len(got) != 2 || got[0] != domain.DeliveryCIBuild || got[1] != domain.DeliveryEmail {
		t.Errorf("with harness evidence = %v, want [ci_build email]", got)
	}
	// An evidence schema that is not the harness one is an ordinary human decision: mail only.
	other := newIntentRepo()
	if err := intentConsumer(other).Handle(context.Background(), event.Envelope{
		ID: "env-4", Type: "governance.proposal_accepted",
		Payload: []byte(`{"FindingID":"fnd-4","EvidenceSchema":"analyst-note/v1","OccurredAt":"2026-09-30T09:00:00Z"}`),
	}); err != nil {
		t.Fatalf("handle other: %v", err)
	}
	if got := other.kinds(); len(got) != 1 || got[0] != domain.DeliveryEmail {
		t.Errorf("with other evidence = %v, want [email]", got)
	}
}

// A node that does no outward delivery is a valid deployment: the lifecycle events are
// ignored rather than panicking on a nil service.
func TestConsumer_LifecycleEventsIgnoredWithoutDeliveryService(t *testing.T) {
	c := consumer(&memRepo{}) // no WithDeliveryIntents
	for _, typ := range []string{"governance.finding_opened", "governance.proposal_accepted"} {
		if err := c.Handle(context.Background(), mkEnv(typ, []byte(`{"FindingID":"fnd-1"}`))); err != nil {
			t.Errorf("%s without a delivery service: %v", typ, err)
		}
	}
}

// The dev /internal/governance-events seam posts envelopes with no id. Using the empty
// string as the dedup key would collapse every event of a type onto ONE intent; the
// surrogate keeps distinct facts distinct.
func TestConsumer_EnvelopeWithoutIDStillDistinguishesFacts(t *testing.T) {
	repo := newIntentRepo()
	c := intentConsumer(repo)
	for _, payload := range []string{
		`{"FindingID":"fnd-1","OccurredAt":"2026-09-30T09:00:00Z"}`,
		`{"FindingID":"fnd-2","OccurredAt":"2026-09-30T09:00:00Z"}`,
		`{"FindingID":"fnd-1","OccurredAt":"2026-09-30T09:00:00Z"}`, // a genuine duplicate
	} {
		if err := c.Handle(context.Background(), mkEnv("governance.finding_opened", []byte(payload))); err != nil {
			t.Fatalf("handle %s: %v", payload, err)
		}
	}
	if len(repo.saved) != 2 {
		t.Errorf("saved %d intents, want 2 (two distinct facts, one duplicate)", len(repo.saved))
	}
}

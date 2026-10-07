package inbound_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	govclient "github.com/themis-project/themis/internal/communication/adapters/governance"
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
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.finding_resolved", []byte(`{}`))); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if len(repo.queue) != 0 {
		t.Error("unknown event must not touch the queue")
	}
}

func TestConsumer_MalformedPayloads(t *testing.T) {
	c := consumer(&memRepo{})
	for _, evt := range []string{"governance.position_established", "governance.position_revised"} {
		if err := c.Handle(context.Background(), mkEnv(evt, []byte("{not json"))); err == nil {
			t.Errorf("%s: malformed payload should error", evt)
		}
	}
}

// --- N-M1a: outward-delivery intents -------------------------------------------------------

// intentStore is an in-memory DeliveryIntents double reproducing the one store behaviour the
// mapping depends on: idempotence on the originating event id.
type intentStore struct {
	created []app.Intent
	byEvent map[string]app.Intent
}

func newIntentStore() *intentStore { return &intentStore{byEvent: map[string]app.Intent{}} }

func (s *intentStore) CreateIntent(_ context.Context, in app.Intent) (app.Intent, error) {
	if in.OriginEventID != "" {
		if existing, ok := s.byEvent[in.OriginEventID]; ok {
			return existing, nil
		}
		s.byEvent[in.OriginEventID] = in
	}
	s.created = append(s.created, in)
	return in, nil
}

func (s *intentStore) GetIntent(context.Context, string) (app.Intent, error) {
	return app.Intent{}, app.ErrIntentNotFound
}
func (s *intentStore) GetPendingForWork(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (s *intentStore) RecordAttempt(context.Context, app.Attempt) error               { return nil }
func (s *intentStore) MarkDelivered(context.Context, string, map[string]string) error { return nil }
func (s *intentStore) MarkDeadLetter(context.Context, string, string) error           { return nil }
func (s *intentStore) CancelIntent(context.Context, string) error                     { return nil }
func (s *intentStore) ListDeadLetters(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (s *intentStore) RetryIntent(context.Context, string) error { return nil }

type intentIDs struct{ n int }

func (g *intentIDs) NewID() string { g.n++; return fmt.Sprintf("int-%d", g.n) }

// deliveringConsumer wires a consumer with the delivery intake attached.
func deliveringConsumer(intents *intentStore) *inbound.Consumer {
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{})
	return consumer(&memRepo{}).WithIntents(svc)
}

// govEnv is a Governance envelope carrying the identity fields the intent's lineage records.
func govEnv(id, typ string, payload []byte) event.Envelope {
	return event.Envelope{
		ID: id, Type: typ, SourceContext: "governance", Subject: "fnd-1",
		SchemaRef: typ + ".v1", CorrelationID: "corr-1",
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(), Payload: payload,
	}
}

const findingOpenedPayload = `{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-2026-1"}`

func TestConsumer_FindingOpenedRecordsOneJiraIntent(t *testing.T) {
	intents := newIntentStore()
	env := govEnv("env-1", "governance.finding_opened", []byte(findingOpenedPayload))
	if err := deliveringConsumer(intents).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 1 {
		t.Fatalf("created %d intents, want 1", len(intents.created))
	}
	in := intents.created[0]
	if in.Type != app.IntentJiraIssue || in.ReleaseID != "rel-1" || in.OriginEventID != "env-1" {
		t.Errorf("intent = %+v", in)
	}
	if in.Lineage.EventType != "governance.finding_opened" || in.Lineage.SourceContext != "governance" ||
		in.Lineage.CorrelationID != "corr-1" || in.Lineage.EventID != "env-1" {
		t.Errorf("lineage = %+v", in.Lineage)
	}
	if in.Snapshot["cve"] != "CVE-2026-1" || in.Snapshot["finding_id"] != "fnd-1" {
		t.Errorf("snapshot = %v", in.Snapshot)
	}
	// Product/project are NOT resolved here: that would be a Registry read on the reader path.
	if in.ProductID != "" || in.ProjectID != "" {
		t.Errorf("reader must not resolve product/project: %+v", in)
	}
}

// Re-delivering the SAME envelope id must not enqueue a second ticket — the transport is
// at-least-once, so this is the normal case, not an edge case.
func TestConsumer_FindingOpenedRedeliveryCreatesNoSecondIntent(t *testing.T) {
	intents := newIntentStore()
	c := deliveringConsumer(intents)
	env := govEnv("env-1", "governance.finding_opened", []byte(findingOpenedPayload))
	for i := 0; i < 2; i++ {
		if err := c.Handle(context.Background(), env); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	if len(intents.created) != 1 {
		t.Fatalf("created %d intents for one event, want 1", len(intents.created))
	}
}

func TestConsumer_ProposalAcceptedRecordsOneDecisionMail(t *testing.T) {
	intents := newIntentStore()
	c := deliveringConsumer(intents)
	env := govEnv("env-2", "governance.proposal_accepted",
		[]byte(`{"FindingID":"fnd-1","ProposalID":"prop-1","PositionVersion":2}`))
	for i := 0; i < 2; i++ { // the second delivery is the replay
		if err := c.Handle(context.Background(), env); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	if len(intents.created) != 1 {
		t.Fatalf("created %d intents for one event, want 1", len(intents.created))
	}
	in := intents.created[0]
	if in.Type != app.IntentEmail || in.ProposalID != "prop-1" || in.FindingID != "fnd-1" {
		t.Errorf("intent = %+v", in)
	}
	if in.Destination != "security-decisions" {
		t.Errorf("destination = %q", in.Destination)
	}
	if in.Snapshot["position_version"] != "2" {
		t.Errorf("snapshot = %v", in.Snapshot)
	}
}

// A Finding whose event names no Release records nothing and reports no error: there is no
// subject to track a fix for, and a retry would not produce one.
func TestConsumer_FindingOpenedWithoutReleaseRecordsNothing(t *testing.T) {
	intents := newIntentStore()
	env := govEnv("env-3", "governance.finding_opened", []byte(`{"FindingID":"fnd-1","ReleaseID":""}`))
	if err := deliveringConsumer(intents).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 0 {
		t.Errorf("created %d intents, want 0", len(intents.created))
	}
}

func TestConsumer_ProposalAcceptedWithoutSubjectRecordsNothing(t *testing.T) {
	intents := newIntentStore()
	env := govEnv("env-4", "governance.proposal_accepted", []byte(`{"PositionVersion":1}`))
	if err := deliveringConsumer(intents).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 0 {
		t.Errorf("created %d intents, want 0", len(intents.created))
	}
}

func TestConsumer_DeliveryEventsMalformedPayloads(t *testing.T) {
	c := deliveringConsumer(newIntentStore())
	for _, evt := range []string{"governance.finding_opened", "governance.proposal_accepted"} {
		if err := c.Handle(context.Background(), govEnv("env-x", evt, []byte("{not json"))); err == nil {
			t.Errorf("%s: malformed payload should error (so the event is retried, not dropped)", evt)
		}
	}
}

// Without the intake wired (delivery disabled on this node) the delivery events are inert —
// no intent, no error — while the Position events keep working.
func TestConsumer_WithoutIntentsRecordsNoIntents(t *testing.T) {
	repo := &memRepo{}
	c := consumer(repo)
	for _, evt := range []string{"governance.finding_opened", "governance.proposal_accepted"} {
		if err := c.Handle(context.Background(), govEnv("env-5", evt, []byte(findingOpenedPayload))); err != nil {
			t.Errorf("%s: %v", evt, err)
		}
	}
	if len(repo.queue) != 0 {
		t.Error("delivery events must not touch the publishable queue")
	}
}

// blockingDeliverer stands in for Jira or a mail relay that never answers. The reader holds no
// deliverer at all, which is the invariant under test: it writes the intent and returns, so an
// unreachable external system cannot stall the bus reader path.
type blockingDeliverer struct{ calls int }

func (d *blockingDeliverer) DeliverIntent(ctx context.Context, _ app.Intent) error {
	d.calls++
	<-ctx.Done() // would hang the reader if the reader ever called it
	return ctx.Err()
}

func TestConsumer_NeverDelivers(t *testing.T) {
	intents := newIntentStore()
	blocked := &blockingDeliverer{}

	// First prove the stand-in really does hang — it is what an unreachable Jira looks like.
	blockCtx, cancelBlock := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelBlock()
	if err := blocked.DeliverIntent(blockCtx, app.Intent{}); err == nil {
		t.Fatal("the blocking stand-in returned without its context being cancelled")
	}
	if blocked.calls != 1 {
		t.Fatalf("stand-in calls = %d, want 1", blocked.calls)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- deliveringConsumer(intents).Handle(ctx,
			govEnv("env-6", "governance.finding_opened", []byte(findingOpenedPayload)))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handle: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("the event reader blocked — it must only persist the intent")
	}
	if blocked.calls != 1 {
		t.Errorf("deliverer calls = %d; handling an event must add none", blocked.calls)
	}
	if len(intents.created) != 1 {
		t.Errorf("the reader must persist exactly one intent, got %d", len(intents.created))
	}
}

// The subscription has to DISPATCH on the new types; an event outside the interest set never
// reaches Handle, so an undeclared mapping is dead code in production.
func TestSubscriptionDispatchesOnTheDeliveryTriggers(t *testing.T) {
	for _, typ := range []string{"governance.finding_opened", "governance.proposal_accepted"} {
		if !inbound.Subscription.InInterest(typ) {
			t.Errorf("%s is not in the Communication interest set", typ)
		}
	}
}

// --- Auth-enabled estate: the reader's own read must be authenticated -----------------------

// authedPostureStub is a Governance node running with THEMIS_AUTH_REQUIRED=1: every read without
// the key is a 401.
func authedPostureStub(t *testing.T, key string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[{"finding_id":"fnd-1","cve":"CVE-2026-1","base_score":95}]`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// materializingConsumer is the PRODUCTION shape of the reader on an auth-enabled estate: the intent
// service renders the ticket payload through the outward serializer, which reads the Release posture
// over Governance's read API — so the reader's own HTTP read is in the path, with whatever credential
// the client was given.
func materializingConsumer(intents *intentStore, governanceURL, apiKey string) *inbound.Consumer {
	posture := govclient.NewClient(governanceURL, nil).WithAPIKey(apiKey)
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{}).
		WithPayloadRenderer(serializer.NewOutwardRenderer(posture))
	return consumer(&memRepo{}).WithIntents(svc)
}

// WITH the key the ticket intent is recorded, payload and all. This is the enterprise-VM case of
// 2026-10-05 and the reason the read seam carries a credential at all.
func TestConsumer_RecordsTheJiraIntentOnAnAuthEnabledEstate(t *testing.T) {
	const key = "read-scoped-key-abc123"
	srv := authedPostureStub(t, key)
	intents := newIntentStore()

	env := govEnv("env-1", "governance.finding_opened", []byte(findingOpenedPayload))
	if err := materializingConsumer(intents, srv.URL, key).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 1 {
		t.Fatalf("created %d intents, want 1", len(intents.created))
	}
	in := intents.created[0]
	if in.PayloadSHA256 == "" || len(in.PayloadBytes) == 0 {
		t.Fatalf("the intent carries no materialized payload: %q", in.PayloadSHA256)
	}
	// The posture the authenticated read returned is IN the ticket: one Critical, its id listed.
	if body := string(in.PayloadBytes); !strings.Contains(body, "Critical: 1") || !strings.Contains(body, "CVE-2026-1") {
		t.Errorf("payload does not reflect the posture read:\n%s", body)
	}
}

// WITHOUT the key, the same estate reproduces the defect exactly: the read 401s, NOTHING is
// recorded, and Handle returns an error so the envelope is retried rather than dropped.
//
// Both halves are the regression. The error is correct behaviour — an intent whose content could not
// be determined must not be queued (D-N-3) — but it is also a LOOP: the retry will 401 again, which
// is why the error has to name the credential rather than look like a broken endpoint.
func TestConsumer_UnauthenticatedPostureReadRecordsNothingAndRetries(t *testing.T) {
	srv := authedPostureStub(t, "read-scoped-key-abc123")
	intents := newIntentStore()

	env := govEnv("env-1", "governance.finding_opened", []byte(findingOpenedPayload))
	err := materializingConsumer(intents, srv.URL, "").Handle(context.Background(), env)
	if err == nil {
		t.Fatal("a 401 on the posture read must surface, so the envelope is retried")
	}
	for _, want := range []string{"401", "THEMIS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q — a bare status reads as a broken endpoint", err, want)
		}
	}
	if len(intents.created) != 0 {
		t.Errorf("an intent was recorded from a refused read: %+v", intents.created)
	}
}

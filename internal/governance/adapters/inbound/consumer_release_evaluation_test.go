package inbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The inbound half of N-M2b: knowledge.release_correlation_completed.v1 RECORDS a pending
// evaluation and does nothing else. The test's central assertion is a NEGATIVE one — the handler
// never reaches Registry — because that is the whole reason the step is split in two: a handler
// error halts the entire Knowledge stream into Governance after five attempts
// (EDR-EVENTBUS-01 D8), so an identity lookup here would let a Registry outage stop Findings
// from opening.

type recordedEvaluation struct{ releaseID, sbomID, cause string }

type memQueue struct {
	rows []recordedEvaluation
	err  error
}

func (q *memQueue) EnqueuePendingReleaseEvaluation(_ context.Context, releaseID, sbomID, cause string) error {
	if q.err != nil {
		return q.err
	}
	for _, r := range q.rows {
		if r == (recordedEvaluation{releaseID, sbomID, cause}) {
			return nil // ON CONFLICT DO NOTHING
		}
	}
	q.rows = append(q.rows, recordedEvaluation{releaseID, sbomID, cause})
	return nil
}

func evaluationConsumer(q app.PendingEvaluations, logger *observability.Logger) *inbound.Consumer {
	svc := app.NewFindingService(newMemRepo(), &ids{}, clk{})
	return inbound.NewConsumer(app.NewCoordinator(svc).WithEvaluations(q)).WithLogger(logger)
}

func TestConsumer_ReleaseCorrelationCompleted_RecordsPendingEvaluation(t *testing.T) {
	q := &memQueue{}
	// snake_case on the wire (M2a-1), with the body's own occurred_at the ACL does not read.
	payload := []byte(`{"release_id":"rel-1","sbom_id":"ev-1","cause":"new_sbom",
		"occurred_at":"2026-10-07T12:00:00Z"}`)
	c := evaluationConsumer(q, nil)

	if err := c.Handle(context.Background(), mkEnv("knowledge.release_correlation_completed", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(q.rows) != 1 || q.rows[0] != (recordedEvaluation{"rel-1", "ev-1", "new_sbom"}) {
		t.Fatalf("recorded = %+v", q.rows)
	}

	// A redelivery records no second row (the store's ON CONFLICT DO NOTHING; the inbox dedupes
	// one delivery, this dedupes the FACT).
	if err := c.Handle(context.Background(), mkEnv("knowledge.release_correlation_completed", payload)); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if len(q.rows) != 1 {
		t.Errorf("a redelivery added a row: %+v", q.rows)
	}

	// A rediscovery of the same SBOM is a DIFFERENT fact and gets its own row — the cause
	// changes what a subscriber may do with it (M2-3).
	rediscovery := []byte(`{"release_id":"rel-1","sbom_id":"ev-1","cause":"rediscovery"}`)
	if err := c.Handle(context.Background(), mkEnv("knowledge.release_correlation_completed", rediscovery)); err != nil {
		t.Fatalf("rediscovery: %v", err)
	}
	if len(q.rows) != 2 || q.rows[1].cause != "rediscovery" {
		t.Errorf("recorded = %+v, want a second row for the rediscovery", q.rows)
	}
}

// A cause outside the closed vocabulary is REFUSED: nothing recorded, and the handler returns
// nil so the stream keeps moving. Returning an error here would halt the Knowledge stream over
// an event that will be just as unusable on its fifth redelivery.
func TestConsumer_ReleaseCorrelationCompleted_UnknownCauseIsRefusedNotHalted(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	q := &memQueue{}
	c := evaluationConsumer(q, observability.New(zap.New(core)))

	for _, body := range []string{
		`{"release_id":"rel-1","sbom_id":"ev-1","cause":"other"}`,
		`{"release_id":"rel-1","sbom_id":"ev-1"}`, // no cause at all
		`{"release_id":"","sbom_id":"ev-1","cause":"new_sbom"}`,
		`{"release_id":"rel-1","sbom_id":"","cause":"rediscovery"}`,
	} {
		if err := c.Handle(context.Background(), mkEnv("knowledge.release_correlation_completed", []byte(body))); err != nil {
			t.Errorf("%s: err = %v, want nil (refused, not halted)", body, err)
		}
	}
	if len(q.rows) != 0 {
		t.Errorf("a refused event recorded %+v", q.rows)
	}
	if logs.Len() != 4 {
		t.Errorf("logged %d refusals, want 4 — a silent skip is indistinguishable from a drop", logs.Len())
	}
	if entry := logs.All()[0]; !strings.Contains(entry.Message, "refused") {
		t.Errorf("log message = %q", entry.Message)
	}
}

// Everything else IS returned, so the bus retries: a malformed payload and a failed store write
// are both conditions a later delivery can resolve, and the pending row is the only record that
// this Release needs evaluating.
func TestConsumer_ReleaseCorrelationCompleted_RetryableFailuresPropagate(t *testing.T) {
	c := evaluationConsumer(&memQueue{}, nil)
	if err := c.Handle(context.Background(), mkEnv("knowledge.release_correlation_completed", []byte(`{bad`))); err == nil {
		t.Error("a malformed payload must be an error so the event is retried, not dropped")
	}

	boom := errors.New("insert failed")
	c = evaluationConsumer(&memQueue{err: boom}, nil)
	err := c.Handle(context.Background(), mkEnv("knowledge.release_correlation_completed",
		[]byte(`{"release_id":"rel-1","sbom_id":"ev-1","cause":"new_sbom"}`)))
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the store error", err)
	}
}

// The reader never resolves identity and never publishes (M1a-1, carried): the only port the
// completion fact touches is the queue. Asserted structurally — the consumer is handed a queue
// and a repository, and there is no seam on it that could reach Registry.
func TestConsumer_ReleaseCorrelationCompleted_NeverResolvesIdentity(t *testing.T) {
	q := &memQueue{}
	c := evaluationConsumer(q, nil)
	env := event.Envelope{
		ID:      "env-1",
		Type:    "knowledge.release_correlation_completed",
		Payload: []byte(`{"release_id":"rel-1","sbom_id":"ev-1","cause":"new_sbom"}`),
	}
	if err := c.Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	// The recorded row carries NO product and NO project: resolving them is the worker's job,
	// off the reader path.
	if len(q.rows) != 1 {
		t.Fatalf("recorded = %+v", q.rows)
	}
	if _, ok := any(c).(interface {
		ProductAndProjectOfRelease(context.Context, string) (string, string, error)
	}); ok {
		t.Error("the inbound consumer must hold no identity-resolution seam")
	}
}

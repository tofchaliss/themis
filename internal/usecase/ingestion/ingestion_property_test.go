package ingestion_test

import (
	"context"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
)

// statusRank orders the forward-progress ingestion states. Terminal failure
// states (REJECTED/FAILED) are handled separately.
var statusRank = map[domain.IngestionStatus]int{
	domain.IngestionStatusValidating:  1,
	domain.IngestionStatusCorrelating: 2,
	domain.IngestionStatusEnriching:   3,
	domain.IngestionStatusCompleted:   4,
	domain.IngestionStatusNotified:    5,
}

func assertLegalStatusSequence(t *rapid.T, updates []domain.IngestionStatus) {
	prev := 0
	for i, s := range updates {
		if s == domain.IngestionStatusRejected || s == domain.IngestionStatusFailed {
			if i != len(updates)-1 {
				t.Fatalf("terminal status %q not last in %v", s, updates)
			}
			continue
		}
		rank, ok := statusRank[s]
		if !ok {
			t.Fatalf("unknown status %q in %v", s, updates)
		}
		if rank < prev {
			t.Fatalf("non-monotonic transition to %q in %v", s, updates)
		}
		prev = rank
	}
}

// TestIngestionLifecycleProperty drives the pipeline under varied trust/parser
// outcomes and asserts the persisted status sequence is always a legal path and
// the terminal result is consistent with retryability rules.
func TestIngestionLifecycleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		trustAccepted := rapid.Bool().Draw(t, "trust_accepted")
		trustDuplicate := trustAccepted && rapid.Bool().Draw(t, "trust_duplicate")
		parserAccepted := rapid.Bool().Draw(t, "parser_accepted")
		parserStatus := rapid.SampledFrom([]domain.ParseStatus{
			domain.ParseStatusRejected,
			domain.ParseStatusFailed,
		}).Draw(t, "parser_status")

		jobs := &memoryJobs{}
		pipeline := newTestPipeline(jobs)
		switch {
		case !trustAccepted:
			pipeline.Trust = fixedTrust{accepted: false, message: "trust rejected"}
		case trustDuplicate:
			pipeline.Trust = fixedTrust{accepted: true, duplicateID: "dup-scan"}
		}
		if !parserAccepted {
			pipeline.Parser = fixedParser{accepted: false, message: "parser rejected", status: parserStatus}
		}

		result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertLegalStatusSequence(t, jobs.updates)

		switch result.Status {
		case domain.IngestionStatusNotified, domain.IngestionStatusRejected,
			domain.IngestionStatusFailed, domain.IngestionStatusCompleted:
		default:
			t.Fatalf("unexpected terminal status %q", result.Status)
		}
		if result.Status == domain.IngestionStatusRejected && result.Retryable {
			t.Fatalf("rejected result must not be retryable: %+v", result)
		}
		if result.Status == domain.IngestionStatusFailed && !result.Retryable {
			t.Fatalf("failed result must be retryable: %+v", result)
		}
	})
}

// TestIngestionIdempotencyProperty asserts that re-ingesting an identical input
// (same ingestion ID) is idempotent: the second run is a duplicate with the same
// scan ID and produces no further lifecycle transitions.
func TestIngestionIdempotencyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := "ing-" + rapid.StringMatching(`[a-f0-9]{8}`).Draw(t, "ingestion_id")
		jobs := &memoryJobs{}
		pipeline := newTestPipeline(jobs)

		input := baseSBOMInput()
		input.IngestionID = id

		first, err := pipeline.IngestSBOM(context.Background(), input)
		if err != nil {
			t.Fatalf("first ingest: %v", err)
		}
		if first.Duplicate {
			t.Fatalf("first ingest unexpectedly duplicate: %+v", first)
		}
		if first.Status != domain.IngestionStatusNotified {
			t.Fatalf("first status = %q", first.Status)
		}
		transitionsAfterFirst := len(jobs.updates)

		second, err := pipeline.IngestSBOM(context.Background(), input)
		if err != nil {
			t.Fatalf("second ingest: %v", err)
		}
		if !second.Duplicate {
			t.Fatalf("replay not marked duplicate: %+v", second)
		}
		if second.ScanID != first.ScanID {
			t.Fatalf("replay scan id = %q want %q", second.ScanID, first.ScanID)
		}
		if len(jobs.updates) != transitionsAfterFirst {
			t.Fatalf("replay produced new transitions: %d want %d", len(jobs.updates), transitionsAfterFirst)
		}
	})
}

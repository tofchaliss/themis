package domain_test

import (
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestIsRetryable(t *testing.T) {
	if !domain.IsRetryable(domain.ErrRetryable) {
		t.Fatal("expected retryable")
	}
	if domain.IsRetryable(errors.New("other")) {
		t.Fatal("expected non-retryable")
	}
}

func TestIngestionStatusConstants(t *testing.T) {
	statuses := []domain.IngestionStatus{
		domain.IngestionStatusReceived,
		domain.IngestionStatusValidating,
		domain.IngestionStatusCorrelating,
		domain.IngestionStatusEnriching,
		domain.IngestionStatusCompleted,
		domain.IngestionStatusNotified,
		domain.IngestionStatusRejected,
		domain.IngestionStatusFailed,
	}
	for _, status := range statuses {
		if status == "" {
			t.Fatal("empty ingestion status constant")
		}
	}
}

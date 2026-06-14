package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestJobStatusValues(t *testing.T) {
	statuses := []domain.JobStatus{
		domain.JobStatusPending,
		domain.JobStatusRunning,
		domain.JobStatusCompleted,
		domain.JobStatusFailed,
		domain.JobStatusCancelled,
	}
	for _, status := range statuses {
		if status == "" {
			t.Fatal("expected non-empty job status")
		}
	}
}

func TestJobTypes(t *testing.T) {
	types := []domain.JobType{
		domain.JobTypeIngestSBOM,
		domain.JobTypeIngestVEX,
		domain.JobTypeCorrelateVulns,
		domain.JobTypeReenrichVEX,
		domain.JobTypeNotify,
		domain.JobTypeSyncVEXFeed,
		domain.JobTypeApplyVEXSBOM,
	}
	for _, jobType := range types {
		if jobType == "" {
			t.Fatal("expected non-empty job type")
		}
	}
}

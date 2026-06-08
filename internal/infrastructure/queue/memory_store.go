package queue

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type memoryJobRecord struct {
	jobType      string
	status       string
	payload      []byte
	attempts     int
	errorMessage string
}

// MemoryJobStore is an in-memory JobStore for unit tests.
type MemoryJobStore struct {
	mu    sync.Mutex
	jobs  map[string]memoryJobRecord
	order []string
}

// NewMemoryJobStore creates an empty in-memory job store.
func NewMemoryJobStore() *MemoryJobStore {
	return &MemoryJobStore{jobs: make(map[string]memoryJobRecord)}
}

func (s *MemoryJobStore) Create(ctx context.Context, jobType string, payload []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	id := uuid.NewString()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[id] = memoryJobRecord{
		jobType: jobType,
		status:  "pending",
		payload: append([]byte(nil), payload...),
	}
	s.order = append(s.order, id)
	return id, nil
}

func (s *MemoryJobStore) MarkRunning(ctx context.Context, jobID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.updateStatus(jobID, "running")
}

func (s *MemoryJobStore) MarkCompleted(ctx context.Context, jobID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.updateStatus(jobID, "completed")
}

func (s *MemoryJobStore) MarkFailed(ctx context.Context, jobID, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("job %q not found", jobID)
	}
	record.status = "failed"
	record.errorMessage = message
	s.jobs[jobID] = record
	return nil
}

func (s *MemoryJobStore) IncrementAttempts(ctx context.Context, jobID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.jobs[jobID]
	if !ok {
		return 0, fmt.Errorf("job %q not found", jobID)
	}
	record.attempts++
	s.jobs[jobID] = record
	return record.attempts, nil
}

func (s *MemoryJobStore) CountByStatus(ctx context.Context, status string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.jobs {
		if record.status == status {
			count++
		}
	}
	return count, nil
}

func (s *MemoryJobStore) GetAttempts(ctx context.Context, jobID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.jobs[jobID]
	if !ok {
		return 0, fmt.Errorf("job %q not found", jobID)
	}
	return record.attempts, nil
}

func (s *MemoryJobStore) updateStatus(jobID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("job %q not found", jobID)
	}
	record.status = status
	s.jobs[jobID] = record
	return nil
}

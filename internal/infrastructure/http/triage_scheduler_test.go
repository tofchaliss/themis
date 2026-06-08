package httpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
	"github.com/themis-project/themis/internal/usecase/triage"
)

func TestStartTriageExpirySchedulerNilService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpserver.StartTriageExpiryScheduler(ctx, nil, time.Millisecond)
}

func TestStartTriageExpirySchedulerRuns(t *testing.T) {
	repo := &schedulerRepo{}
	svc := &triage.Handler{Repo: repo}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpserver.StartTriageExpiryScheduler(ctx, svc, 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if repo.calls == 0 {
		t.Fatal("expected expiry processor to run")
	}
}

type schedulerRepo struct {
	calls int
}

func (s *schedulerRepo) GetFindingScope(context.Context, string) (string, error) { return "", nil }
func (s *schedulerRepo) GetFindingContext(context.Context, string) (domain.TriageFindingContext, error) {
	return domain.TriageFindingContext{}, nil
}
func (s *schedulerRepo) AppendHistory(context.Context, domain.TriageHistoryRecord) error { return nil }
func (s *schedulerRepo) ListHistory(context.Context, string, domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}
func (s *schedulerRepo) UpdateRiskContext(context.Context, domain.RiskContextTriageUpdate) error {
	return nil
}
func (s *schedulerRepo) ListExpiredAcceptedRiskFindings(context.Context, time.Time) ([]string, error) {
	s.calls++
	return nil, nil
}
func (s *schedulerRepo) LatestDecision(context.Context, string) (string, error) { return "", nil }

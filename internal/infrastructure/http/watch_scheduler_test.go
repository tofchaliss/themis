package httpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
	"github.com/themis-project/themis/internal/usecase/watch"
)

func TestStartWatchSchedulerNilService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpserver.StartWatchScheduler(ctx, nil, time.Millisecond)
}

func TestStartWatchSchedulerRuns(t *testing.T) {
	repo := &schedulerWatchRepo{lastSuccess: time.Now().UTC()}
	calls := 0
	svc := &watch.Service{
		Repo: repo,
		NVD:  &schedulerNVD{},
		OnSuccess: func(time.Time) {
			calls++
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpserver.StartWatchScheduler(ctx, svc, 10*time.Millisecond)
	time.Sleep(35 * time.Millisecond)
	if calls == 0 {
		t.Fatal("expected watch cycle to run")
	}
}

type schedulerWatchRepo struct {
	lastSuccess time.Time
}

func (s *schedulerWatchRepo) ListWatchCatalog(context.Context) ([]domain.WatchCatalogEntry, error) {
	return nil, nil
}

func (s *schedulerWatchRepo) ListVulnerabilityRecords(context.Context) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}

func (s *schedulerWatchRepo) GetLastSuccessTimestamp(context.Context) (time.Time, error) {
	return s.lastSuccess, nil
}

func (s *schedulerWatchRepo) SetLastSuccessTimestamp(context.Context, time.Time) error {
	return nil
}

func (s *schedulerWatchRepo) UpsertVulnerability(_ context.Context, record domain.VulnerabilityRecord) (string, error) {
	return "v-" + record.CVEID, nil
}

func (s *schedulerWatchRepo) HasFinding(context.Context, string, string) (bool, error) {
	return false, nil
}

func (s *schedulerWatchRepo) CreateWatchFinding(context.Context, domain.CreateWatchFindingInput) (domain.CreateWatchFindingResult, error) {
	return domain.CreateWatchFindingResult{}, nil
}

type schedulerNVD struct{}

func (schedulerNVD) FetchModifiedSince(context.Context, time.Time) ([]domain.FeedVulnerability, error) {
	return nil, nil
}

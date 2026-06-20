package httpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/epsskev"
	"github.com/themis-project/themis/internal/adapter/exploitdb"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
)

func TestStartVEXFeedSchedulerNilService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpserver.StartVEXFeedScheduler(ctx, nil, time.Millisecond)
}

func TestStartExploitDBSchedulerNilService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpserver.StartExploitDBScheduler(ctx, nil, time.Millisecond)
}

func TestStartVEXFeedSchedulerRuns(t *testing.T) {
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{},
		Store: stubVEXStore{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpserver.StartVEXFeedScheduler(ctx, svc, 10*time.Millisecond)
	time.Sleep(35 * time.Millisecond)
}

func TestStartExploitDBSchedulerRuns(t *testing.T) {
	svc := &exploitdb.Service{
		Source: stubExploitSource{},
		Store:  stubExploitStore{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpserver.StartExploitDBScheduler(ctx, svc, 10*time.Millisecond)
	time.Sleep(35 * time.Millisecond)
}

func TestStartEPSSKevSchedulerRuns(t *testing.T) {
	svc := &epsskev.Service{
		Fetcher: stubEPSSFetcher{},
		Store:   stubEPSSStore{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpserver.StartEPSSKevScheduler(ctx, svc, 10*time.Millisecond)
	time.Sleep(35 * time.Millisecond)
}

type stubVEXStore struct{}

func (stubVEXStore) UpsertAssertions(context.Context, string, []domain.VendorVEXAssertion) (int, error) {
	return 0, nil
}
func (stubVEXStore) ListAssertionsForCVE(context.Context, string) ([]domain.VendorVEXAssertion, error) {
	return nil, nil
}
func (stubVEXStore) ListAssertionsForSBOMCVEs(context.Context, string, []string) (map[string][]domain.VendorVEXAssertion, error) {
	return nil, nil
}
func (stubVEXStore) FindSBOMDocumentIDsForCVE(context.Context, string) ([]string, error) {
	return nil, nil
}

type stubExploitSource struct{}

func (stubExploitSource) FetchExploits(context.Context) ([]domain.ExploitRecord, error) {
	return nil, nil
}

type stubExploitStore struct{}

func (stubExploitStore) UpsertExploits(context.Context, []domain.ExploitRecord) error { return nil }
func (stubExploitStore) HasPublicExploit(context.Context, string) (bool, error)       { return false, nil }
func (stubExploitStore) CountExploits(context.Context) (int, error)                   { return 0, nil }

type stubEPSSFetcher struct{}

func (stubEPSSFetcher) FetchEPSS(context.Context) ([]domain.EPSSSignal, error) { return nil, nil }
func (stubEPSSFetcher) FetchKEV(context.Context) ([]domain.KEVSignal, error)   { return nil, nil }

type stubEPSSStore struct{}

func (stubEPSSStore) UpsertEPSS(context.Context, []domain.EPSSSignal) error   { return nil }
func (stubEPSSStore) UpsertKEV(context.Context, []domain.KEVSignal) error     { return nil }
func (stubEPSSStore) ListKEVCVEIDs(context.Context) ([]string, error)         { return nil, nil }
func (stubEPSSStore) MarkStale(context.Context, bool) error                   { return nil }
func (stubEPSSStore) SignalsStale(context.Context) (bool, error)              { return false, nil }
func (stubEPSSStore) GetEPSSForCVE(context.Context, string) (*float64, error) { return nil, nil }
func (stubEPSSStore) IsKEVListed(context.Context, string) (bool, error)       { return false, nil }
func (stubEPSSStore) CountEPSSRows(context.Context) (int, error)              { return 0, nil }
func (stubEPSSStore) LastSuccessfulFetch(context.Context) (time.Time, error)  { return time.Time{}, nil }

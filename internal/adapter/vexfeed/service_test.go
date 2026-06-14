package vexfeed_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
)

func TestServiceNilStore(t *testing.T) {
	svc := &vexfeed.Service{}
	result, err := svc.RunSync(context.Background())
	if err != nil || result.AssertionsUpserted != 0 {
		t.Fatalf("RunSync() = %+v, %v", result, err)
	}
}

func TestNoOpSyncLoggerAndMetrics(t *testing.T) {
	var logger vexfeed.NoOpSyncLogger
	logger.Warn("warn")
	logger.Error("error")
	var metrics vexfeed.NoOpSyncMetrics
	metrics.RecordSync("feed", "ok")
	metrics.RecordAssertions("feed", "exact", 1)
	metrics.RecordPURLMismatch("feed")
}

func TestServiceUpsertError(t *testing.T) {
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{vexfeed.StaticFeedSource{
			FeedName:   "rhel",
			Assertions: []domain.VendorVEXAssertion{{CVEID: "CVE-1"}},
		}},
		Store: &failingStore{err: errors.New("upsert failed")},
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected upsert error")
	}
}

func TestServiceFindSBOMError(t *testing.T) {
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{vexfeed.StaticFeedSource{
			FeedName:   "rhel",
			Assertions: []domain.VendorVEXAssertion{{CVEID: "CVE-1"}},
		}},
		Store:    &failingStore{findErr: errors.New("find failed")},
		ReEnrich: &sbomEnqueueStub{},
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected find error")
	}
}

func TestServiceEnqueueError(t *testing.T) {
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{vexfeed.StaticFeedSource{
			FeedName:   "rhel",
			Assertions: []domain.VendorVEXAssertion{{CVEID: "CVE-1"}},
		}},
		Store:    &failingStore{cveSBOMs: map[string][]string{"CVE-1": {"sbom-1"}}},
		ReEnrich: &failingEnqueuer{err: errors.New("enqueue failed")},
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected enqueue error")
	}
}

type failingStore struct {
	err      error
	findErr  error
	cveSBOMs map[string][]string
}

func (f *failingStore) UpsertAssertions(context.Context, string, []domain.VendorVEXAssertion) (int, error) {
	return 0, f.err
}
func (f *failingStore) ListAssertionsForCVE(context.Context, string) ([]domain.VendorVEXAssertion, error) {
	return nil, nil
}
func (f *failingStore) ListAssertionsForSBOMCVEs(context.Context, string, []string) (map[string][]domain.VendorVEXAssertion, error) {
	return nil, nil
}
func (f *failingStore) FindSBOMDocumentIDsForCVE(context.Context, string) ([]string, error) {
	return nil, f.findErr
}

type failingEnqueuer struct{ err error }

func (f *failingEnqueuer) EnqueueApplyVEXForSBOMs(context.Context, []string) error {
	return f.err
}

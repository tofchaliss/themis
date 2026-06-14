package vexfeed_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
)

func TestVendorFeed_HTTP429_Retry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"ALPINE-1","aliases":["CVE-2024-0001"],"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"1.0-r1"}]}]}]}]`))
	}))
	defer srv.Close()

	fetcher := &vexfeed.HTTPFetcher{
		HTTPClient: srv.Client(),
		MaxRetries: 3,
		Sleep:      func(time.Duration) {},
	}
	src := vexfeed.URLFeedSource{Name_: "alpine", URL: srv.URL, Kind: "osv", Fetcher: fetcher}
	out, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(out) == 0 || calls.Load() < 2 {
		t.Fatalf("assertions = %d calls = %d", len(out), calls.Load())
	}
}

func TestVendorFeed_MalformedCSAF(t *testing.T) {
	good := `{"document":{"tracking":{"id":"RHSA-2024:0001"}},"vulnerabilities":[{"cve":"CVE-2024-0001","product_status":{"known_not_affected":["pkg:rpm/redhat/httpd@2.4.37-51.el8"]}}]}`
	bad := `{"document":{"tracking":{"id":"RHSA-2024:bad"}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			_, _ = w.Write([]byte(bad))
		default:
			_, _ = w.Write([]byte(good))
		}
	}))
	defer srv.Close()

	logger := &captureLogger{}
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{
			vexfeed.StaticFeedSource{FeedName: "rhel", Assertions: mustParseCSAF(t, good)},
			vexfeed.URLFeedSource{
				Name_: "rhel-bad", URL: srv.URL + "/bad", Kind: "csaf",
				Fetcher: &vexfeed.HTTPFetcher{HTTPClient: srv.Client()},
			},
		},
		Store:  &memStore{},
		Logger: logger,
	}
	result, err := svc.RunSync(context.Background())
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	if result.AssertionsUpserted == 0 {
		t.Fatal("expected good advisory processed")
	}
}

func TestVendorFeed_FetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	logger := &captureLogger{}
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{
			vexfeed.URLFeedSource{
				Name_:   "rhel",
				URL:     srv.URL,
				Kind:    "csaf",
				Fetcher: &vexfeed.HTTPFetcher{HTTPClient: srv.Client(), MaxRetries: 3, Sleep: func(time.Duration) {}},
			},
		},
		Store:  &memStore{},
		Logger: logger,
	}
	if _, err := svc.RunSync(context.Background()); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	if !logger.warned {
		t.Fatal("expected warning logged")
	}
}

func TestServiceEnqueuesSBOMReEnrich(t *testing.T) {
	enqueue := &sbomEnqueueStub{}
	svc := &vexfeed.Service{
		Feeds: []vexfeed.FeedSource{vexfeed.StaticFeedSource{
			FeedName: "rhel",
			Assertions: []domain.VendorVEXAssertion{{
				AdvisoryID: "RHSA-1", CVEID: "CVE-2024-1",
				ComponentPURL: "pkg:rpm/redhat/httpd@1.0", Status: domain.VEXStatusNotAffected,
			}},
		}},
		Store:    &memStore{cveSBOMs: map[string][]string{"CVE-2024-1": {"sbom-1"}}},
		ReEnrich: enqueue,
	}
	result, err := svc.RunSync(context.Background())
	if err != nil || result.SBOMsScheduled != 1 || len(enqueue.ids) != 1 {
		t.Fatalf("result=%+v err=%v ids=%v", result, err, enqueue.ids)
	}
}

func mustParseCSAF(t *testing.T, raw string) []domain.VendorVEXAssertion {
	t.Helper()
	out, err := vexfeed.ParseCSAF([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type memStore struct {
	cveSBOMs map[string][]string
}

func (m *memStore) UpsertAssertions(_ context.Context, _ string, assertions []domain.VendorVEXAssertion) (int, error) {
	return len(assertions), nil
}
func (m *memStore) ListAssertionsForCVE(context.Context, string) ([]domain.VendorVEXAssertion, error) {
	return nil, nil
}
func (m *memStore) ListAssertionsForSBOMCVEs(context.Context, string, []string) (map[string][]domain.VendorVEXAssertion, error) {
	return nil, nil
}
func (m *memStore) FindSBOMDocumentIDsForCVE(_ context.Context, cveID string) ([]string, error) {
	if m.cveSBOMs == nil {
		return nil, nil
	}
	return m.cveSBOMs[cveID], nil
}

type sbomEnqueueStub struct{ ids []string }

func (s *sbomEnqueueStub) EnqueueApplyVEXForSBOMs(_ context.Context, ids []string) error {
	s.ids = append(s.ids, ids...)
	return nil
}

type captureLogger struct {
	warned bool
}

func (l *captureLogger) Warn(string, ...any) { l.warned = true }
func (l *captureLogger) Error(string, ...any) {}

func TestSlogMismatchLogger(t *testing.T) {
	vexfeed.SlogMismatchLogger{Logger: slog.Default()}.LogPURLMismatch("CVE-1", "sbom", "vex")
}

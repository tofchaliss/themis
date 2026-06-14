package epsskev_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/epsskev"
	"github.com/themis-project/themis/internal/domain"
)

func gzipBody(t *testing.T, plain string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseEPSSCSV(t *testing.T) {
	csv := "#model_version:v1\nCVE,epss,percentile\nCVE-2024-0001,0.42,0.9\nCVE-2024-0002,0.1,0.2\n"
	scores, err := epsskev.ParseEPSSCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseEPSSCSV() error = %v", err)
	}
	if scores["CVE-2024-0001"] != 0.42 || scores["CVE-2024-0002"] != 0.1 {
		t.Fatalf("scores = %#v", scores)
	}
}

func TestParseEPSSCSVRejectsOutOfRange(t *testing.T) {
	_, err := epsskev.ParseEPSSCSV(strings.NewReader("CVE,epss\nCVE-2024-0001,1.5\n"))
	if err == nil {
		t.Fatal("expected range error")
	}
}

func TestParseKEVJSON(t *testing.T) {
	body := `{"vulnerabilities":[{"cveID":"CVE-2024-0001"},{"cveID":"CVE-2024-0002"}]}`
	cves, err := epsskev.ParseKEVJSON([]byte(body))
	if err != nil {
		t.Fatalf("ParseKEVJSON() error = %v", err)
	}
	if len(cves) != 2 || cves[0] != "CVE-2024-0001" {
		t.Fatalf("cves = %#v", cves)
	}
}

func TestClientFetchEPSSGzip(t *testing.T) {
	csv := "CVE,epss,percentile\nCVE-2024-0001,0.5,0.8\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipBody(t, csv))
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL})
	signals, err := client.FetchEPSS(context.Background())
	if err != nil {
		t.Fatalf("FetchEPSS() error = %v", err)
	}
	if len(signals) != 1 || signals[0].Score != 0.5 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestClientFetchKEV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-9999"}]}`))
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL})
	signals, err := client.FetchKEV(context.Background())
	if err != nil {
		t.Fatalf("FetchKEV() error = %v", err)
	}
	if len(signals) != 1 || !signals[0].Listed {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestClientHTTP500Retries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{
		EPSSURL:    srv.URL,
		KEVURL:     srv.URL,
		MaxRetries: 3,
		Sleep:      func(time.Duration) {},
	})
	_, err := client.FetchEPSS(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

type memStore struct {
	epssRows map[string]float64
	kev      map[string]bool
	stale    bool
	fetched  time.Time
}

func (m *memStore) UpsertEPSS(_ context.Context, signals []domain.EPSSSignal) error {
	for _, s := range signals {
		m.epssRows[s.CVEID] = s.Score
		m.fetched = s.FetchedAt
	}
	return nil
}
func (m *memStore) UpsertKEV(_ context.Context, signals []domain.KEVSignal) error {
	prev := make([]string, 0)
	for cve, listed := range m.kev {
		if listed {
			prev = append(prev, cve)
		}
	}
	listedNow := map[string]struct{}{}
	for _, s := range signals {
		listedNow[s.CVEID] = struct{}{}
		m.kev[s.CVEID] = true
	}
	for _, cve := range prev {
		if _, ok := listedNow[cve]; !ok {
			m.kev[cve] = false
		}
	}
	return nil
}
func (m *memStore) ListKEVCVEIDs(_ context.Context) ([]string, error) {
	var out []string
	for cve, listed := range m.kev {
		if listed {
			out = append(out, cve)
		}
	}
	return out, nil
}
func (m *memStore) MarkStale(_ context.Context, stale bool) error { m.stale = stale; return nil }
func (m *memStore) SignalsStale(context.Context) (bool, error)  { return m.stale, nil }
func (m *memStore) GetEPSSForCVE(_ context.Context, cveID string) (*float64, error) {
	if score, ok := m.epssRows[cveID]; ok {
		return &score, nil
	}
	return nil, nil
}
func (m *memStore) IsKEVListed(_ context.Context, cveID string) (bool, error) {
	return m.kev[cveID], nil
}
func (m *memStore) CountEPSSRows(_ context.Context) (int, error) { return len(m.epssRows), nil }
func (m *memStore) LastSuccessfulFetch(_ context.Context) (time.Time, error) {
	return m.fetched, nil
}

type stubFetcher struct {
	epss []domain.EPSSSignal
	kev  []domain.KEVSignal
	err  error
}

func (s stubFetcher) FetchEPSS(context.Context) ([]domain.EPSSSignal, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.epss, nil
}
func (s stubFetcher) FetchKEV(context.Context) ([]domain.KEVSignal, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.kev, nil
}

type batchEnqueuer struct {
	batches int
}

func (b *batchEnqueuer) EnqueueReEnrichSignalsBatches(_ context.Context, totalOpen int) error {
	if totalOpen <= 0 {
		return nil
	}
	b.batches = (totalOpen + 499) / 500
	return nil
}

type openCounter struct{ total int }

func (o openCounter) CountOpenRiskContexts(context.Context) (int, error) { return o.total, nil }

func TestServiceRunSyncEnqueuesBatches(t *testing.T) {
	store := &memStore{epssRows: map[string]float64{"CVE-OLD": 0.1}, kev: map[string]bool{}}
	enq := &batchEnqueuer{}
	svc := &epsskev.Service{
		Fetcher: stubFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-2024-0001", Score: 0.2, FetchedAt: time.Now()}},
			kev:  []domain.KEVSignal{{CVEID: "CVE-2024-0001", Listed: true, FetchedAt: time.Now()}},
		},
		Store:        store,
		ReEnrich:     enq,
		OpenFindings: openCounter{total: 1200},
	}
	result, err := svc.RunSync(context.Background())
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	if result.EPSSRows != 1 || enq.batches != 3 {
		t.Fatalf("result=%+v batches=%d", result, enq.batches)
	}
}

func TestServiceRunSyncAbortsTruncatedEPSS(t *testing.T) {
	store := &memStore{epssRows: map[string]float64{
		"CVE-1": 0.1, "CVE-2": 0.2, "CVE-3": 0.3, "CVE-4": 0.4,
	}}
	svc := &epsskev.Service{
		Fetcher: stubFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-NEW", Score: 0.1, FetchedAt: time.Now()}},
		},
		Store: store,
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected truncated csv error")
	}
	if len(store.epssRows) != 4 {
		t.Fatalf("store mutated: %#v", store.epssRows)
	}
}

func TestServiceRefreshStaleFlags(t *testing.T) {
	store := &memStore{fetched: time.Now().Add(-26 * time.Hour)}
	svc := &epsskev.Service{Store: store, Now: func() time.Time { return time.Now() }}
	if err := svc.RefreshStaleFlags(context.Background()); err != nil {
		t.Fatalf("RefreshStaleFlags() error = %v", err)
	}
	if !store.stale {
		t.Fatal("expected stale flag")
	}
}

func TestUpsertKEVRemovesDelistedCVE(t *testing.T) {
	store := &memStore{kev: map[string]bool{"CVE-OLD": true}}
	if err := store.UpsertKEV(context.Background(), []domain.KEVSignal{
		{CVEID: "CVE-NEW", Listed: true, FetchedAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if store.kev["CVE-NEW"] != true || store.kev["CVE-OLD"] {
		t.Fatalf("kev map = %#v", store.kev)
	}
}

func TestServiceFetchFailurePreservesData(t *testing.T) {
	store := &memStore{epssRows: map[string]float64{"CVE-1": 0.5}}
	svc := &epsskev.Service{
		Fetcher: stubFetcher{err: errors.New("fetch failed")},
		Store:   store,
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if store.epssRows["CVE-1"] != 0.5 {
		t.Fatal("epss data changed on failure")
	}
}

func TestNoOpMetrics(t *testing.T) {
	var m epsskev.NoOpMetrics
	m.RecordSync("epss", "success")
	m.RecordReEnrichBatches(2)
	m.SetStale(true)
}

func TestServiceRunSyncRecordsMetrics(t *testing.T) {
	capture := &captureSyncMetrics{}
	svc := &epsskev.Service{
		Fetcher: stubFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-1", Score: 0.2, FetchedAt: time.Now()}},
			kev:  []domain.KEVSignal{{CVEID: "CVE-1", Listed: true, FetchedAt: time.Now()}},
		},
		Store:        &memStore{epssRows: map[string]float64{}, kev: map[string]bool{}},
		ReEnrich:     &batchEnqueuer{},
		OpenFindings: openCounter{total: 1000},
		Metrics:      capture,
		BatchSize:    100,
	}
	if _, err := svc.RunSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(capture.syncs) < 2 || capture.batches != 10 {
		t.Fatalf("metrics = syncs:%v batches:%d", capture.syncs, capture.batches)
	}
}

type captureSyncMetrics struct {
	syncs   []string
	batches int
	stale   bool
}

func (c *captureSyncMetrics) RecordSync(feed, status string) {
	c.syncs = append(c.syncs, feed+":"+status)
}
func (c *captureSyncMetrics) RecordReEnrichBatches(count int) { c.batches = count }
func (c *captureSyncMetrics) SetStale(v bool)                   { c.stale = v }

func TestServiceRefreshStaleSetsMetrics(t *testing.T) {
	capture := &captureSyncMetrics{}
	store := &memStore{fetched: time.Now().Add(-26 * time.Hour)}
	svc := &epsskev.Service{
		Store:   store,
		Now:     func() time.Time { return time.Now() },
		Metrics: capture,
	}
	if err := svc.RefreshStaleFlags(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !capture.stale || !store.stale {
		t.Fatal("expected stale metrics and store flag")
	}
}

func TestServiceRunSyncMissingDependencies(t *testing.T) {
	svc := &epsskev.Service{}
	if _, err := svc.RunSync(context.Background()); err == nil {
		t.Fatal("expected dependency error")
	}
}

func TestServiceRunSyncKEVFailureAfterEPSS(t *testing.T) {
	svc := &epsskev.Service{
		Fetcher: fetcherWithKEVErr{
			epss: []domain.EPSSSignal{{CVEID: "CVE-1", Score: 0.1, FetchedAt: time.Now()}},
		},
		Store: &memStore{epssRows: map[string]float64{}, kev: map[string]bool{}},
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected kev error")
	}
}

type fetcherWithKEVErr struct {
	epss []domain.EPSSSignal
}

func (f fetcherWithKEVErr) FetchEPSS(context.Context) ([]domain.EPSSSignal, error) {
	return f.epss, nil
}
func (fetcherWithKEVErr) FetchKEV(context.Context) ([]domain.KEVSignal, error) {
	return nil, errors.New("kev down")
}

func TestClientFetchPlaintextEPSS(t *testing.T) {
	csv := "CVE,epss,percentile\nCVE-2024-0001,0.5,0.8\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(csv))
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL})
	signals, err := client.FetchEPSS(context.Background())
	if err != nil {
		t.Fatalf("FetchEPSS() error = %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestClientFetchGzipEPSS(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("CVE,epss,percentile\nCVE-2024-0001,0.42,0.9\n"))
	_ = gw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL})
	signals, err := client.FetchEPSS(context.Background())
	if err != nil {
		t.Fatalf("FetchEPSS() error = %v", err)
	}
	if len(signals) != 1 || signals[0].Score != 0.42 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestClientGetOnceNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL, MaxRetries: 1})
	_, err := client.FetchEPSS(context.Background())
	if err == nil {
		t.Fatal("expected fetch error")
	}
}

func TestClientGetOnceReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1")
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL, MaxRetries: 1})
	_, err := client.FetchEPSS(context.Background())
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestServiceRunSyncTruncatedEPSS(t *testing.T) {
	svc := &epsskev.Service{
		Fetcher: stubFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-1", Score: 0.1, FetchedAt: time.Now()}},
		},
		Store: &memStore{
			epssRows: map[string]float64{"CVE-0": 0.5, "CVE-2": 0.6, "CVE-3": 0.7},
			kev:      map[string]bool{},
		},
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected truncated epss error")
	}
}

func TestServiceDefaultConfigHelpers(t *testing.T) {
	svc := &epsskev.Service{}
	if svc.BatchSize != 0 || svc.MinRowRatio != 0 || svc.StaleAfter != 0 {
		t.Fatal("expected zero defaults before helpers")
	}
	// Exercise defaults through RunSync with empty batch path.
	svc = &epsskev.Service{
		Fetcher:      stubFetcher{epss: []domain.EPSSSignal{{CVEID: "CVE-1", Score: 0.2, FetchedAt: time.Now()}}, kev: []domain.KEVSignal{}},
		Store:        &memStore{epssRows: map[string]float64{}, kev: map[string]bool{}},
		ReEnrich:     &batchEnqueuer{},
		OpenFindings: openCounter{total: 1001},
		Metrics:      &captureSyncMetrics{},
	}
	if _, err := svc.RunSync(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestParseEPSSCSVInvalidScore(t *testing.T) {
	_, err := epsskev.ParseEPSSCSV(strings.NewReader("CVE-2024-0001,not-a-float\n"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseEPSSCSVOutOfRange(t *testing.T) {
	_, err := epsskev.ParseEPSSCSV(strings.NewReader("CVE-2024-0001,1.5\n"))
	if err == nil {
		t.Fatal("expected range error")
	}
}

func TestServiceRunSyncCountEPSSFailure(t *testing.T) {
	svc := &epsskev.Service{
		Fetcher: stubFetcher{epss: []domain.EPSSSignal{{CVEID: "CVE-1", Score: 0.1, FetchedAt: time.Now()}}},
		Store:   newCountFailStore(),
	}
	_, err := svc.RunSync(context.Background())
	if err == nil {
		t.Fatal("expected count error")
	}
}

type countFailStore struct {
	memStore
}

func newCountFailStore() *countFailStore {
	return &countFailStore{memStore: memStore{epssRows: map[string]float64{}, kev: map[string]bool{}}}
}

func (s *countFailStore) CountEPSSRows(context.Context) (int, error) {
	return 0, errors.New("count failed")
}

func TestServiceRunSyncReEnrichFailure(t *testing.T) {
	svc := &epsskev.Service{
		Fetcher: stubFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-1", Score: 0.2, FetchedAt: time.Now()}},
			kev:  []domain.KEVSignal{{CVEID: "CVE-1", Listed: true, FetchedAt: time.Now()}},
		},
		Store:        &memStore{epssRows: map[string]float64{}, kev: map[string]bool{}},
		ReEnrich:     reEnrichFail{},
		OpenFindings: openCounter{total: 10},
	}
	result, err := svc.RunSync(context.Background())
	if err == nil || result.EPSSRows != 1 || result.KEVRows != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

type reEnrichFail struct{}

func (reEnrichFail) EnqueueReEnrichSignalsBatches(context.Context, int) error {
	return errors.New("enqueue failed")
}

func TestClientFetchKEVInvalidContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>bad</html>"))
	}))
	t.Cleanup(srv.Close)

	client := epsskev.NewClient(epsskev.ClientConfig{EPSSURL: srv.URL, KEVURL: srv.URL})
	_, err := client.FetchKEV(context.Background())
	if err == nil {
		t.Fatal("expected error for html response")
	}
}

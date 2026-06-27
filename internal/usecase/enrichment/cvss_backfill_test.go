package enrichment_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

type stubCVSSFetcher struct {
	data  map[string]domain.CVSSData
	errOn map[string]bool
}

func (s stubCVSSFetcher) FetchByCVEID(_ context.Context, cveID string) (domain.CVSSData, bool, error) {
	if s.errOn[cveID] {
		return domain.CVSSData{}, false, errors.New("nvd down")
	}
	d, ok := s.data[cveID]
	return d, ok, nil
}

type stubCVSSCatalog struct {
	candidates []string
	listErr    error
	applied    map[string]domain.CVSSData
	checked    []string
	applyErr   bool
}

func (s *stubCVSSCatalog) ListCVEsNeedingCVSS(context.Context, int, time.Time) ([]string, error) {
	return s.candidates, s.listErr
}

func (s *stubCVSSCatalog) ApplyCVSS(_ context.Context, cveID, severity string, score float64, vector string) error {
	if s.applyErr {
		return errors.New("apply failed")
	}
	if s.applied == nil {
		s.applied = map[string]domain.CVSSData{}
	}
	s.applied[cveID] = domain.CVSSData{Severity: severity, Score: score, Vector: vector}
	return nil
}

func (s *stubCVSSCatalog) MarkCVSSChecked(_ context.Context, cveID string) error {
	s.checked = append(s.checked, cveID)
	return nil
}

type stubReEnrich struct {
	enqueued int
	total    int
}

func (s *stubReEnrich) EnqueueReEnrichSignalsBatches(_ context.Context, total int) error {
	s.enqueued++
	s.total = total
	return nil
}

type stubOpenCount struct{ n int }

func (s stubOpenCount) CountOpenRiskContexts(context.Context) (int, error) { return s.n, nil }

func TestCVSSBackfillRun(t *testing.T) {
	catalog := &stubCVSSCatalog{candidates: []string{"CVE-1", "CVE-2", "CVE-3"}}
	fetcher := stubCVSSFetcher{
		data:  map[string]domain.CVSSData{"CVE-1": {Severity: "high", Score: 7.5, Vector: "v"}},
		errOn: map[string]bool{"CVE-3": true},
	}
	reenrich := &stubReEnrich{}
	svc := &enrichment.CVSSBackfillService{
		Fetcher:   fetcher,
		Catalog:   catalog,
		ReEnrich:  reenrich,
		OpenCount: stubOpenCount{n: 42},
	}

	result, err := svc.RunBackfill(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidates != 3 || result.Updated != 1 || result.Checked != 1 || result.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if got := catalog.applied["CVE-1"]; got.Severity != "high" || got.Score != 7.5 {
		t.Fatalf("CVE-1 not applied: %+v", catalog.applied)
	}
	if len(catalog.checked) != 1 || catalog.checked[0] != "CVE-2" {
		t.Fatalf("checked = %v", catalog.checked)
	}
	if reenrich.enqueued != 1 || reenrich.total != 42 {
		t.Fatalf("reenrich enqueued=%d total=%d", reenrich.enqueued, reenrich.total)
	}
}

func TestCVSSBackfillAbortsAfterConsecutiveFetchFailures(t *testing.T) {
	// 12 candidates, all failing: the cycle must abort once NVD has failed
	// enough times in a row instead of logging a warning for every candidate.
	candidates := make([]string, 12)
	errOn := map[string]bool{}
	for i := range candidates {
		id := "CVE-X-" + string(rune('A'+i))
		candidates[i] = id
		errOn[id] = true
	}
	catalog := &stubCVSSCatalog{candidates: candidates}
	svc := &enrichment.CVSSBackfillService{
		Fetcher: stubCVSSFetcher{errOn: errOn},
		Catalog: catalog,
	}

	result, err := svc.RunBackfill(context.Background())
	if err == nil {
		t.Fatal("expected abort error after consecutive NVD failures")
	}
	if result.Errors != 8 {
		t.Fatalf("expected to stop at 8 consecutive errors, got %d", result.Errors)
	}
	if result.Updated != 0 || result.Checked != 0 {
		t.Fatalf("no rows should have landed: %+v", result)
	}
}

func TestCVSSBackfillNoUpdatesSkipsReEnrich(t *testing.T) {
	catalog := &stubCVSSCatalog{candidates: []string{"CVE-2"}}
	reenrich := &stubReEnrich{}
	svc := &enrichment.CVSSBackfillService{
		Fetcher:   stubCVSSFetcher{},
		Catalog:   catalog,
		ReEnrich:  reenrich,
		OpenCount: stubOpenCount{n: 5},
	}
	result, err := svc.RunBackfill(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated != 0 || result.Checked != 1 {
		t.Fatalf("result = %+v", result)
	}
	if reenrich.enqueued != 0 {
		t.Fatal("re-enrich must not fire when nothing updated")
	}
}

type captureBackfillMetrics struct{ statuses []string }

func (c *captureBackfillMetrics) RecordBackfill(status string) { c.statuses = append(c.statuses, status) }

func TestCVSSBackfillCustomFieldsAndMetrics(t *testing.T) {
	catalog := &stubCVSSCatalog{candidates: []string{"CVE-1"}}
	mc := &captureBackfillMetrics{}
	svc := &enrichment.CVSSBackfillService{
		Fetcher:    stubCVSSFetcher{data: map[string]domain.CVSSData{"CVE-1": {Severity: "high", Score: 7.5}}},
		Catalog:    catalog,
		ReEnrich:   &stubReEnrich{},
		OpenCount:  stubOpenCount{n: 1},
		Metrics:    mc,
		BatchLimit: 50,
		RetryAfter: 24 * time.Hour,
		Now:        func() time.Time { return time.Unix(1000, 0) },
	}
	if _, err := svc.RunBackfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mc.statuses) != 1 || mc.statuses[0] != "updated" {
		t.Fatalf("metrics statuses = %v", mc.statuses)
	}
}

func TestCVSSBackfillNotConfigured(t *testing.T) {
	svc := &enrichment.CVSSBackfillService{}
	if result, err := svc.RunBackfill(context.Background()); err != nil || result.Candidates != 0 {
		t.Fatalf("unconfigured result=%+v err=%v", result, err)
	}
}

func TestCVSSBackfillListError(t *testing.T) {
	svc := &enrichment.CVSSBackfillService{
		Fetcher: stubCVSSFetcher{},
		Catalog: &stubCVSSCatalog{listErr: errors.New("db down")},
	}
	if _, err := svc.RunBackfill(context.Background()); err == nil {
		t.Fatal("expected list error")
	}
}

func TestCVSSBackfillApplyError(t *testing.T) {
	svc := &enrichment.CVSSBackfillService{
		Fetcher: stubCVSSFetcher{data: map[string]domain.CVSSData{"CVE-1": {Severity: "high", Score: 7.5}}},
		Catalog: &stubCVSSCatalog{candidates: []string{"CVE-1"}, applyErr: true},
	}
	if _, err := svc.RunBackfill(context.Background()); err == nil {
		t.Fatal("expected apply error")
	}
}

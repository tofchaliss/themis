package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/domain"
)

func TestGetStatusTopClamping(t *testing.T) {
	status := &fakeStatusRepo{}
	handler := api.NewHandler(api.Dependencies{Status: status, ThreatSignals: &fakeThreatSignals{}})
	r := mountTestAPI(handler, adminKeyRepo(t))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status?top=200", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if status.topN != 50 {
		t.Fatalf("topN = %d, want 50", status.topN)
	}
}

func TestGetStatusDegradedFeeds(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{
		Status:        &fakeStatusRepo{},
		ThreatSignals: &fakeThreatSignals{},
		FeedHealth:    fakeFeedHealth{degraded: []string{"alpine", "rocky"}},
	})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"degraded_feeds":["alpine","rocky"]`) {
		t.Fatalf("degraded_feeds missing: %s", rec.Body.String())
	}
}

func TestGetStatusFeedHealthError(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{
		Status:        &fakeStatusRepo{},
		ThreatSignals: &fakeThreatSignals{},
		FeedHealth:    fakeFeedHealth{err: errors.New("db down")},
	})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rec.Code)
	}
}

type fakeFeedHealth struct {
	degraded []string
	err      error
}

func (f fakeFeedHealth) DegradedFeeds(context.Context) ([]string, error) {
	return f.degraded, f.err
}

func TestDeleteSBOMForceGuard(t *testing.T) {
	mgmt := &fakeSBOMMgmt{deleteErr: domain.ErrCannotDeleteLatestSBOM}
	handler := api.NewHandler(api.Dependencies{SBOMMgmt: mgmt})
	rec := deleteSBOMRequest(t, handler, "sbom-1", false)
	assertAPIError(t, rec, http.StatusConflict, "CANNOT_DELETE_LATEST_SBOM")
}

func TestDeleteSBOMNotFound(t *testing.T) {
	mgmt := &fakeSBOMMgmt{deleteErr: domain.ErrSBOMNotFound}
	handler := api.NewHandler(api.Dependencies{SBOMMgmt: mgmt})
	rec := deleteSBOMRequest(t, handler, "missing", false)
	assertAPIError(t, rec, http.StatusNotFound, "SBOM_NOT_FOUND")
}

func TestDeleteSBOMAuditWritten(t *testing.T) {
	audit := &fakeAudit{}
	mgmt := &fakeSBOMMgmt{summary: domain.SBOMDeleteSummary{SBOMID: "sbom-1", ComponentCount: 3, FindingCount: 5}}
	handler := api.NewHandler(api.Dependencies{SBOMMgmt: mgmt, Audit: audit})
	rec := deleteSBOMRequest(t, handler, "sbom-1", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != domain.AuditActionSBOMDeleted {
		t.Fatalf("audit = %+v", audit.entries)
	}
}

func TestListSBOMsPagination(t *testing.T) {
	now := time.Now()
	mgmt := &fakeSBOMMgmt{
		items: []domain.SBOMListEntry{{ID: "a", ProductName: "p", UploadedAt: now}},
		total: 1,
	}
	handler := api.NewHandler(api.Dependencies{SBOMMgmt: mgmt})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms?limit=1", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func deleteSBOMRequest(t *testing.T, handler *api.Handler, id string, force bool) *httptest.ResponseRecorder {
	t.Helper()
	r := mountTestAPI(handler, adminKeyRepo(t))
	path := "/api/v1/sboms/" + id
	if force {
		path += "?force=true"
	}
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

type fakeStatusRepo struct {
	topN int
}

func (f *fakeStatusRepo) GetSystemStatus(_ context.Context, topN int) (domain.SystemStatus, error) {
	f.topN = topN
	return domain.SystemStatus{AsOf: time.Now()}, nil
}

type fakeThreatSignals struct{}

func (fakeThreatSignals) UpsertEPSS(context.Context, []domain.EPSSSignal) error   { return nil }
func (fakeThreatSignals) UpsertKEV(context.Context, []domain.KEVSignal) error     { return nil }
func (fakeThreatSignals) ListKEVCVEIDs(context.Context) ([]string, error)         { return nil, nil }
func (fakeThreatSignals) MarkStale(context.Context, bool) error                   { return nil }
func (fakeThreatSignals) SignalsStale(context.Context) (bool, error)              { return false, nil }
func (fakeThreatSignals) GetEPSSForCVE(context.Context, string) (*float64, error) { return nil, nil }
func (fakeThreatSignals) IsKEVListed(context.Context, string) (bool, error)       { return false, nil }
func (fakeThreatSignals) CountEPSSRows(context.Context) (int, error)              { return 0, nil }
func (fakeThreatSignals) LastSuccessfulFetch(context.Context) (time.Time, error) {
	return time.Time{}, nil
}

type fakeSBOMMgmt struct {
	items     []domain.SBOMListEntry
	total     int
	next      domain.PageResult
	deleteErr error
	summary   domain.SBOMDeleteSummary
}

func (f *fakeSBOMMgmt) ListSBOMs(context.Context, domain.PageRequest) ([]domain.SBOMListEntry, int, domain.PageResult, error) {
	return f.items, f.total, f.next, nil
}

func (f *fakeSBOMMgmt) ListProductSBOMs(context.Context, string, domain.PageRequest) ([]domain.SBOMListEntry, int, domain.PageResult, error) {
	return f.items, f.total, f.next, nil
}

func (f *fakeSBOMMgmt) SoftDeleteSBOM(context.Context, string, bool) (domain.SBOMDeleteSummary, error) {
	if f.deleteErr != nil {
		return domain.SBOMDeleteSummary{}, f.deleteErr
	}
	return f.summary, nil
}

type fakeAudit struct {
	entries []domain.AuditEntry
}

func (f *fakeAudit) Record(_ context.Context, entry domain.AuditEntry) error {
	f.entries = append(f.entries, entry)
	return nil
}

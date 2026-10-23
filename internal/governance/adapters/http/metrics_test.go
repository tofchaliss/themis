package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type metricsSource struct {
	rows []app.MetricsRow
	err  error
}

func (m metricsSource) MetricsFindings(context.Context) ([]app.MetricsRow, error) { return m.rows, m.err }

type estateSource map[string]app.ProductRef

func (e estateSource) ReleaseProducts(context.Context) (map[string]app.ProductRef, error) { return e, nil }

func metricsServer(t *testing.T, m *app.MetricsService) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	if m != nil {
		h = h.WithMetrics(m)
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv
}

func TestGetRemediationMetrics(t *testing.T) {
	now := fixedClock{}.Now()
	rows := []app.MetricsRow{
		{FindingID: "a", ReleaseID: "r1", Finding: domain.MetricsFinding{CreatedAt: now.Add(-3 * 24 * time.Hour), Open: true, Bucket: "high",
			FirstHumanAt: now.Add(-24 * time.Hour)}},
		{FindingID: "b", ReleaseID: "r2", Finding: domain.MetricsFinding{CreatedAt: now.Add(-40 * 24 * time.Hour), Open: true}},
	}
	m := app.NewMetricsService(metricsSource{rows: rows}, estateSource{"r1": {ID: "p1", Name: "Gateway"}, "r2": {ID: "p2", Name: "Portal"}}, nil, fixedClock{})
	code, body := do(t, http.MethodGet, metricsServer(t, m).URL+"/metrics/remediation?product=gateway", nil)
	var rep gen.RemediationReport
	if code != http.StatusOK || json.Unmarshal(body, &rep) != nil {
		t.Fatalf("metrics = %d %s", code, body)
	}
	if rep.Estate.Open != 2 || len(rep.Products) != 1 || rep.Products[0].Scope != "Gateway" || rep.Products[0].OpenByAge["0-7"]["high"] != 1 ||
		rep.Estate.OpenByAge["31-90"]["unknown"] != 1 || rep.Estate.TimeToDecision.Count != 1 || rep.Estate.TimeToDecision.MeanDays != 2 || rep.GeneratedAt.IsZero() {
		t.Fatalf("report = %s", body)
	}
	if code, body := do(t, http.MethodGet, metricsServer(t, m).URL+"/metrics/remediation", nil); code != http.StatusOK || json.Unmarshal(body, &rep) != nil || len(rep.Products) != 2 {
		t.Fatalf("all products = %d %s", code, body)
	}
	if code, _ := do(t, http.MethodGet, metricsServer(t, app.NewMetricsService(metricsSource{err: errors.New("db")}, nil, nil, fixedClock{})).URL+"/metrics/remediation", nil); code != http.StatusInternalServerError {
		t.Fatalf("error = %d", code)
	}
	if code, body := do(t, http.MethodGet, metricsServer(t, m).URL+"/metrics/remediation?tag=env:prod", nil); code != http.StatusOK || json.Unmarshal(body, &rep) != nil || rep.Estate.Open != 0 {
		t.Fatalf("tag filter = %d %s", code, body)
	}
	if code, _ := do(t, http.MethodGet, metricsServer(t, app.NewMetricsService(metricsSource{rows: rows}, nil, nil, fixedClock{})).URL+"/metrics/remediation?tag=x", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("tag without estate = %d", code)
	}
	if code, _ := do(t, http.MethodGet, metricsServer(t, nil).URL+"/metrics/remediation", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("unwired = %d", code)
	}
}

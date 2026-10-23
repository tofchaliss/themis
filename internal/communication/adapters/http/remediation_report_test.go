package http_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
)

type reportSource struct {
	rep app.RemediationReport
	err error
}

func (r reportSource) RemediationMetrics(context.Context, string) (app.RemediationReport, error) {
	return r.rep, r.err
}

func reportServer(t *testing.T, src app.RemediationMetricsReader) *httptest.Server {
	t.Helper()
	repo := &memRepo{}
	h := commhttp.NewHandler(app.NewPublicationService(repo, nil, nil, nil, nil), app.NewReadService(repo, nil, nil))
	if src != nil {
		h = h.WithRemediationReports(app.NewRemediationReports(src, serializer.RemediationRenderer{}))
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, string, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b)
}

func TestGetRemediationMetricsReport(t *testing.T) {
	srv := reportServer(t, reportSource{rep: app.RemediationReport{Estate: app.RemediationMetrics{Open: 7}}})
	code, ct, body := get(t, srv.URL+"/reports/remediation-metrics?product=Gateway")
	if code != 200 || !strings.HasPrefix(ct, "text/markdown") || !strings.Contains(body, "Open findings: 7") {
		t.Fatalf("markdown = %d %s %s", code, ct, body)
	}
	if code, ct, body := get(t, srv.URL+"/reports/remediation-metrics?format=json"); code != 200 || ct != "application/json" || !strings.Contains(body, `"open": 7`) {
		t.Fatalf("json = %d %s %s", code, ct, body)
	}
	if code, _, _ := get(t, srv.URL+"/reports/remediation-metrics?format=pdf"); code != http.StatusBadRequest {
		t.Fatalf("pdf = %d", code)
	}
	if code, _, _ := get(t, reportServer(t, reportSource{err: errors.New("down")}).URL+"/reports/remediation-metrics"); code != http.StatusBadGateway {
		t.Fatalf("down = %d", code)
	}
	if code, _, _ := get(t, reportServer(t, nil).URL+"/reports/remediation-metrics"); code != http.StatusServiceUnavailable {
		t.Fatalf("unwired = %d", code)
	}
}

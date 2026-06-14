package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/metrics"
)

func TestRegisterIsIdempotent(t *testing.T) {
	metrics.Register()
	metrics.Register()
}

func TestHandlerExposesMetrics(t *testing.T) {
	metrics.RecordIngestionJob("ingest_sbom", "success", 25*time.Millisecond)
	metrics.SetQueueDepth(3)
	metrics.RecordNotification("email", "success")
	metrics.RecordCVEWatchCycle("success", 100*time.Millisecond)
	metrics.RecordCVEWatchNewFindings("npm", 2)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"themis_ingestion_jobs_total",
		"themis_job_duration_seconds",
		"themis_queue_depth",
		"themis_active_workers",
		"themis_notifications_total",
		"themis_cve_watch_cycles_total",
		"themis_cve_watch_duration_seconds",
		"themis_cve_watch_new_findings_total",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics body missing %q", want)
		}
	}
}

func TestIngestionJobLabels(t *testing.T) {
	metrics.RecordIngestionJob("ingest_vex", "failure", time.Second)

	var metric dto.Metric
	if err := collectCounter(metrics.IngestionJobsTotal, &metric); err != nil {
		t.Fatalf("collect counter: %v", err)
	}
	if metric.GetCounter().GetValue() < 1 {
		t.Fatal("expected ingestion job counter increment")
	}
	labels := labelMap(&metric)
	if labels["job_type"] != "ingest_vex" || labels["status"] != "failure" {
		t.Fatalf("unexpected labels: %#v", labels)
	}
}

func TestNotificationLabels(t *testing.T) {
	metrics.RecordNotification("teams", "retried")

	var metric dto.Metric
	if err := collectCounter(metrics.NotificationsTotal, &metric); err != nil {
		t.Fatalf("collect counter: %v", err)
	}
	labels := labelMap(&metric)
	if labels["channel_type"] != "teams" || labels["status"] != "retried" {
		t.Fatalf("unexpected labels: %#v", labels)
	}
}

func TestCVEWatchNewFindingsSkipsZero(t *testing.T) {
	before := counterValue(t, metrics.CVEWatchNewFindingsTotal, "pypi")
	metrics.RecordCVEWatchNewFindings("pypi", 0)
	after := counterValue(t, metrics.CVEWatchNewFindingsTotal, "pypi")
	if before != after {
		t.Fatalf("zero count should not increment counter")
	}
}

type stubNotifier struct {
	err error
}

func (s stubNotifier) NotifyComplete(context.Context, domain.IngestionResult) error {
	return s.err
}

func TestInstrumentedNotifierRecordsSuccessAndFailure(t *testing.T) {
	success := metrics.InstrumentedNotifier{
		Inner:      stubNotifier{},
		ChannelTyp: "ingestion",
	}
	if err := success.NotifyComplete(context.Background(), domain.IngestionResult{}); err != nil {
		t.Fatalf("NotifyComplete() error = %v", err)
	}

	failure := metrics.InstrumentedNotifier{Inner: stubNotifier{err: context.Canceled}}
	if err := failure.NotifyComplete(context.Background(), domain.IngestionResult{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestInstrumentJobHandler(t *testing.T) {
	handler := metrics.InstrumentJobHandler(func(ctx context.Context, job domain.Job) error {
		if job.Type == domain.JobTypeIngestVEX {
			return context.Canceled
		}
		return nil
	})

	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatalf("success path: %v", err)
	}
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeIngestVEX}); err == nil {
		t.Fatal("expected failure path error")
	}
}

func TestStageSpanNamesMatchPipelineStages(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(sdktrace.NewTracerProvider()) })

	ctx := metrics.InjectStageSpan(context.Background())
	stages := []string{
		domain.StageWebhookReceipt,
		domain.StageTrustGate,
		domain.StageParse,
		domain.StageCorrelate,
		domain.StageEnrich,
		domain.StageNotify,
	}
	for _, stage := range stages {
		_, end := domain.StartStage(ctx, stage)
		end()
	}

	spans := sr.Ended()
	if len(spans) != len(stages) {
		t.Fatalf("ended spans = %d, want %d", len(spans), len(stages))
	}
	for i, stage := range stages {
		if spans[i].Name() != stage {
			t.Fatalf("span[%d] name = %q, want %q", i, spans[i].Name(), stage)
		}
	}
}

func TestStageSpanMiddleware(t *testing.T) {
	called := false
	handler := metrics.StageSpanMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, end := domain.StartStage(r.Context(), domain.StageWebhookReceipt)
		defer end()
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/scan", nil)
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("expected handler invocation")
	}
}

func TestRecordCVEWatchNewFindingsIncrements(t *testing.T) {
	before := counterValue(t, metrics.CVEWatchNewFindingsTotal, "maven")
	metrics.RecordCVEWatchNewFindings("maven", 3)
	after := counterValue(t, metrics.CVEWatchNewFindingsTotal, "maven")
	if after-before != 3 {
		t.Fatalf("counter delta = %v, want 3", after-before)
	}
}

func TestPhase2aMetricsRegistered(t *testing.T) {
	metrics.RegisterPhase2a()
	metrics.EPSSKevMetrics{}.RecordSync("epss", "success")
	metrics.EPSSKevMetrics{}.SetStale(true)
	metrics.EPSSKevMetrics{}.RecordReEnrichBatches(2)
	metrics.VEXFeedMetrics{}.RecordSync("rhel", "success")
	metrics.VEXFeedMetrics{}.RecordAssertions("alpine", "exact", 3)
	metrics.VEXFeedMetrics{}.RecordPURLMismatch("alpine")
	metrics.EnrichmentMetrics{}.RecordLayer1Rule("Critical")
	metrics.EnrichmentMetrics{}.RecordBlastRadiusScore(1.5)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"themis_epsskev_sync_total",
		"themis_epsskev_stale",
		"themis_reenrichjob_batches_total",
		"themis_vexfeed_sync_total",
		"themis_vexfeed_assertions_total",
		"themis_vexfeed_purl_mismatch_total",
		"themis_layer1_rules_fired_total",
		"themis_blast_radius_score",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics body missing %q", want)
		}
	}
}

func TestDomainStartStageNoOpWithoutInjection(t *testing.T) {
	ctx, end := domain.StartStage(context.Background(), domain.StageParse)
	end()
	if ctx == nil {
		t.Fatal("expected context")
	}
}

func collectCounter(cv *prometheus.CounterVec, dest *dto.Metric) error {
	switch cv {
	case metrics.IngestionJobsTotal:
		return cv.WithLabelValues("ingest_vex", "failure").(prometheus.Metric).Write(dest)
	case metrics.NotificationsTotal:
		return cv.WithLabelValues("teams", "retried").(prometheus.Metric).Write(dest)
	default:
		return cv.WithLabelValues().(prometheus.Metric).Write(dest)
	}
}

func counterValue(t *testing.T, cv *prometheus.CounterVec, ecosystem string) float64 {
	t.Helper()
	var metric dto.Metric
	if err := cv.WithLabelValues(ecosystem).(prometheus.Metric).Write(&metric); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func labelMap(metric *dto.Metric) map[string]string {
	out := make(map[string]string)
	for _, pair := range metric.GetLabel() {
		out[pair.GetName()] = pair.GetValue()
	}
	return out
}

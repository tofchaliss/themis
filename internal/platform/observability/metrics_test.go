package observability_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/platform/observability"
)

// scrape renders the registry the way Prometheus would read it.
func scrape(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// The distinction the NVD-WATCH-1 defect turned on: a poll that read part of its window and
// reported success. `truncated` must be its own series, or "healthy" can once again mean
// "saw 5% of the window".
func TestMetrics_FeedPollOutcomesAreDistinctSeries(t *testing.T) {
	m := observability.NewMetrics("knowledge")
	m.RecordFeedPoll("nvd", observability.FeedPollComplete)
	m.RecordFeedPoll("nvd", observability.FeedPollTruncated)
	m.RecordFeedPoll("nvd", observability.FeedPollTruncated)
	m.RecordFeedPoll("osv", observability.FeedPollFailed)

	body := scrape(t, m)
	for _, want := range []string{
		`themis_feed_polls_total{outcome="complete",service="knowledge",source="nvd"} 1`,
		`themis_feed_polls_total{outcome="truncated",service="knowledge",source="nvd"} 2`,
		`themis_feed_polls_total{outcome="failed",service="knowledge",source="osv"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}

// `folded: 0` is ambiguous alone — either the feed returned nothing, or it returned plenty and
// none of it was about us. Those need opposite responses, so they are two series.
func TestMetrics_DiscoveredAndFoldedAreCountedSeparately(t *testing.T) {
	m := observability.NewMetrics("knowledge")
	m.RecordFeedRecords("nvd", observability.FeedRecordsDiscovered, 356223)
	m.RecordFeedRecords("nvd", observability.FeedRecordsFolded, 0) // no-op: nothing folded
	m.RecordFeedRecords("nvd", observability.FeedRecordsFolded, 3)

	body := scrape(t, m)
	if !strings.Contains(body, `themis_feed_records_total{service="knowledge",source="nvd",stage="discovered"} 356223`) {
		t.Error("discovered count missing")
	}
	if !strings.Contains(body, `themis_feed_records_total{service="knowledge",source="nvd",stage="folded"} 3`) {
		t.Error("folded count missing")
	}
}

func TestMetrics_AIInvocationsCountedByReason(t *testing.T) {
	m := observability.NewMetrics("intelligence")
	m.RecordAIInvocation("recommend_position", "ok", true)
	m.RecordAIInvocation("recommend_position", "business_invalid", false)

	body := scrape(t, m)
	for _, want := range []string{
		`themis_ai_invocations_total{capability="recommend_position",produced="true",reason="ok",service="intelligence"} 1`,
		`themis_ai_invocations_total{capability="recommend_position",produced="false",reason="business_invalid",service="intelligence"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}

// Status is bucketed by class, never by exact code: an unbounded label is the classic way to
// take down a metrics backend, and alerts are written against classes anyway.
func TestMetrics_HTTPStatusIsBucketedByClass(t *testing.T) {
	m := observability.NewMetrics("governance")
	for _, code := range []int{200, 204, 404, 500, 503, 302, 100} {
		m.RecordHTTPRequest(http.MethodGet, "/findings/{id}", code, 10*time.Millisecond)
	}
	body := scrape(t, m)
	for _, want := range []string{`status="2xx"} 2`, `status="4xx"} 1`, `status="5xx"} 2`, `status="3xx"} 1`, `status="other"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
	if !strings.Contains(body, `themis_http_request_duration_seconds_count{method="GET",route="/findings/{id}",service="governance"} 7`) {
		t.Error("latency histogram missing or not keyed by route template")
	}
}

// Every recorder is nil-safe, so a unit test that never called Setup records nothing rather
// than panicking. Instrumentation must never be able to break the code it observes.
func TestMetrics_NilReceiverIsSafe(t *testing.T) {
	var m *observability.Metrics
	m.RecordFeedPoll("nvd", observability.FeedPollComplete)
	m.RecordFeedRecords("nvd", observability.FeedRecordsFolded, 1)
	m.RecordAIInvocation("c", "ok", true)
	m.RecordHTTPRequest(http.MethodGet, "/x", 200, time.Second)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("nil handler status = %d, want 404", rec.Code)
	}
}

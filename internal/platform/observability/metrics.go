package observability

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the greenfield's operational metric surface (R1 · BCK-0051), the second of the
// three OTel signals after logs.
//
// Why counters and not more logging. Every gap this file exists to close was a QUESTION ABOUT
// A RATE OR A TOTAL that logs answer badly: "is this feed actually enriching anything?",
// "how often does the AI get refused, and for which check?", "how long has this been true?".
// A log line answers "what happened once"; you cannot alert on the absence of one, and
// grepping a week of them to count is not observability. Three separate defects found on
// 2026-08-06 were all invisible for exactly this reason — the code was behaving correctly and
// reporting nothing countable.
//
// It is a plain Prometheus registry rather than an OTel MeterProvider because
// `prometheus/client_golang` is already a chosen dependency (STACK.md) while the OTLP
// metric/trace exporters are not, and adding modules is a decision this does not need to take.
// The metric names are exporter-agnostic, so moving to an OTel pipeline later is a wiring
// change, not a rename.
type Metrics struct {
	reg *prometheus.Registry

	feedPolls     *prometheus.CounterVec
	feedRecords   *prometheus.CounterVec
	aiInvocations *prometheus.CounterVec
	aiDeclines    *prometheus.CounterVec
	httpRequests  *prometheus.CounterVec
	httpDuration  *prometheus.HistogramVec
}

// NewMetrics builds a service-scoped registry with the standard collectors registered.
func NewMetrics(service string) *Metrics {
	reg := prometheus.NewRegistry()
	labels := prometheus.Labels{"service": service}
	factory := prometheus.WrapRegistererWith(labels, reg)

	m := &Metrics{
		reg: reg,
		// outcome is the DIMENSION that was missing: a poll that succeeds and folds nothing is
		// not the same as one that was truncated or failed, and only a labelled counter lets an
		// operator alert on "nvd has not had a complete poll in 24h".
		feedPolls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "themis_feed_polls_total",
			Help: "Feed polls by source and outcome (complete, truncated, failed).",
		}, []string{"source", "outcome"}),
		// discovered vs folded, separately. `folded: 0` is ambiguous on its own — it means
		// either "the feed returned nothing" or "it returned plenty, none of it about us" —
		// and those need opposite responses. Two counters disambiguate what one cannot.
		feedRecords: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "themis_feed_records_total",
			Help: "Feed records by source and stage (discovered = returned by the feed, relevant = survived the relevance bound, folded = applied).",
		}, []string{"source", "stage"}),
		aiInvocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "themis_ai_invocations_total",
			Help: "Intelligence capability invocations by capability, outcome reason, and whether a proposal was produced.",
		}, []string{"capability", "reason", "produced"}),
		// The G-AI-2c eval signal: honest declines split by WHAT could not tell — the model
		// (`model_undetermined`, a model/prompt question) or the grounding
		// (`thin_grounding`, a projection/correlation gap) — and by the tier that gave up.
		aiDeclines: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "themis_ai_declines_total",
			Help: "Honest insufficient outcomes by capability, decline class (thin_grounding | model_undetermined), and model tier.",
		}, []string{"capability", "class", "tier"}),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "themis_http_requests_total",
			Help: "HTTP requests by method, route and status class.",
		}, []string{"method", "route", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "themis_http_request_duration_seconds",
			Help:    "HTTP request latency by method and route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
	}
	factory.MustRegister(m.feedPolls, m.feedRecords, m.aiInvocations, m.aiDeclines, m.httpRequests, m.httpDuration)
	return m
}

// Feed poll outcomes. `truncated` is deliberately distinct from `complete`: a feed that read
// part of its window and reported success is the NVD-WATCH-1 defect, and "healthy" must never
// again be able to mean "saw 5% of the window".
const (
	FeedPollComplete  = "complete"
	FeedPollTruncated = "truncated"
	FeedPollFailed    = "failed"
)

// Feed record stages. `discovered` is what the feed returned, `relevant` what survived the D5
// relevance bound (a CVE the enterprise already has carded), `folded` what was actually applied.
// Three stages rather than two because the two drops have different meanings: discovered→relevant
// is the relevance bound working as designed, relevant→folded is a fold that did nothing.
const (
	FeedRecordsDiscovered = "discovered"
	FeedRecordsRelevant   = "relevant"
	FeedRecordsFolded     = "folded"
)

// RecordFeedPoll counts one poll of a feed with its outcome.
func (m *Metrics) RecordFeedPoll(source, outcome string) {
	if m == nil {
		return
	}
	m.feedPolls.WithLabelValues(source, outcome).Inc()
}

// RecordFeedRecords counts records seen at a stage of one poll.
//
// A count of ZERO is recorded, not skipped. Adding 0 to a counter changes no value but does
// CREATE the series, and that is the whole point here: "this feed discovered nothing" and "this
// feed has never been polled" are different operational states, and an absent time series
// cannot express the first. Skipping zeroes would reintroduce, one level down, exactly the
// ambiguity these counters were added to remove. Only a negative — impossible from a length —
// is refused.
func (m *Metrics) RecordFeedRecords(source, stage string, n int) {
	if m == nil || n < 0 {
		return
	}
	m.feedRecords.WithLabelValues(source, stage).Add(float64(n))
}

// RecordAIInvocation counts one Intelligence invocation by its terminal reason. `produced`
// separates "declined safely" from "produced a proposal" without needing a second metric.
func (m *Metrics) RecordAIInvocation(capability, reason string, produced bool) {
	if m == nil {
		return
	}
	m.aiInvocations.WithLabelValues(capability, reason, strconv.FormatBool(produced)).Inc()
}

// RecordAIDecline counts one honest insufficient by its G-AI-2c class and the tier that gave
// up — the rate a tuning loop watches per capability/model.
func (m *Metrics) RecordAIDecline(capability, class, tier string) {
	if m == nil {
		return
	}
	if tier == "" {
		tier = "none"
	}
	m.aiDeclines.WithLabelValues(capability, class, tier).Inc()
}

// RecordHTTPRequest counts one request and observes its latency.
func (m *Metrics) RecordHTTPRequest(method, route string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.httpRequests.WithLabelValues(method, route, statusClass(status)).Inc()
	m.httpDuration.WithLabelValues(method, route).Observe(d.Seconds())
}

// statusClass buckets a status code as 2xx/3xx/4xx/5xx. The exact code is already in the log
// line; a metric label with unbounded cardinality is a liability, and alerts are written
// against classes.
func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "other"
	}
}

// Handler serves the registry in the Prometheus text format. Mounted OUTSIDE the authenticated
// /api/v1 group: it is operational data for the platform's own scraper, carries no business
// content, and requiring an API key would mean handing scrape credentials to monitoring.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// metricsOnce guards the process-wide default so repeated Setup calls in tests do not panic on
// duplicate registration.
var metricsOnce sync.Once

// defaultMetrics is the process-wide instance, set by Setup so a node's workers can record
// without threading the handle through every constructor. Nil until Setup runs, and every
// method is nil-safe, so an uninstrumented unit test records nothing rather than panicking.
var defaultMetrics *Metrics

// Default returns the process-wide Metrics, or nil before Setup.
func Default() *Metrics { return defaultMetrics }

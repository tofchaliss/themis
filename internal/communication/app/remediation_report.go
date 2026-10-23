package app

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The remediation-metrics report (EDR-REMEDIATION-01 D6): Governance computes the figures,
// Communication renders them for people (markdown) and tools (JSON). Rendered on request and
// stored nowhere; a scheduled delivery is a later step through the webhook channel.

// MeanDays is an average in days over Count Findings.
type MeanDays struct {
	MeanDays float64 `json:"mean_days"`
	Count    int     `json:"count"`
}

// RemediationMetrics mirrors one scope of Governance's report.
type RemediationMetrics struct {
	Scope             string                    `json:"scope"`
	Open              int                       `json:"open"`
	OpenByAge         map[string]map[string]int `json:"open_by_age"`
	SLAApplicable     int                       `json:"sla_applicable"`
	WithinSLA         int                       `json:"within_sla"`
	BreachedNow       int                       `json:"breached_now"`
	WithinSLAShare    float64                   `json:"within_sla_share"`
	TimeToDecision    MeanDays                  `json:"time_to_decision"`
	TimeToRemediation MeanDays                  `json:"time_to_remediation"`
	TimeToResolution  MeanDays                  `json:"time_to_resolution"`
}

// RemediationReport mirrors Governance's GET /metrics/remediation.
type RemediationReport struct {
	GeneratedAt         time.Time            `json:"generated_at"`
	Estate              RemediationMetrics   `json:"estate"`
	Products            []RemediationMetrics `json:"products"`
	ProductsUnavailable bool                 `json:"products_unavailable"`
	Unattributed        int                  `json:"unattributed"`
}

// RemediationMetricsReader reads the figures from Governance.
type RemediationMetricsReader interface {
	RemediationMetrics(ctx context.Context, product, tag string) (RemediationReport, error)
}

// RemediationRenderer renders a report in one format.
type RemediationRenderer interface {
	RenderRemediation(rep RemediationReport, format string) ([]byte, string, error)
}

// ErrUnknownReportFormat is returned for a format the renderer does not produce.
var ErrUnknownReportFormat = errors.New("communication: unknown report format (json | markdown)")

// RemediationReports renders the report on request.
type RemediationReports struct {
	reader   RemediationMetricsReader
	renderer RemediationRenderer
}

// NewRemediationReports wires the report.
func NewRemediationReports(reader RemediationMetricsReader, renderer RemediationRenderer) *RemediationReports {
	return &RemediationReports{reader: reader, renderer: renderer}
}

// Render reads the figures and renders them; it returns the bytes and their content type.
func (r *RemediationReports) Render(ctx context.Context, product, tag, format string) ([]byte, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "json" {
		return nil, "", ErrUnknownReportFormat
	}
	rep, err := r.reader.RemediationMetrics(ctx, product, tag)
	if err != nil {
		return nil, "", err
	}
	return r.renderer.RenderRemediation(rep, format)
}

// Snapshot keys of the scheduled metrics webhook.
const (
	SnapshotMetricsOpen       = "metrics_open"
	SnapshotMetricsWithin     = "metrics_within_sla"
	SnapshotMetricsApplicable = "metrics_sla_applicable"
	SnapshotMetricsBreached   = "metrics_breached_now"
	SnapshotMetricsDecision   = "metrics_days_to_decision"
	SnapshotMetricsWorst      = "metrics_most_breached" // "Gateway=4,Portal=1", worst first, at most 5
)

// MetricsSchedule posts the remediation-metrics summary through the webhook channel on a
// cadence (EDR-REMEDIATION-01 D6 "later on a schedule through D4"). It runs only while the
// remediation_metrics route is configured, and sends one summary per pass; the full report stays
// one click away at /reports/remediation-metrics.
type MetricsSchedule struct {
	reader  RemediationMetricsReader
	intents *DeliveryIntentService
	ids     IDGenerator
}

// NewMetricsSchedule wires the schedule.
func NewMetricsSchedule(reader RemediationMetricsReader, intents *DeliveryIntentService, ids IDGenerator) *MetricsSchedule {
	return &MetricsSchedule{reader: reader, intents: intents, ids: ids}
}

// Run sends one summary when the route is configured; it reports whether it sent.
func (m *MetricsSchedule) Run(ctx context.Context) (bool, error) {
	if _, ok := m.intents.WebhookAudience(WebhookRemediationMetrics); !ok {
		return false, nil
	}
	rep, err := m.reader.RemediationMetrics(ctx, "", "")
	if err != nil {
		return false, err
	}
	products := append([]RemediationMetrics(nil), rep.Products...)
	sort.SliceStable(products, func(i, j int) bool { return products[i].BreachedNow > products[j].BreachedNow })
	var worst []string
	for _, p := range products {
		if p.BreachedNow == 0 || len(worst) == 5 {
			break
		}
		worst = append(worst, p.Scope+"="+strconv.Itoa(p.BreachedNow))
	}
	e := rep.Estate
	snap := map[string]string{
		SnapshotMetricsOpen:       strconv.Itoa(e.Open),
		SnapshotMetricsWithin:     strconv.Itoa(e.WithinSLA),
		SnapshotMetricsApplicable: strconv.Itoa(e.SLAApplicable),
		SnapshotMetricsBreached:   strconv.Itoa(e.BreachedNow),
		SnapshotMetricsWorst:      strings.Join(worst, ","),
	}
	if e.TimeToDecision.Count > 0 {
		snap[SnapshotMetricsDecision] = strconv.FormatFloat(e.TimeToDecision.MeanDays, 'f', 1, 64)
	}
	id := "metrics:" + m.ids.NewID()
	_, sent, err := m.intents.EnqueueWebhook(ctx, IntentLineage{EventType: "communication.remediation_metrics", EventID: id},
		id, WebhookRemediationMetrics, "", "estate", "", "", snap)
	return sent, err
}

// RunEvery runs the schedule until ctx is cancelled.
func (m *MetricsSchedule) RunEvery(ctx context.Context, every time.Duration, report func(sent bool, err error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sent, err := m.Run(ctx)
			if report != nil {
				report(sent, err)
			}
		}
	}
}

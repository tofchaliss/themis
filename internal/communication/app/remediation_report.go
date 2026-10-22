package app

import (
	"context"
	"errors"
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

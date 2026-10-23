package app

import (
	"context"
	"strings"

	"github.com/themis-project/themis/internal/governance/domain"
)

// Remediation metrics (EDR-REMEDIATION-01 D6): one read over every Finding, grouped by Product
// through the Registry estate, the arithmetic in domain.ComputeRemediationMetrics.

// MetricsRow is one Finding as the metrics read needs it.
type MetricsRow struct {
	FindingID domain.FindingID
	ReleaseID string
	Finding   domain.MetricsFinding
}

// MetricsReader reads every Finding's metric facts in one query.
type MetricsReader interface {
	MetricsFindings(ctx context.Context) ([]MetricsRow, error)
}

// ProductRef names a Product.
type ProductRef struct {
	ID   string
	Name string
}

// EstateReader maps every Release in the estate to its Product (the Registry traversal).
type EstateReader interface {
	ReleaseProducts(ctx context.Context) (map[string]ProductRef, error)
}

// RemediationReport is the estate-wide figures and one set per Product.
type RemediationReport struct {
	Estate   domain.RemediationMetrics
	Products []domain.RemediationMetrics
	// ProductsUnavailable: the Registry could not be read, so only the estate figures are given.
	ProductsUnavailable bool
	// Unattributed counts Findings whose Release the estate does not list.
	Unattributed int
}

// MetricsService computes the report.
type MetricsService struct {
	reader MetricsReader
	estate EstateReader // may be nil: estate-wide figures only
	sla    *SLAService  // may be nil: no SLA share
	clock  Clock
}

// NewMetricsService wires the metrics read.
func NewMetricsService(reader MetricsReader, estate EstateReader, sla *SLAService, clock Clock) *MetricsService {
	return &MetricsService{reader: reader, estate: estate, sla: sla, clock: clock}
}

// Remediation computes the report. product, when set, keeps only the Product whose id or name
// matches (case-insensitive); the estate figures always cover everything.
func (m *MetricsService) Remediation(ctx context.Context, product string) (RemediationReport, error) {
	rows, err := m.reader.MetricsFindings(ctx)
	if err != nil {
		return RemediationReport{}, err
	}
	if m.sla != nil {
		states, err := m.sla.States(ctx)
		if err != nil {
			return RemediationReport{}, err
		}
		for i := range rows {
			if st, ok := states[rows[i].FindingID]; ok {
				rows[i].Finding.SLA = st
			}
		}
	}
	now := m.clock.Now()
	all := make([]domain.MetricsFinding, len(rows))
	for i, r := range rows {
		all[i] = r.Finding
	}
	out := RemediationReport{Estate: domain.ComputeRemediationMetrics("", all, now)}
	if m.estate == nil {
		out.ProductsUnavailable = true
		return out, nil
	}
	byRelease, err := m.estate.ReleaseProducts(ctx)
	if err != nil {
		out.ProductsUnavailable = true
		return out, nil
	}
	groups := map[string][]domain.MetricsFinding{}
	for _, r := range rows {
		p, ok := byRelease[r.ReleaseID]
		if !ok {
			out.Unattributed++
			continue
		}
		if product != "" && !strings.EqualFold(product, p.ID) && !strings.EqualFold(product, p.Name) {
			continue
		}
		name := p.Name
		if name == "" {
			name = p.ID
		}
		groups[name] = append(groups[name], r.Finding)
	}
	for name, fs := range groups {
		out.Products = append(out.Products, domain.ComputeRemediationMetrics(name, fs, now))
	}
	domain.SortMetrics(out.Products)
	return out, nil
}

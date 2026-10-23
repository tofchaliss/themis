package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

func TestComputeRemediationMetrics(t *testing.T) {
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	ago := func(d int) time.Time { return now.Add(-time.Duration(d) * 24 * time.Hour) }
	fs := []domain.MetricsFinding{
		// Open, 3 days old, decided after 1 day, within SLA.
		{CreatedAt: ago(3), Open: true, Bucket: "critical", FirstHumanAt: ago(2), SLA: domain.SLAWithin},
		// Open, 20 days, breached.
		{CreatedAt: ago(20), Open: true, Bucket: "high", SLA: domain.SLABreached},
		// Open, 60 days, paused (counts as within), unknown bucket.
		{CreatedAt: ago(60), Open: true, SLA: domain.SLAPaused},
		// Open, 200 days, SLA not applicable.
		{CreatedAt: ago(200), Open: true, Bucket: "low", SLA: domain.SLANotApplicable},
		// Absent after 10 days, decided by a person afterwards: remediated in 10 days; resolved in 12.
		{CreatedAt: ago(40), Open: false, AbsentSince: ago(30), HumanAfterAbsentAt: ago(29), FirstHumanAt: ago(29), ResolvedAt: ago(28)},
		// Absent, nobody decided since: NOT remediated (Q4).
		{CreatedAt: ago(40), Open: true, Bucket: "medium", AbsentSince: ago(5), SLA: domain.SLADueSoon},
		// A decision before creation (bad data) is ignored.
		{CreatedAt: ago(1), Open: false, FirstHumanAt: ago(2)},
	}
	m := domain.ComputeRemediationMetrics("Gateway", fs, now)
	if m.Scope != "Gateway" || m.Open != 5 {
		t.Fatalf("open = %+v", m)
	}
	if m.OpenByAge["0-7"]["critical"] != 1 || m.OpenByAge["8-30"]["high"] != 1 || m.OpenByAge["31-90"]["unknown"] != 1 ||
		m.OpenByAge["31-90"]["medium"] != 1 || m.OpenByAge["over-90"]["low"] != 1 {
		t.Fatalf("bands = %v", m.OpenByAge)
	}
	if m.SLAApplicable != 4 || m.WithinSLA != 3 || m.BreachedNow != 1 || m.WithinShare != 0.75 {
		t.Fatalf("sla = %+v", m)
	}
	if m.TimeToDecision.N != 2 || m.TimeToDecision.Days != 6 {
		t.Fatalf("decision = %+v", m.TimeToDecision)
	}
	if m.TimeToRemediation.N != 1 || m.TimeToRemediation.Days != 10 {
		t.Fatalf("remediation = %+v", m.TimeToRemediation)
	}
	if m.TimeToResolution.N != 1 || m.TimeToResolution.Days != 12 {
		t.Fatalf("resolution = %+v", m.TimeToResolution)
	}
	empty := domain.ComputeRemediationMetrics("", nil, now)
	if empty.Open != 0 || empty.WithinShare != 0 || empty.TimeToDecision.N != 0 || len(empty.OpenByAge) != 4 {
		t.Fatalf("empty = %+v", empty)
	}
	ms := []domain.RemediationMetrics{{Scope: "b"}, {Scope: ""}, {Scope: "a"}}
	domain.SortMetrics(ms)
	if ms[0].Scope != "" || ms[1].Scope != "a" {
		t.Fatalf("sort = %+v", ms)
	}
}

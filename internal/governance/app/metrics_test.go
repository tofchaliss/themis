package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type metricsRows struct {
	rows []app.MetricsRow
	err  error
}

func (m metricsRows) MetricsFindings(context.Context) ([]app.MetricsRow, error) {
	out := append([]app.MetricsRow(nil), m.rows...)
	return out, m.err
}

type estateMap struct {
	m   map[string]app.ProductRef
	err error
}

func (e estateMap) ReleaseProducts(context.Context) (map[string]app.ProductRef, error) { return e.m, e.err }

func mrow(id, rel string, open bool) app.MetricsRow {
	now := fixedClock{}.Now()
	return app.MetricsRow{FindingID: domain.FindingID(id), ReleaseID: rel,
		Finding: domain.MetricsFinding{CreatedAt: now.Add(-10 * 24 * time.Hour), Open: open, Bucket: "high"}}
}

func TestMetricsService_Remediation(t *testing.T) {
	ctx := context.Background()
	rows := metricsRows{rows: []app.MetricsRow{mrow("a", "rel-1", true), mrow("b", "rel-2", true), mrow("c", "rel-3", false), mrow("d", "rel-x", true)}}
	estate := estateMap{m: map[string]app.ProductRef{"rel-1": {ID: "p1", Name: "Gateway"}, "rel-2": {ID: "p1", Name: "Gateway"}, "rel-3": {ID: "p2"}}}
	// SLA: finding a breached (critical created 10 days ago), b within.
	slaStore := &fakeSLAStore{running: []app.SLAFacts{slaFacts("a", domain.SLABucketCritical, 10), slaFacts("b", domain.SLABucketHigh, 10)}}
	svc := app.NewMetricsService(rows, estate, app.NewSLAService(slaStore, nil, fixedClock{}), fixedClock{})
	rep, err := svc.Remediation(ctx, "", "")
	if err != nil || rep.Estate.Open != 3 || rep.Unattributed != 1 || len(rep.Products) != 2 || rep.ProductsUnavailable {
		t.Fatalf("report = %+v %v", rep, err)
	}
	if rep.Products[0].Scope != "Gateway" || rep.Products[0].Open != 2 || rep.Products[0].BreachedNow != 1 || rep.Products[0].WithinSLA != 1 {
		t.Fatalf("gateway = %+v", rep.Products[0])
	}
	if rep.Products[1].Scope != "p2" || rep.Products[1].Open != 0 {
		t.Fatalf("unnamed product = %+v", rep.Products[1])
	}
	if f, _ := svc.Remediation(ctx, "gateway", ""); len(f.Products) != 1 || f.Products[0].Scope != "Gateway" {
		t.Fatalf("filter by name = %+v", f.Products)
	}
	if f, _ := svc.Remediation(ctx, "P2", ""); len(f.Products) != 1 {
		t.Fatalf("filter by id = %+v", f.Products)
	}
	// No estate seam, or Registry down: estate figures only, flagged.
	for name, e := range map[string]app.EstateReader{"nil": nil, "down": estateMap{err: errors.New("down")}} {
		r, err := app.NewMetricsService(rows, e, nil, fixedClock{}).Remediation(ctx, "", "")
		if err != nil || !r.ProductsUnavailable || r.Estate.Open != 3 || r.Products != nil {
			t.Fatalf("%s = %+v %v", name, r, err)
		}
	}
	if _, err := app.NewMetricsService(metricsRows{err: errors.New("db")}, nil, nil, fixedClock{}).Remediation(ctx, "", ""); err == nil {
		t.Fatal("read error swallowed")
	}
	if _, err := app.NewMetricsService(rows, nil, app.NewSLAService(&fakeSLAStore{policyErr: errors.New("db")}, nil, fixedClock{}), fixedClock{}).Remediation(ctx, "", ""); err == nil {
		t.Fatal("sla error swallowed")
	}
}

func TestSLAService_StatesPagesAndFails(t *testing.T) {
	st := &fakeSLAStore{}
	for i := 0; i < app.SLASweepBatch+2; i++ {
		st.running = append(st.running, slaFacts(fmt.Sprintf("f%04d", i), domain.SLABucketHigh, 1))
	}
	states, err := app.NewSLAService(st, nil, fixedClock{}).States(context.Background())
	if err != nil || len(states) != app.SLASweepBatch+2 || states["f0000"] != domain.SLAWithin {
		t.Fatalf("states = %d %v", len(states), err)
	}
	if _, err := app.NewSLAService(&fakeSLAStore{runningErr: errors.New("db")}, nil, fixedClock{}).States(context.Background()); err == nil {
		t.Fatal("list error swallowed")
	}
	if _, err := app.NewSLAService(&fakeSLAStore{policyErr: errors.New("db")}, nil, fixedClock{}).States(context.Background()); err == nil {
		t.Fatal("policy error swallowed")
	}
}

// D7: a tag keeps only Findings on releases carrying it — estate figures included — and refuses
// when the estate (where tags live) cannot be read.
func TestMetricsService_TagFilter(t *testing.T) {
	ctx := context.Background()
	rows := metricsRows{rows: []app.MetricsRow{mrow("a", "rel-1", true), mrow("b", "rel-2", true), mrow("c", "rel-x", true)}}
	estate := estateMap{m: map[string]app.ProductRef{
		"rel-1": {ID: "p1", Name: "Gateway", Tags: []string{"env:prod", "team:payments"}},
		"rel-2": {ID: "p1", Name: "Gateway", Tags: []string{"env:test"}},
	}}
	rep, err := app.NewMetricsService(rows, estate, nil, fixedClock{}).Remediation(ctx, "", " Team:Payments ")
	if err != nil || rep.Estate.Open != 1 || len(rep.Products) != 1 || rep.Products[0].Open != 1 {
		t.Fatalf("tagged = %+v %v", rep, err)
	}
	for name, e := range map[string]app.EstateReader{"nil": nil, "down": estateMap{err: errors.New("down")}} {
		if _, err := app.NewMetricsService(rows, e, nil, fixedClock{}).Remediation(ctx, "", "env:prod"); !errors.Is(err, app.ErrTagFilterUnavailable) {
			t.Fatalf("%s = %v", name, err)
		}
	}
}

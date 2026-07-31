package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type feedRecord struct {
	kind, source string
	tier         int
}

type feedHealthStoreFake struct {
	rows    []app.FeedHealthRow
	rowsErr error
	calls   []feedRecord
}

func (f *feedHealthStoreFake) RecordFeedSuccess(_ context.Context, source string, tier int, _ time.Time) error {
	f.calls = append(f.calls, feedRecord{"success", source, tier})
	return nil
}

func (f *feedHealthStoreFake) RecordFeedFailure(_ context.Context, source string, tier int, _ time.Time) error {
	f.calls = append(f.calls, feedRecord{"failure", source, tier})
	return nil
}

func (f *feedHealthStoreFake) FeedHealthRows(context.Context) ([]app.FeedHealthRow, error) {
	return f.rows, f.rowsErr
}

func TestFeedHealthReport(t *testing.T) {
	now := fixedClock{}.Now()
	recent := now.Add(-1 * time.Hour)     // within every tier threshold
	overdueT1 := now.Add(-30 * time.Hour) // past the 25h Tier-1 threshold

	rows := []app.FeedHealthRow{
		{Source: "nvd", Tier: int(domain.Tier1Critical), LastSuccessAt: &recent, ConsecutiveFailures: 0},    // healthy
		{Source: "kev", Tier: int(domain.Tier1Critical), LastSuccessAt: &overdueT1, ConsecutiveFailures: 0}, // Tier-1 overdue → stale
		{Source: "epss", Tier: int(domain.Tier1Critical), LastSuccessAt: nil, ConsecutiveFailures: 0},       // never succeeded → stale
		{Source: "osv", Tier: int(domain.Tier2Recommended), LastSuccessAt: &recent, ConsecutiveFailures: 4}, // Tier-2 failing → degraded
		{Source: "vex", Tier: int(domain.Tier3Enrichment), LastSuccessAt: &recent, ConsecutiveFailures: 2},  // Tier-3 failing → informational
	}
	svc := app.NewFeedHealthService(&feedHealthStoreFake{rows: rows}, fixedClock{})

	rep, err := svc.Report(context.Background())
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !rep.SignalsStale {
		t.Errorf("SignalsStale = false, want true (a Tier-1 feed is stale)")
	}
	if len(rep.DegradedFeeds) != 1 || rep.DegradedFeeds[0] != "osv" {
		t.Errorf("DegradedFeeds = %v, want [osv]", rep.DegradedFeeds)
	}
	want := map[string]string{
		"nvd":  string(domain.FeedHealthy),
		"kev":  string(domain.FeedStale),
		"epss": string(domain.FeedStale),
		"osv":  string(domain.FeedDegraded),
		"vex":  string(domain.FeedInformational),
	}
	if len(rep.Feeds) != len(want) {
		t.Fatalf("feeds = %d, want %d", len(rep.Feeds), len(want))
	}
	for _, f := range rep.Feeds {
		if got := want[f.Source]; got != f.Status {
			t.Errorf("%s status = %q, want %q", f.Source, f.Status, got)
		}
	}
}

func TestFeedHealthReportHealthyOnly(t *testing.T) {
	recent := fixedClock{}.Now().Add(-1 * time.Hour)
	svc := app.NewFeedHealthService(&feedHealthStoreFake{rows: []app.FeedHealthRow{
		{Source: "nvd", Tier: int(domain.Tier1Critical), LastSuccessAt: &recent},
	}}, fixedClock{})

	rep, err := svc.Report(context.Background())
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.SignalsStale {
		t.Errorf("SignalsStale = true, want false")
	}
	if rep.DegradedFeeds == nil {
		t.Errorf("DegradedFeeds is nil, want non-nil empty slice")
	}
	if len(rep.DegradedFeeds) != 0 {
		t.Errorf("DegradedFeeds = %v, want empty", rep.DegradedFeeds)
	}
}

func TestFeedHealthReportError(t *testing.T) {
	svc := app.NewFeedHealthService(&feedHealthStoreFake{rowsErr: errors.New("db down")}, fixedClock{})
	if _, err := svc.Report(context.Background()); err == nil {
		t.Fatalf("Report: want error, got nil")
	}
}

func TestFeedHealthRecordDelegates(t *testing.T) {
	store := &feedHealthStoreFake{}
	svc := app.NewFeedHealthService(store, fixedClock{})

	if err := svc.RecordSuccess(context.Background(), "nvd", domain.Tier1Critical); err != nil {
		t.Fatalf("RecordSuccess: %v", err)
	}
	if err := svc.RecordFailure(context.Background(), "osv", domain.Tier2Recommended); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	want := []feedRecord{{"success", "nvd", 1}, {"failure", "osv", 2}}
	if len(store.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", store.calls, want)
	}
	for i, c := range want {
		if store.calls[i] != c {
			t.Errorf("call %d = %v, want %v", i, store.calls[i], c)
		}
	}
}

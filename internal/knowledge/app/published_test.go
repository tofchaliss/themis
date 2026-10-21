package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakePublished struct {
	since time.Time
	rows  []app.PublishedCVE
	err   error
}

func (f *fakePublished) PublishedSince(_ context.Context, since time.Time) ([]app.PublishedCVE, error) {
	f.since = since
	return f.rows, f.err
}

// GUI-16 layer 2: the window defaults to 7 days and is clamped at 30; rows come back newest
// first with the carded flag set from the repository; nothing is written; a missing source or a
// failing source is an error, never an empty page.
func TestPublishedService_LatestPublished(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	if _, _, err := fold.FoldProposal(ctx, cve(t, "CVE-2026-2"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	now := fixedClock{}.Now()
	src := &fakePublished{rows: []app.PublishedCVE{
		{CVE: "CVE-2026-1", Published: now.Add(-48 * time.Hour)},
		{CVE: "CVE-2026-2", Published: now.Add(-2 * time.Hour)},
		{CVE: "CVE-2026-3", Published: now.Add(-2 * time.Hour)},
	}}
	svc := app.NewPublishedService(src, repo, fixedClock{})
	if !svc.Enabled() {
		t.Fatal("a wired source must report enabled")
	}
	rows, err := svc.LatestPublished(ctx, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !src.since.Equal(now.Add(-7 * 24 * time.Hour)) {
		t.Errorf("default window asked since %v, want 7 days back", src.since)
	}
	if len(rows) != 3 || rows[0].CVE != "CVE-2026-2" || rows[1].CVE != "CVE-2026-3" || rows[2].CVE != "CVE-2026-1" {
		t.Errorf("order = %+v, want newest first then by id", rows)
	}
	if !rows[0].Carded || rows[1].Carded || rows[2].Carded {
		t.Errorf("carded flags = %v %v %v, want only CVE-2026-2", rows[0].Carded, rows[1].Carded, rows[2].Carded)
	}
	if n := len(repo.cards); n != 1 {
		t.Errorf("the read created %d cards; it must persist nothing", n-1)
	}
	if _, err := svc.LatestPublished(ctx, 400); err != nil || !src.since.Equal(now.Add(-30*24*time.Hour)) {
		t.Errorf("clamp: since %v err %v", src.since, err)
	}
	src.err = errors.New("nvd down")
	if _, err := svc.LatestPublished(ctx, 7); err == nil {
		t.Error("a source failure must surface")
	}
	src.err = nil
	repo.getErr = errors.New("db down")
	if _, err := svc.LatestPublished(ctx, 7); err == nil {
		t.Error("a repository failure must surface")
	}
	var none *app.PublishedService
	if none.Enabled() {
		t.Error("nil service is not enabled")
	}
	if _, err := app.NewPublishedService(nil, repo, fixedClock{}).LatestPublished(ctx, 7); !errors.Is(err, app.ErrPublishedUnavailable) {
		t.Errorf("unwired: %v", err)
	}
}

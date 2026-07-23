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

type fakeChanged struct {
	props []app.ProposalFor
	err   error
}

func (f fakeChanged) ChangedSince(_ context.Context, _ time.Time) ([]app.ProposalFor, error) {
	return f.props, f.err
}

type fakeWatchState struct {
	last      time.Time
	getErr    error
	setErr    error
	setCalled bool
}

func (f *fakeWatchState) LastSuccess(_ context.Context) (time.Time, error) { return f.last, f.getErr }
func (f *fakeWatchState) SetLastSuccess(_ context.Context, t time.Time) error {
	f.setCalled = true
	f.last = t
	return f.setErr
}

func watchSvc(t *testing.T, changed app.ChangedVulnSource, state app.WatchState, repo app.Repository) *app.WatchService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"))
	return app.NewWatchService(changed, state, fold, fixedClock{})
}

func TestWatch_PollFoldsAndAdvances(t *testing.T) {
	ctx := context.Background()
	changed := fakeChanged{props: []app.ProposalFor{
		{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "nvd", value.SeverityHigh)},
		{CVE: cve(t, "CVE-2024-2"), Proposal: vulnFacts(t, "nvd", value.SeverityMedium)},
	}}
	state := &fakeWatchState{}
	repo := newRepo()

	n, err := watchSvc(t, changed, state, repo).Poll(ctx)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 2 {
		t.Errorf("folded = %d, want 2", n)
	}
	if !state.setCalled {
		t.Error("watermark should advance after a successful pass")
	}
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-1"); !found {
		t.Error("watch should have created the card")
	}
}

func TestWatch_Errors(t *testing.T) {
	ctx := context.Background()
	good := fakeChanged{props: []app.ProposalFor{{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "nvd", value.SeverityHigh)}}}

	// Watermark read error.
	if _, err := watchSvc(t, good, &fakeWatchState{getErr: errors.New("boom")}, newRepo()).Poll(ctx); err == nil {
		t.Error("watermark error: expected error")
	}
	// Discovery error.
	if _, err := watchSvc(t, fakeChanged{err: errors.New("boom")}, &fakeWatchState{}, newRepo()).Poll(ctx); err == nil {
		t.Error("changed error: expected error")
	}
	// Fold error.
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	if _, err := watchSvc(t, good, &fakeWatchState{}, badRepo).Poll(ctx); err == nil {
		t.Error("fold error: expected error")
	}
	// Watermark write error (after a successful fold).
	if _, err := watchSvc(t, good, &fakeWatchState{setErr: errors.New("boom")}, newRepo()).Poll(ctx); err == nil {
		t.Error("set-watermark error: expected error")
	}
}

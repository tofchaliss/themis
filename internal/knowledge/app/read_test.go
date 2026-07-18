package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeProjection struct {
	releases []string
	err      error
}

func (f fakeProjection) AffectedReleases(_ context.Context, _ string) ([]string, error) {
	return f.releases, f.err
}

type fakeReconciler struct {
	n   int
	err error
}

func (f fakeReconciler) ReconcileStuckStages(_ context.Context) (int, error) { return f.n, f.err }

func TestReadService(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"))
	id, err := fold.FoldProposal(ctx, cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}

	rs := app.NewReadService(repo, fakeProjection{releases: []string{"rel-1", "rel-2"}})

	if got, err := rs.GetByID(ctx, id); err != nil || got.ID() != id {
		t.Errorf("GetByID = %v err=%v", got.ID(), err)
	}
	if _, found, err := rs.GetByCVE(ctx, "CVE-2024-1"); err != nil || !found {
		t.Errorf("GetByCVE: found=%v err=%v", found, err)
	}
	rels, err := rs.AffectedReleases(ctx, string(id))
	if err != nil || len(rels) != 2 {
		t.Errorf("AffectedReleases = %v err=%v", rels, err)
	}
}

func TestReconcileService(t *testing.T) {
	if n, err := app.NewReconcileService(fakeReconciler{n: 3}).Reconcile(context.Background()); err != nil || n != 3 {
		t.Errorf("reconcile = %d err=%v, want 3", n, err)
	}
	if _, err := app.NewReconcileService(fakeReconciler{err: errors.New("boom")}).Reconcile(context.Background()); err == nil {
		t.Error("reconcile error: expected error")
	}
}

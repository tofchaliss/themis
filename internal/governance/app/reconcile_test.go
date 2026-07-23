package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
)

type fakeRelay struct {
	batches []int // per-call delivered counts; a trailing 0 drains
	i       int
	err     error
}

func (r *fakeRelay) DeliverPending(context.Context) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.i >= len(r.batches) {
		return 0, nil
	}
	n := r.batches[r.i]
	r.i++
	return n, nil
}

func TestReconcile_DrainsOutbox(t *testing.T) {
	relay := &fakeRelay{batches: []int{3, 2, 0}}
	total, err := app.NewReconcileService(relay).Reconcile(context.Background())
	if err != nil || total != 5 {
		t.Fatalf("reconcile total=%d err=%v, want 5", total, err)
	}
}

func TestReconcile_Error(t *testing.T) {
	relay := &fakeRelay{err: errors.New("bus down")}
	if _, err := app.NewReconcileService(relay).Reconcile(context.Background()); err == nil {
		t.Error("expected error")
	}
}

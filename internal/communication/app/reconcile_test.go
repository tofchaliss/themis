package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/communication/app"
)

type fakeRelay struct {
	batches []int
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
	relay := &fakeRelay{batches: []int{2, 1, 0}}
	total, err := app.NewReconcileService(relay).Reconcile(context.Background())
	if err != nil || total != 3 {
		t.Fatalf("reconcile total=%d err=%v, want 3", total, err)
	}
}

func TestReconcile_Error(t *testing.T) {
	if _, err := app.NewReconcileService(&fakeRelay{err: errors.New("bus down")}).Reconcile(context.Background()); err == nil {
		t.Error("expected error")
	}
}

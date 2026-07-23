package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

func TestRetention_Prune(t *testing.T) {
	repo := newRepo()
	repo.pruned = 4
	n, err := app.NewRetentionService(repo, 30*24*time.Hour, fixedClock{}).Prune(context.Background())
	if err != nil || n != 4 {
		t.Fatalf("prune n=%d err=%v, want 4", n, err)
	}

	// Error propagates.
	pe := newRepo()
	pe.pruneErr = errors.New("db down")
	if _, err := app.NewRetentionService(pe, time.Hour, fixedClock{}).Prune(context.Background()); err == nil {
		t.Error("prune error: expected error")
	}
}

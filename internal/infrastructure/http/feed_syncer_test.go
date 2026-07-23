package httpserver

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestFeedSyncer(t *testing.T) {
	called := false
	fs := feedSyncer{fns: map[string]func(context.Context) error{
		"b": func(context.Context) error { return nil },
		"a": func(context.Context) error { called = true; return nil },
	}}

	if err := fs.SyncFeed(context.Background(), "a"); err != nil || !called {
		t.Fatalf("SyncFeed(a) err=%v called=%v", err, called)
	}
	if err := fs.SyncFeed(context.Background(), "missing"); !errors.Is(err, domain.ErrUnknownFeed) {
		t.Fatalf("SyncFeed(missing) = %v, want ErrUnknownFeed", err)
	}
	feeds := fs.Feeds()
	if len(feeds) != 2 || feeds[0] != "a" || feeds[1] != "b" {
		t.Fatalf("Feeds() = %v, want [a b]", feeds)
	}
}

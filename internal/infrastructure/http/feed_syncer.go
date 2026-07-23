package httpserver

import (
	"context"
	"sort"

	"github.com/themis-project/themis/internal/domain"
)

// feedSyncer runs on-demand intelligence-feed syncs by name for the admin
// feed-sync endpoint. Each function is the same cycle the scheduler runs on its
// ticker (it logs and records feed health).
type feedSyncer struct {
	fns map[string]func(context.Context) error
}

// SyncFeed runs the named feed's sync cycle, or returns ErrUnknownFeed.
func (f feedSyncer) SyncFeed(ctx context.Context, feed string) error {
	fn, ok := f.fns[feed]
	if !ok {
		return domain.ErrUnknownFeed
	}
	return fn(ctx)
}

// Feeds lists the registered feed names, sorted.
func (f feedSyncer) Feeds() []string {
	names := make([]string, 0, len(f.fns))
	for name := range f.fns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

package domain

import (
	"context"
	"errors"
)

// ErrUnknownFeed indicates a feed name has no registered syncer.
var ErrUnknownFeed = errors.New("unknown feed")

// FeedSyncer triggers an on-demand sync of a named intelligence feed and lists
// the available feed names. It backs the admin feed-sync endpoint, which lets an
// operator force a refresh instead of waiting for the next scheduled tick.
type FeedSyncer interface {
	SyncFeed(ctx context.Context, feed string) error
	Feeds() []string
}

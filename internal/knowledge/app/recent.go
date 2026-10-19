package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The "what's new" read (GUI-16 layer 1): the newest CARDED Faultlines by card-creation time.
// It is a pure read over persisted, estate-relevant data — never a mirror of the world's CVE
// feed (EDR-KNOWLEDGE-01 D5): a card exists only because something in the estate, a feed
// sweep or an operator's gather put it there, so "newest cards" is "newest things that
// concern this estate".

const (
	// RecentDefaultLimit is the page when the caller names none.
	RecentDefaultLimit = 50
	// RecentMaxLimit caps the page; a larger ask is clamped, not refused.
	RecentMaxLimit = 200
)

// ErrRecentUnavailable is returned when no lister is wired.
var ErrRecentUnavailable = errors.New("recent faultlines are not available on this node")

// RecentFaultline is one card with the time it was created — a store fact the aggregate does
// not carry, so it rides beside the card rather than inside it.
type RecentFaultline struct {
	Faultline domain.Faultline
	CreatedAt time.Time
}

// RecentLister is the store port: the newest cards first.
type RecentLister interface {
	RecentFaultlines(ctx context.Context, limit int) ([]RecentFaultline, error)
}

// WithRecent attaches the lister.
func (s *ReadService) WithRecent(r RecentLister) *ReadService {
	s.recent = r
	return s
}

// Recent returns the newest cards, newest first. A non-positive limit takes the default and a
// limit above the cap is clamped.
func (s *ReadService) Recent(ctx context.Context, limit int) ([]RecentFaultline, error) {
	if s.recent == nil {
		return nil, ErrRecentUnavailable
	}
	if limit <= 0 {
		limit = RecentDefaultLimit
	}
	if limit > RecentMaxLimit {
		limit = RecentMaxLimit
	}
	return s.recent.RecentFaultlines(ctx, limit)
}

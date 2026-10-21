package app

import (
	"context"
	"errors"
	"sort"
	"time"
)

// The "latest published" read (GUI-16 layer 2): CVEs the world published recently, fetched LIVE
// from a per-CVE source and shown, never stored. "Gathering Is Not Knowing" (EDR-KNOWLEDGE-01
// D5): a card is created only by an explicit act — the operator's Gather on one of these rows —
// so this read persists nothing and the estate's knowledge stays relevance-bounded. Each row
// says whether the estate already holds a card, which is the one join with persisted data.

const (
	// PublishedDefaultDays is the window when the caller names none.
	PublishedDefaultDays = 7
	// PublishedMaxDays caps the window; a larger ask is clamped, not refused.
	PublishedMaxDays = 30
)

// ErrPublishedUnavailable is returned when no source is wired.
var ErrPublishedUnavailable = errors.New("the latest-published read has no source on this node")

// PublishedCVE is one recently published CVE as the source describes it, plus whether the
// estate already carries it.
type PublishedCVE struct {
	CVE       string
	Published time.Time
	Summary   string
	Severity  string
	Score     float64
	Carded    bool
}

// PublishedSource lists CVEs published since a moment, newest first or not — the service sorts.
type PublishedSource interface {
	PublishedSince(ctx context.Context, since time.Time) ([]PublishedCVE, error)
}

// PublishedService serves the read.
type PublishedService struct {
	src   PublishedSource
	repo  Repository
	clock Clock
}

// NewPublishedService wires the read; a nil source makes it refuse honestly.
func NewPublishedService(src PublishedSource, repo Repository, clock Clock) *PublishedService {
	return &PublishedService{src: src, repo: repo, clock: clock}
}

// Enabled reports whether a source is wired.
func (s *PublishedService) Enabled() bool { return s != nil && s.src != nil }

// LatestPublished returns the CVEs published in the last `days` days (default 7, clamped to
// 30), newest first, each marked Carded when the estate holds a card for it.
func (s *PublishedService) LatestPublished(ctx context.Context, days int) ([]PublishedCVE, error) {
	if !s.Enabled() {
		return nil, ErrPublishedUnavailable
	}
	if days <= 0 {
		days = PublishedDefaultDays
	}
	if days > PublishedMaxDays {
		days = PublishedMaxDays
	}
	since := s.clock.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	rows, err := s.src.PublishedSince(ctx, since)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		_, found, err := s.repo.GetByCVE(ctx, rows[i].CVE)
		if err != nil {
			return nil, err
		}
		rows[i].Carded = found
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].Published.Equal(rows[j].Published) {
			return rows[i].Published.After(rows[j].Published)
		}
		return rows[i].CVE < rows[j].CVE
	})
	return rows, nil
}

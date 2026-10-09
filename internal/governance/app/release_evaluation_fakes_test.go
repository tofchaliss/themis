package app_test

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// --- the release-evaluation queue, in memory (EDR-DELIVERY-01 N-M2b) -------------------
//
// It mirrors the real store's two guarantees rather than merely recording calls, because both
// are what the worker's correctness rests on: the insert is idempotent on
// (release, sbom, cause), and publish-and-mark is ATOMIC — a row already published takes no
// second event, which is what a crash between the append and the mark would otherwise cause.

type publishedEvaluation struct {
	row        app.PendingEvaluation
	event      domain.ReleaseEvaluated
	occurredAt time.Time
}

type evalQueue struct {
	mu        sync.Mutex
	rows      []app.PendingEvaluation
	published map[int64]bool
	events    []publishedEvaluation
	// scores is the release's Finding base scores — EVERY Finding, including the suppressed
	// ones (M1b-4). The bucketing itself is the real domain ladder, so a ladder test here is a
	// test of the rule and not of this fake.
	scores map[string][]int

	nextID     int64
	listErr    error
	countErr   error
	publishErr error
	listCalls  int
}

func newEvalQueue() *evalQueue {
	return &evalQueue{published: map[int64]bool{}, scores: map[string][]int{}}
}

func (q *evalQueue) EnqueuePendingReleaseEvaluation(_ context.Context, releaseID, sbomID, cause string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, r := range q.rows {
		if r.ReleaseID == releaseID && r.SBOMID == sbomID && r.Cause == cause {
			return nil // ON CONFLICT DO NOTHING
		}
	}
	q.nextID++
	q.rows = append(q.rows, app.PendingEvaluation{
		ID: q.nextID, ReleaseID: releaseID, SBOMID: sbomID, Cause: cause,
		ReceivedAt: time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(q.nextID) * time.Second),
	})
	return nil
}

func (q *evalQueue) ListPendingReleaseEvaluations(_ context.Context, limit int) ([]app.PendingEvaluation, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.listCalls++
	if q.listErr != nil {
		return nil, q.listErr
	}
	var out []app.PendingEvaluation
	for _, r := range q.rows {
		if q.published[r.ID] {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, r)
	}
	return out, nil
}

func (q *evalQueue) CountFindingsByBaseScoreBuckets(_ context.Context, releaseID string) (domain.SeverityCounts, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.countErr != nil {
		return domain.SeverityCounts{}, q.countErr
	}
	return domain.CountSeverityBuckets(q.scores[releaseID]), nil
}

func (q *evalQueue) PublishEvaluatedAndMark(_ context.Context, row app.PendingEvaluation, ev domain.ReleaseEvaluated, at time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.publishErr != nil {
		return q.publishErr // nothing appended AND nothing marked — one transaction, rolled back
	}
	if q.published[row.ID] {
		return nil // guarded by `published_at IS NULL`: another pass got there first
	}
	q.published[row.ID] = true
	q.events = append(q.events, publishedEvaluation{row: row, event: ev, occurredAt: at})
	return nil
}

func (q *evalQueue) pending() []app.PendingEvaluation {
	rows, _ := q.ListPendingReleaseEvaluations(context.Background(), 100)
	return rows
}

func (q *evalQueue) publishedEvents() []publishedEvaluation {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]publishedEvaluation(nil), q.events...)
}

// --- the Registry identity seam -------------------------------------------------------

// stubIdentity answers the release → project → product hops. failUntil simulates an OUTAGE: the
// first failUntil calls error, the rest succeed — the shape the worker must survive without
// dropping a row.
type stubIdentity struct {
	mu        sync.Mutex
	product   string
	project   string
	failUntil int
	calls     int
	asked     []string
}

var errRegistryDown = errors.New("registry: connection refused")

func (s *stubIdentity) ProductAndProjectOfRelease(_ context.Context, releaseID string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.asked = append(s.asked, releaseID)
	if s.calls <= s.failUntil {
		return "", "", errRegistryDown
	}
	return s.product, s.project, nil
}

// --- the worker's reporting seam ------------------------------------------------------

type recordedProblem struct {
	msg       string
	releaseID string
	err       error
}

type evalLog struct {
	mu       sync.Mutex
	problems []recordedProblem
}

func (l *evalLog) Error(msg, releaseID string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.problems = append(l.problems, recordedProblem{msg: msg, releaseID: releaseID, err: err})
}

func (l *evalLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.problems)
}

// --- a clock a test can move ----------------------------------------------------------

type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func newStepClock() *stepClock {
	return &stepClock{now: time.Unix(1_700_000_000, 0).UTC()}
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

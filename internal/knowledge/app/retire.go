package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The duplicate-identity repair (KN-SCAN-4(b)).
//
// Measured on MRF 2026-09-17, and the numbers decided the design rather than the other way
// round: 87 of 1569 match rows carried an unusable purl, all of them ONE component
// (`app:httpd@2.4.37-65.module+el8.10.0+40257+286895ef.9`), zero rows had an EMPTY purl — and in
// **87 of 87** cases the canonical `pkg:rpm/rocky/httpd@…` row was ALREADY recorded on the same
// (release, card) by the SBOM correlation path.
//
// So there was nothing to rename onto, and two earlier designs died on that fact: a supersede
// lifecycle (machinery for a relationship the evidence does not need) and a rename in place (the
// purl is a PK column and Postgres will UPDATE it — elegant, and dead at 87/87 collisions).
//
// What remains is a DEDUPLICATION. The raw row does not denote an additional component, so it
// leaves the active projection and stays stored for the audit trail. Findings and Positions are
// untouched: a Position belongs to a Finding, not a component, so retiring a duplicate retracts
// no security decision — and queue state re-derives from what remains, which makes the counts
// MORE correct, because the component is currently counted twice per Finding.

// DefaultRetireBatch bounds one repair sweep. The measured population is 87 rows, so this
// drains in one pass; the bound exists so an unexpected population cannot become an unbounded
// pass, not because a large one is expected.
const DefaultRetireBatch = 200

// DuplicateIdentityRow is one occurrence whose identity is a raw string and whose canonical twin
// is already recorded beside it.
type DuplicateIdentityRow struct {
	ReleaseID   string
	FaultlineID domain.FaultlineID
	CVE         string
	PURL        string
}

// DuplicateIdentitySource lists retirable duplicates, bounded. A raw row with NO identified twin
// is deliberately NOT listed: it may be the only record of something real, and retiring it would
// delete evidence rather than a duplicate.
type DuplicateIdentitySource interface {
	DuplicateIdentityRows(ctx context.Context, limit int) ([]DuplicateIdentityRow, error)
}

// MatchRetirer marks one occurrence retired and queues its retirement event atomically.
// created=false means it was already retired — a no-op, and no second event.
type MatchRetirer interface {
	RetireMatch(ctx context.Context, r DuplicateIdentityRow, at time.Time, event any) (bool, error)
}

// RetireService runs the duplicate-identity repair.
type RetireService struct {
	dups    DuplicateIdentitySource
	retirer MatchRetirer
	repo    Repository
	clock   Clock
	batch   int
}

// NewRetireService wires the repair. batch <= 0 falls back to the default.
func NewRetireService(dups DuplicateIdentitySource, retirer MatchRetirer, repo Repository, clock Clock, batch int) *RetireService {
	if batch <= 0 {
		batch = DefaultRetireBatch
	}
	return &RetireService{dups: dups, retirer: retirer, repo: repo, clock: clock, batch: batch}
}

// Sweep retires one bounded batch of duplicate-identity occurrences. Returns how many were
// retired and whether the batch filled (more remain).
//
// Idempotent throughout: the store's UPDATE is guarded on `retired_at IS NULL`, the listing
// excludes retired rows so the sweep converges, and the event asserts a STATE rather than a
// transition, so a re-delivery downstream re-asserts the same state and changes nothing.
func (s *RetireService) Sweep(ctx context.Context) (retired int, full bool, err error) {
	rows, err := s.dups.DuplicateIdentityRows(ctx, s.batch)
	if err != nil || len(rows) == 0 {
		return 0, false, err
	}
	now := s.clock.Now()
	cards := map[domain.FaultlineID]domain.Faultline{}
	for _, r := range rows {
		card, ok := cards[r.FaultlineID]
		if !ok {
			card, err = s.repo.GetByID(ctx, r.FaultlineID)
			if err != nil {
				return retired, false, err
			}
			cards[r.FaultlineID] = card
		}
		event := domain.NewComponentRetired(card, r.ReleaseID, r.PURL, domain.RetiredDuplicateIdentity, now)
		done, rerr := s.retirer.RetireMatch(ctx, r, now, event)
		if rerr != nil {
			return retired, false, rerr
		}
		if done {
			retired++
		}
	}
	return retired, len(rows) == s.batch, nil
}

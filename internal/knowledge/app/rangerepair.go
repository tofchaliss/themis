package app

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// FaultlineLister names every card, for a one-time pass over the whole estate.
type FaultlineLister interface {
	AllFaultlineIDs(ctx context.Context) ([]domain.FaultlineID, error)
}

// RangeRepairResult counts what one pass did.
type RangeRepairResult struct {
	Cards    int
	Repaired int
}

// RangeRepair is the ONE-TIME pass that corrects the ranges the pre-2026-10-14 OSV reader
// wrote onto every card it ever fed (KN-GO-3). The reader split one OSV interval into two
// OR'd rules, and the lone lower bound matched every version ever written; the reader is
// fixed, but the proposal log is append-only and the sweep re-polls OSV only for the
// components a release's CURRENT version is affected by — so a card whose only flaw is the
// old shape would never hear a corrected statement. Measured: 165 stdlib cards, 330 open
// Findings on Go 1.27.1, zero of them cleared by the KN-GO-2 pass.
//
// It respects the log: for each card, the latest range-bearing statement of each source is
// re-paired, and where that changes anything a NEW statement from the same source — same
// severity, CVSS, fixes and carriers, corrected ranges, observed now — is folded. Reconcile
// then takes that later statement over the earlier one, the view changes, and the ordinary
// FaultlineEnriched fan-out runs Governance's version-range rule. Nothing is edited in place,
// nothing is deleted, and a second pass finds nothing to repair.
type RangeRepair struct {
	cards FaultlineLister
	repo  Repository
	fold  *FaultlineService
	clock Clock
}

// NewRangeRepair builds the pass.
func NewRangeRepair(cards FaultlineLister, repo Repository, fold *FaultlineService, clock Clock) *RangeRepair {
	return &RangeRepair{cards: cards, repo: repo, fold: fold, clock: clock}
}

// Run performs one pass. A card that cannot be read is fatal: the pass is a repair, and a
// repair that silently skipped cards would leave the operator believing the estate is clean.
func (r *RangeRepair) Run(ctx context.Context) (RangeRepairResult, error) {
	var res RangeRepairResult
	ids, err := r.cards.AllFaultlineIDs(ctx)
	if err != nil {
		return res, fmt.Errorf("list faultlines: %w", err)
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Cards++
		f, err := r.repo.GetByID(ctx, id)
		if err != nil {
			return res, fmt.Errorf("read %s: %w", id, err)
		}
		for _, facts := range latestRangeFactsPerSource(f) {
			repaired, changed := domain.RepairSplitRanges(facts.facts.AffectedRanges)
			if !changed {
				continue
			}
			corrected := facts.facts
			corrected.AffectedRanges = repaired
			// The source and time are a stored proposal's and the clock's, both already valid,
			// so the constructor cannot refuse them.
			p, _ := domain.NewVulnFactsProposal(facts.source, r.clock.Now(), corrected)
			if _, _, err := r.fold.FoldProposal(ctx, f.CVE(), p); err != nil {
				return res, fmt.Errorf("fold %s from %s: %w", id, facts.source, err)
			}
			res.Repaired++
		}
	}
	return res, nil
}

type sourceFacts struct {
	source string
	facts  domain.VulnFacts
}

// latestRangeFactsPerSource returns, per source, the vuln-facts of its latest statement that
// carries ranges — the one Reconcile honours, and therefore the one worth correcting.
func latestRangeFactsPerSource(f domain.Faultline) []sourceFacts {
	latest := map[string]domain.Proposal{}
	var order []string
	for _, p := range f.Proposals() {
		facts, ok := p.VulnFacts()
		if !ok || len(facts.AffectedRanges) == 0 {
			continue
		}
		prev, seen := latest[p.Source()]
		if !seen {
			order = append(order, p.Source())
		}
		if !seen || !p.ObservedAt().Before(prev.ObservedAt()) {
			latest[p.Source()] = p
		}
	}
	out := make([]sourceFacts, 0, len(order))
	for _, src := range order {
		facts, _ := latest[src].VulnFacts()
		out = append(out, sourceFacts{source: src, facts: facts})
	}
	return out
}

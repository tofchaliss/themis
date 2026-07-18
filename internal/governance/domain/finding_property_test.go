package domain_test

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/governance/domain"
)

// TestFindingInvariantsProperty drives a Finding through a random sequence of governed
// operations and asserts the aggregate invariants hold no matter the order (D3/D7/D9):
//   - the optimistic version never decreases;
//   - Proposals and Position versions are append-only (their counts never shrink);
//   - Position versions are contiguous 1..n and the current position is the latest;
//   - the stage is always a valid stage and, once Archived (terminal), stays Archived.
func TestFindingInvariantsProperty(t *testing.T) {
	stances := []domain.Stance{domain.StanceAffected, domain.StanceNotAffected, domain.StanceMitigated, domain.StanceAcceptedRisk}
	proposers := []domain.Actor{human, system}

	rapid.Check(t, func(t *rapid.T) {
		f, err := domain.NewFinding("fnd", "rel", "fl", "CVE-2024-1")
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}

		prevVersion, prevPositions, prevProposals := f.Version(), 0, 0
		archived := false
		nextPID := 0

		firstOpenProposal := func() (domain.ProposalID, bool) {
			for _, p := range f.Proposals() {
				if p.IsOpen() {
					return p.ID(), true
				}
			}
			return "", false
		}

		n := rapid.IntRange(1, 40).Draw(t, "ops")
		for i := 0; i < n; i++ {
			switch rapid.SampledFrom([]string{"absorb", "raise", "accept", "reject", "resolve", "reopen", "monitor", "archive"}).Draw(t, "op") {
			case "absorb":
				purl := rapid.SampledFrom([]string{"a", "b", "c"}).Draw(t, "purl")
				_, _ = f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:generic/" + purl})
			case "raise":
				nextPID++
				stance := rapid.SampledFrom(stances).Draw(t, "stance")
				proposer := rapid.SampledFrom(proposers).Draw(t, "proposer")
				p, perr := domain.NewGovernanceProposal(domain.ProposalID(fmt.Sprintf("p%d", nextPID)), proposer, stance, "x", epoch)
				if perr != nil {
					t.Fatalf("build proposal: %v", perr)
				}
				_ = f.RaiseProposal(p)
			case "accept":
				if id, ok := firstOpenProposal(); ok {
					_, _ = f.AcceptProposal(id, human, epoch)
				}
			case "reject":
				if id, ok := firstOpenProposal(); ok {
					_ = f.RejectProposal(id, human, epoch)
				}
			case "resolve":
				_ = f.Resolve()
			case "reopen":
				_ = f.Reopen()
			case "monitor":
				_ = f.MarkMonitoring()
			case "archive":
				_ = f.Archive()
			}

			if f.Version() < prevVersion {
				t.Fatalf("version decreased: %d < %d", f.Version(), prevVersion)
			}
			positions := f.Positions()
			if len(positions) < prevPositions {
				t.Fatalf("positions shrank: %d < %d", len(positions), prevPositions)
			}
			if len(f.Proposals()) < prevProposals {
				t.Fatalf("proposals shrank: %d < %d", len(f.Proposals()), prevProposals)
			}
			if !f.Stage().Valid() {
				t.Fatalf("invalid stage %q", f.Stage())
			}
			if archived && f.Stage() != domain.StageArchived {
				t.Fatalf("left terminal Archived state → %q", f.Stage())
			}
			for idx, pos := range positions {
				if pos.Version() != idx+1 {
					t.Fatalf("position[%d] version = %d, want %d", idx, pos.Version(), idx+1)
				}
			}
			if cur, ok := f.CurrentPosition(); ok && cur.Version() != len(positions) {
				t.Fatalf("current position version = %d, want latest %d", cur.Version(), len(positions))
			}

			prevVersion, prevPositions, prevProposals = f.Version(), len(positions), len(f.Proposals())
			if f.Stage() == domain.StageArchived {
				archived = true
			}
		}
	})
}

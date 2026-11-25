package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Decision copy (EDR-SYNC-01 revision 2, D9-D11). The person picks the Findings a decision is
// copied to; Governance checks every pick before the decision is recorded (same CVE, same
// product, same component) and makes the copies off the request path, on the scope sweep. A
// copy is one-time and in the person's name, and it may replace a decision already on a target
// the person picked. Nothing here decides.

// ErrCopyTargetInvalid is returned when a picked Finding may not receive the copy.
var ErrCopyTargetInvalid = errors.New("governance: a copy target must be another Finding of the same CVE in the same product that carries the same component")

// CopyCandidate is one Finding of the same CVE in the same product, as the pick list shows it:
// where it lives, how alike it is to the source (Level vulnerability cannot be copied to), and
// the decision it carries now, if any.
type CopyCandidate struct {
	ScopeTarget
	Decided   bool
	Stance    domain.Stance
	DecidedBy domain.Actor
	DecidedAt time.Time
}

// Copyable reports whether a decision can be copied to this candidate.
func (c CopyCandidate) Copyable() bool { return c.Level != domain.LevelVulnerability }

// CopyCandidates lists every other Finding of the source's CVE in the source's product (D10).
// A Registry failure is an error, never a shorter list.
func (p *ScopePropagation) CopyCandidates(ctx context.Context, sourceID domain.FindingID) ([]CopyCandidate, error) {
	source, err := p.svc.repo.GetByID(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	ownersOf := p.owners(map[string]ReleaseOwners{})
	src, err := ownersOf(ctx, source.ReleaseID())
	if err != nil {
		return nil, err
	}
	siblings, err := p.svc.repo.FindingsByFaultline(ctx, source.FaultlineID())
	if err != nil {
		return nil, err
	}
	var out []CopyCandidate
	for _, sid := range siblings {
		if sid == source.ID() {
			continue
		}
		target, err := p.svc.repo.GetByID(ctx, sid)
		if err != nil {
			return nil, err
		}
		own, err := ownersOf(ctx, target.ReleaseID())
		if err != nil {
			return nil, err
		}
		if own.ProductID != src.ProductID {
			continue // never another product
		}
		c := CopyCandidate{ScopeTarget: ScopeTarget{
			FindingID: sid, ReleaseID: target.ReleaseID(),
			ProductID: own.ProductID, ProjectID: own.ProjectID,
			ProductName: own.ProductName, ProjectName: own.ProjectName, Version: own.Version,
			Level: domain.CopyLevel(target.ActiveComponents(), source.ActiveComponents()),
		}}
		if pos, ok := target.CurrentPosition(); ok {
			c.Decided, c.Stance, c.DecidedBy, c.DecidedAt = true, pos.Stance(), pos.Actor(), pos.EstablishedAt()
		}
		out = append(out, c)
	}
	return out, nil
}

// CheckCopyTargets refuses the whole pick when any picked Finding is not a copyable candidate
// (D9): "never another product" is Governance's rule, not only the GUI's.
func (p *ScopePropagation) CheckCopyTargets(ctx context.Context, sourceID domain.FindingID, ids []domain.FindingID) error {
	if len(ids) == 0 {
		return nil
	}
	candidates, err := p.CopyCandidates(ctx, sourceID)
	if err != nil {
		return err
	}
	copyable := map[domain.FindingID]bool{}
	for _, c := range candidates {
		copyable[c.FindingID] = c.Copyable()
	}
	for _, id := range ids {
		if !copyable[id] {
			return fmt.Errorf("%w: %s", ErrCopyTargetInvalid, id)
		}
	}
	return nil
}

// ApplyCopy makes the copies of the decision `sp` names. A decision no longer current
// (re-decided since) copies nothing: the newer decision speaks for the person now. A target
// that stopped carrying the same component since the pick is skipped. Returns how many
// Positions were established.
func (p *ScopePropagation) ApplyCopy(ctx context.Context, sp ScopedPosition) (int, error) {
	source, err := p.svc.repo.GetByID(ctx, sp.FindingID)
	if err != nil {
		return 0, err
	}
	pos, ok := source.CurrentPosition()
	if !ok || pos.Version() != sp.Version || !pos.IsCopySource() {
		return 0, nil
	}
	src, err := p.owners(map[string]ReleaseOwners{})(ctx, source.ReleaseID())
	if err != nil {
		return 0, err
	}
	copied := 0
	for _, id := range pos.CopyTo() {
		if err := ctx.Err(); err != nil {
			return copied, err
		}
		ok, err := p.svc.ApplyCopiedPosition(ctx, id, source, src.Label(), pos)
		if err != nil {
			return copied, fmt.Errorf("copy to %s: %w", id, err)
		}
		if ok {
			copied++
		}
	}
	return copied, nil
}

// sweepCopies makes the pending copies and marks each decision done. A failure leaves the row
// pending and ends the pass; a copy already made is not made twice (the proposal id is the
// same), so the retry is safe.
func (p *ScopePropagation) sweepCopies(ctx context.Context, res ScopeResult) (ScopeResult, error) {
	rows, err := p.pending.PendingCopyPositions(ctx, scopeSweepBatch)
	if err != nil {
		return res, err
	}
	for _, sp := range rows {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		n, err := p.ApplyCopy(ctx, sp)
		res.Copied += n
		if err != nil {
			return res, err
		}
		if err := p.pending.MarkCopyApplied(ctx, sp.FindingID, sp.Version); err != nil {
			return res, err
		}
		res.Copies++
	}
	return res, nil
}

// ApplyCopiedPosition establishes `pos` (the source's current Position) on the target: a
// proposal in the person's own name, accepted by that person in the same transaction, with the
// same terms and the source recorded (D11). Unlike a scoped decision it does not stop at a
// target that already has a Position: the person picked this Finding, and the earlier Position
// stays in the history. Returns whether a Position was established; a target that already
// carries this copy, or no longer carries the same component, gets nothing.
func (s *FindingService) ApplyCopiedPosition(ctx context.Context, targetID domain.FindingID, source domain.Finding, sourceLabel string, pos domain.Position) (bool, error) {
	pid := domain.CopiedProposalID(targetID, source.ID(), pos.Version())
	in := pos.Inputs()
	terms := domain.AcceptanceTerms{
		ReviewBy: in.ReviewBy, Owner: in.Owner, Treatment: in.Treatment, Proof: in.Proof,
		PropagatedFrom: domain.PropagationSource{FindingID: source.ID(), Version: pos.Version()},
	}
	applied := false
	err := s.mutate(ctx, targetID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		level := domain.CopyLevel(f.ActiveComponents(), source.ActiveComponents())
		if level == domain.LevelVulnerability {
			return nil, errNoop
		}
		// Asserted: the person stated this stance for this Finding by picking it.
		p, err := domain.NewGovernanceProposal(pid, pos.Actor(), pos.Stance(),
			domain.CopiedRationale(source, sourceLabel, pos, level), now, value.TrustAsserted)
		if err != nil {
			return nil, err
		}
		if err := f.RaiseProposal(p); errors.Is(err, domain.ErrDuplicateProposal) {
			return nil, errNoop
		} else if err != nil {
			return nil, err
		}
		established, err := f.AcceptProposalWith(pid, pos.Actor(), now, terms)
		if err != nil {
			return nil, err
		}
		applied = true
		return []OutboxNote{
			{EventType: EventProposalRaised, Event: domain.NewProposalRaised(*f, p, now), OccurredAt: now},
			{EventType: EventProposalAccepted, Event: domain.NewProposalAccepted(*f, pid, established, now), OccurredAt: now},
			positionNote(*f, established, now),
		}, nil
	})
	return applied, err
}

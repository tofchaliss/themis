package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// rollForwardActorID is the system proposer of a roll-forward proposal (EDR-ROLLFORWARD-01 D1).
const rollForwardActorID = "roll-forward"

// UndecidedFindingLister names the Findings of one release that have no Position yet — the
// population roll-forward has any business proposing on.
type UndecidedFindingLister interface {
	UndecidedFindingsByRelease(ctx context.Context, releaseID string) ([]domain.FindingID, error)
}

// RollForwardResult counts what one pass did: Findings considered, proposals raised, and
// Findings with no eligible precedent (no sibling decided, different project, a rule's verdict,
// or not alike enough — D3).
type RollForwardResult struct {
	Considered  int
	Raised      int
	NoPrecedent int
}

// RollForward is the deterministic, model-free "same CVE, decided on a sibling release of this
// project" proposal (EDR-ROLLFORWARD-01). It runs where the Registry seam may fail without
// stopping the pipeline: on the release-evaluation worker after a release's correlation
// completes, and in the one-time re-judge pass for the Findings an estate already holds.
//
// It raises a system proposal on Inferred evidence, so the constitutional check keeps it from
// any policy (EDR-TRUST-01 T6): a person accepts it, with the source release, Position version,
// decider kind and level named in the rationale. It never writes a Position.
type RollForward struct {
	svc       *FindingService
	undecided UndecidedFindingLister
	identity  ReleaseIdentityResolver
}

// NewRollForward builds the pass over the write service, the per-release lister and the
// Registry identity seam (release → project).
func NewRollForward(svc *FindingService, undecided UndecidedFindingLister, identity ReleaseIdentityResolver) *RollForward {
	return &RollForward{svc: svc, undecided: undecided, identity: identity}
}

// ForRelease proposes on every undecided Finding of one release whose project is already known
// (the worker resolved it). A Registry failure while placing a sibling is an error, so the
// caller defers and retries — a missing precedent is "no proposal", a missing answer is not.
func (r *RollForward) ForRelease(ctx context.Context, releaseID, projectID string) (RollForwardResult, error) {
	var res RollForwardResult
	if strings.TrimSpace(projectID) == "" {
		return res, ErrUnresolvedReleaseIdentity
	}
	ids, err := r.undecided.UndecidedFindingsByRelease(ctx, releaseID)
	if err != nil {
		return res, err
	}
	projects := map[string]string{releaseID: projectID}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Considered++
		raised, err := r.svc.RollForwardFinding(ctx, id, projectID, r.projectOf(projects))
		if err != nil {
			return res, fmt.Errorf("roll-forward %s: %w", id, err)
		}
		if raised {
			res.Raised++
		} else {
			res.NoPrecedent++
		}
	}
	return res, nil
}

// Sweep is ForRelease over EVERY undecided Finding (the one-time pass): each Finding's own
// project is resolved first, then its siblings are judged against it.
func (r *RollForward) Sweep(ctx context.Context, faultlines UndecidedFaultlineLister) (RollForwardResult, error) {
	var res RollForwardResult
	fls, err := faultlines.UndecidedFaultlines(ctx)
	if err != nil {
		return res, err
	}
	projects := map[string]string{}
	lookup := r.projectOf(projects)
	for _, fl := range fls {
		ids, err := r.svc.repo.FindingsByFaultline(ctx, fl)
		if err != nil {
			return res, err
		}
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			f, err := r.svc.repo.GetByID(ctx, id)
			if err != nil {
				return res, err
			}
			if _, decided := f.CurrentPosition(); decided {
				continue
			}
			project, err := lookup(ctx, f.ReleaseID())
			if err != nil {
				return res, fmt.Errorf("place release %s: %w", f.ReleaseID(), err)
			}
			res.Considered++
			raised, err := r.svc.RollForwardFinding(ctx, id, project, lookup)
			if err != nil {
				return res, fmt.Errorf("roll-forward %s: %w", id, err)
			}
			if raised {
				res.Raised++
			} else {
				res.NoPrecedent++
			}
		}
	}
	return res, nil
}

// projectOf is the release → project hop with a per-pass cache: one Registry call per release,
// however many Findings share it. A blank answer is an error (fail closed, like the worker).
func (r *RollForward) projectOf(cache map[string]string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, releaseID string) (string, error) {
		if p, ok := cache[releaseID]; ok {
			return p, nil
		}
		_, project, err := r.identity.ProductAndProjectOfRelease(ctx, releaseID)
		if err != nil {
			return "", err
		}
		if project == "" {
			return "", ErrUnresolvedReleaseIdentity
		}
		cache[releaseID] = project
		return project, nil
	}
}

// RollForwardFinding raises the roll-forward proposal on one undecided Finding when a sibling
// Finding on the same Faultline, in a release of the same project, holds a JUDGED Position and
// the two are alike enough (D3). Among several, the most recently established wins. Returns
// whether a proposal was raised; an already-raised pair is not raised again.
func (s *FindingService) RollForwardFinding(ctx context.Context, id domain.FindingID, projectID string, projectOf func(context.Context, string) (string, error)) (bool, error) {
	target, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	if _, decided := target.CurrentPosition(); decided {
		return false, nil
	}
	siblings, err := s.repo.FindingsByFaultline(ctx, target.FaultlineID())
	if err != nil {
		return false, err
	}
	var (
		best      domain.Finding
		bestPos   domain.Position
		bestLevel domain.RollForwardLevel
		found     bool
	)
	for _, sid := range siblings {
		if sid == id {
			continue
		}
		sib, err := s.repo.GetByID(ctx, sid)
		if err != nil {
			return false, err
		}
		if sib.ReleaseID() == target.ReleaseID() {
			continue
		}
		pos, judged := sib.JudgedPosition()
		if !judged {
			continue
		}
		level := domain.RollForwardEligibility(target.ActiveComponents(), sib.ActiveComponents())
		if level == "" {
			continue
		}
		// The project hop runs LAST, only for a sibling that would otherwise qualify: it is the
		// one step that can fail against another service.
		project, err := projectOf(ctx, sib.ReleaseID())
		if err != nil {
			return false, err
		}
		if project != projectID {
			continue
		}
		if !found || pos.EstablishedAt().After(bestPos.EstablishedAt()) {
			best, bestPos, bestLevel, found = sib, pos, level, true
		}
	}
	if !found {
		return false, nil
	}
	pid := domain.RollForwardProposalID(id, best.ID())
	rationale := rollForwardRationale(best, bestPos, bestLevel)
	proposer := domain.Actor{Kind: domain.ActorSystem, ID: rollForwardActorID}
	raised := false
	err = s.mutate(ctx, id, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		if _, decided := f.CurrentPosition(); decided {
			return nil, errNoop // decided between the read and the write
		}
		// Inferred: a decision carried from another release is a hypothesis about this one,
		// so the constitutional check keeps it away from every policy; a person accepts it.
		p, err := domain.NewGovernanceProposal(pid, proposer, bestPos.Stance(), rationale, now, value.TrustInferred)
		if err != nil {
			return nil, err
		}
		notes, err := s.raiseAndMaybeAutoAccept(f, p, now)
		if errors.Is(err, domain.ErrDuplicateProposal) {
			return nil, errNoop
		}
		if err == nil {
			raised = true
		}
		return notes, err
	})
	return raised, err
}

// rollForwardRationale states where the stance comes from, so the person deciding can weigh it:
// the source release, the Position version, who decided it, how alike the Findings are, and the
// original rationale verbatim.
func rollForwardRationale(source domain.Finding, pos domain.Position, level domain.RollForwardLevel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "roll-forward (%s level) from release %s, Position v%d decided by %s: %s",
		level, source.ReleaseID(), pos.Version(), pos.Actor().Kind, pos.Stance())
	if r := strings.TrimSpace(pos.Rationale()); r != "" {
		b.WriteString(" — ")
		b.WriteString(r)
	}
	return b.String()
}

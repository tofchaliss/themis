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

// Scope propagation (EDR-SYNC-01 D1–D4). A person decides once and says how wide the subject
// is (release · project · product); Governance then establishes the SAME Position — recorded
// against that person, naming the source — on every Finding of the same CVE in scope that
// carries the same component (D2), now and for Findings born later (D4). It runs off the
// request path, like roll-forward: the product/project hops are Registry reads, and a Registry
// outage must cost a retry, never a half-applied decision. Nothing here decides: a propagated
// Position is the person's own decision with a wider subject.

const (
	// DefaultScopeSweepInterval is how often standing scoped decisions not yet applied are
	// picked up. The person asked for "soft realtime": a minute, not a second.
	DefaultScopeSweepInterval = time.Minute
	// scopeSweepBatch bounds one pass.
	scopeSweepBatch = 100
)

// ScopedPosition is one scoped decision as the queue sees it: the Finding the person decided
// and the Position version they established there.
type ScopedPosition struct {
	FindingID domain.FindingID
	Version   int
}

// ScopedPositions is the store seam of the sweep: the Position rows taken with a propagating
// scope and not yet applied, and the mark that says they were. The Position row IS the queue
// row — recorded in the accept's own transaction, so a decision can never be taken and lost.
type ScopedPositions interface {
	// PendingScopedPositions lists up to limit unapplied scoped decisions, oldest first.
	PendingScopedPositions(ctx context.Context, limit int) ([]ScopedPosition, error)
	// MarkScopeApplied stamps the row; a later pass lists it no more.
	MarkScopeApplied(ctx context.Context, findingID domain.FindingID, version int) error
}

// ReleaseOwners is a release as Registry knows it: the ids that decide scope and the names a
// person reads. The ids are mandatory (fail closed); the names are a courtesy and may be blank.
type ReleaseOwners struct {
	ProductID, ProjectID              string
	ProductName, ProjectName, Version string
}

// Label is the release as a person says it — "<project> <version>" — or blank when Registry
// gave no name, in which case callers fall back to the id.
func (o ReleaseOwners) Label() string {
	return strings.TrimSpace(strings.TrimSpace(o.ProjectName) + " " + strings.TrimSpace(o.Version))
}

// ReleaseOwnerResolver is the Registry hop scope needs: release → owners WITH their names, so
// the rationale and the preview say "<project> <version>", not a UUID (owner ask, 2026-11-03).
type ReleaseOwnerResolver interface {
	ReleaseOwners(ctx context.Context, releaseID string) (ReleaseOwners, error)
}

// ScopeTarget is one Finding a scoped decision reaches: where it lives (ids and names) and how
// alike it is to the source (the level, D2). The preview (D7) and the application share this list.
type ScopeTarget struct {
	FindingID   domain.FindingID
	ReleaseID   string
	ProductID   string
	ProjectID   string
	ProductName string
	ProjectName string
	Version     string
	Level       domain.RollForwardLevel
}

// ScopeResult counts one pass.
type ScopeResult struct {
	// Decisions is how many scoped decisions were visited (sweep) or Findings considered
	// (release pass); Applied how many Positions were established; Conflicts how many targets
	// were left alone because two standing decisions disagreed (D5).
	Decisions, Applied, Conflicts int
}

// ScopePropagation applies scoped decisions. It needs the write service, the queue, the
// per-release undecided lister and the Registry identity seam.
type ScopePropagation struct {
	svc       *FindingService
	pending   ScopedPositions
	undecided UndecidedFindingLister
	registry  ReleaseOwnerResolver
}

// NewScopePropagation builds the pass.
func NewScopePropagation(svc *FindingService, pending ScopedPositions, undecided UndecidedFindingLister, registry ReleaseOwnerResolver) *ScopePropagation {
	return &ScopePropagation{svc: svc, pending: pending, undecided: undecided, registry: registry}
}

// Targets lists the Findings a decision of `scope` on `source` reaches NOW (D2): the same
// Faultline, another release, undecided, alike enough (artifact or component level), and owned
// by the same project or product. The preview answers from it before the person clicks (D7).
// A Registry failure is an error, never an empty list: "nobody" and "cannot tell" must not
// look alike to the person reading the count.
func (p *ScopePropagation) Targets(ctx context.Context, sourceID domain.FindingID, scope domain.DecisionScope) ([]ScopeTarget, error) {
	source, err := p.svc.repo.GetByID(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	return p.targetsOf(ctx, source, scope, p.owners(map[string]ReleaseOwners{}))
}

func (p *ScopePropagation) targetsOf(ctx context.Context, source domain.Finding, scope domain.DecisionScope, ownersOf ownerLookup) ([]ScopeTarget, error) {
	if !scope.Propagates() {
		return nil, nil
	}
	src, err := ownersOf(ctx, source.ReleaseID())
	if err != nil {
		return nil, err
	}
	siblings, err := p.svc.repo.FindingsByFaultline(ctx, source.FaultlineID())
	if err != nil {
		return nil, err
	}
	var out []ScopeTarget
	for _, sid := range siblings {
		if sid == source.ID() {
			continue
		}
		target, err := p.svc.repo.GetByID(ctx, sid)
		if err != nil {
			return nil, err
		}
		if target.ReleaseID() == source.ReleaseID() {
			continue
		}
		if _, decided := target.CurrentPosition(); decided {
			continue // a decision already on the target is never overwritten (D5)
		}
		level := domain.RollForwardEligibility(target.ActiveComponents(), source.ActiveComponents())
		if level == "" {
			continue // a different component is never synced (D2)
		}
		// The identity hop runs LAST, only for a target that qualifies on every other count.
		own, err := ownersOf(ctx, target.ReleaseID())
		if err != nil {
			return nil, err
		}
		if !scope.Covers(src.ProductID, src.ProjectID, own.ProductID, own.ProjectID) {
			continue
		}
		out = append(out, ScopeTarget{
			FindingID: sid, ReleaseID: target.ReleaseID(),
			ProductID: own.ProductID, ProjectID: own.ProjectID,
			ProductName: own.ProductName, ProjectName: own.ProjectName, Version: own.Version,
			Level: level,
		})
	}
	return out, nil
}

// Apply establishes the scoped decision `sp` on every target it reaches now. A decision no
// longer current (re-decided since), or one that is itself propagated, applies nothing: the
// caller marks it and moves on. Returns how many Positions were established.
func (p *ScopePropagation) Apply(ctx context.Context, sp ScopedPosition) (int, error) {
	source, err := p.svc.repo.GetByID(ctx, sp.FindingID)
	if err != nil {
		return 0, err
	}
	pos, ok := source.CurrentPosition()
	if !ok || pos.Version() != sp.Version || !pos.IsScopedSource() {
		return 0, nil
	}
	ownersOf := p.owners(map[string]ReleaseOwners{})
	src, err := ownersOf(ctx, source.ReleaseID()) // names the source in every rationale; cached for targetsOf
	if err != nil {
		return 0, err
	}
	targets, err := p.targetsOf(ctx, source, pos.Scope(), ownersOf)
	if err != nil {
		return 0, err
	}
	applied := 0
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return applied, err
		}
		ok, err := p.svc.ApplyScopedPosition(ctx, t.FindingID, source, src.Label(), pos, t.Level)
		if err != nil {
			return applied, fmt.Errorf("apply scope to %s: %w", t.FindingID, err)
		}
		if ok {
			applied++
		}
	}
	return applied, nil
}

// Sweep applies every pending scoped decision and marks it. A failure leaves the row pending
// and ends the pass: the next one retries from the same place, and nothing is marked that
// was not applied.
func (p *ScopePropagation) Sweep(ctx context.Context) (ScopeResult, error) {
	var res ScopeResult
	rows, err := p.pending.PendingScopedPositions(ctx, scopeSweepBatch)
	if err != nil {
		return res, err
	}
	for _, sp := range rows {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		n, err := p.Apply(ctx, sp)
		res.Applied += n
		if err != nil {
			return res, err
		}
		if err := p.pending.MarkScopeApplied(ctx, sp.FindingID, sp.Version); err != nil {
			return res, err
		}
		res.Decisions++
	}
	return res, nil
}

// ForRelease is the later-born half (D4): every undecided Finding of a release whose owners are
// known is checked for a standing scoped decision among its siblings. It runs on the
// release-evaluation worker once correlation completes, before roll-forward — a Finding the
// person already decided for the whole product should not also carry a sibling's proposal.
func (p *ScopePropagation) ForRelease(ctx context.Context, releaseID, productID, projectID string) (ScopeResult, error) {
	var res ScopeResult
	if strings.TrimSpace(productID) == "" || strings.TrimSpace(projectID) == "" {
		return res, ErrUnresolvedReleaseIdentity
	}
	ids, err := p.undecided.UndecidedFindingsByRelease(ctx, releaseID)
	if err != nil {
		return res, err
	}
	ownersOf := p.owners(map[string]ReleaseOwners{releaseID: {ProductID: productID, ProjectID: projectID}})
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Decisions++
		applied, conflict, err := p.applyStanding(ctx, id, productID, projectID, ownersOf)
		if err != nil {
			return res, fmt.Errorf("scope %s: %w", id, err)
		}
		if applied {
			res.Applied++
		}
		if conflict {
			res.Conflicts++
		}
	}
	return res, nil
}

// applyStanding applies the standing scoped decision that covers one undecided target. Among
// several, the most recently established wins — unless they disagree on the stance, in which
// case nothing is applied (D5): Themis never picks between two people.
func (p *ScopePropagation) applyStanding(ctx context.Context, id domain.FindingID, productID, projectID string, ownersOf ownerLookup) (applied, conflict bool, err error) {
	target, err := p.svc.repo.GetByID(ctx, id)
	if err != nil {
		return false, false, err
	}
	if _, decided := target.CurrentPosition(); decided {
		return false, false, nil
	}
	siblings, err := p.svc.repo.FindingsByFaultline(ctx, target.FaultlineID())
	if err != nil {
		return false, false, err
	}
	var (
		best      domain.Finding
		bestPos   domain.Position
		bestLevel domain.RollForwardLevel
		bestOwner ReleaseOwners
		found     bool
	)
	for _, sid := range siblings {
		if sid == id {
			continue
		}
		sib, err := p.svc.repo.GetByID(ctx, sid)
		if err != nil {
			return false, false, err
		}
		if sib.ReleaseID() == target.ReleaseID() {
			continue
		}
		pos, ok := sib.CurrentPosition()
		if !ok || !pos.IsScopedSource() {
			continue
		}
		level := domain.RollForwardEligibility(target.ActiveComponents(), sib.ActiveComponents())
		if level == "" {
			continue
		}
		own, err := ownersOf(ctx, sib.ReleaseID())
		if err != nil {
			return false, false, err
		}
		if !pos.Scope().Covers(own.ProductID, own.ProjectID, productID, projectID) {
			continue
		}
		if found && pos.Stance() != bestPos.Stance() {
			conflict = true
		}
		if !found || pos.EstablishedAt().After(bestPos.EstablishedAt()) {
			best, bestPos, bestLevel, bestOwner, found = sib, pos, level, own, true
		}
	}
	if !found || conflict {
		return false, conflict, nil
	}
	applied, err = p.svc.ApplyScopedPosition(ctx, id, best, bestOwner.Label(), bestPos, bestLevel)
	return applied, false, err
}

// RunEvery sweeps on a cadence until ctx is cancelled, reporting each pass through report
// (nil = silent).
func (p *ScopePropagation) RunEvery(ctx context.Context, every time.Duration, report func(ScopeResult, error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := p.Sweep(ctx)
			if report != nil {
				report(res, err)
			}
		}
	}
}

// ownerLookup is the release → owners hop with a per-pass cache: one Registry call per release,
// however many Findings share it. A blank id is an error (fail closed); blank names are not.
type ownerLookup func(ctx context.Context, releaseID string) (ReleaseOwners, error)

func (p *ScopePropagation) owners(cache map[string]ReleaseOwners) ownerLookup {
	return func(ctx context.Context, releaseID string) (ReleaseOwners, error) {
		if o, ok := cache[releaseID]; ok {
			return o, nil
		}
		own, err := p.registry.ReleaseOwners(ctx, releaseID)
		if err != nil {
			return ReleaseOwners{}, err
		}
		if own.ProductID == "" || own.ProjectID == "" {
			return ReleaseOwners{}, ErrUnresolvedReleaseIdentity
		}
		cache[releaseID] = own
		return own, nil
	}
}

// ApplyScopedPosition establishes `pos` (the source's current scoped Position) on the target:
// a proposal in the person's own name, accepted by that person in the same transaction, with
// the same terms, the scope and the source recorded as inputs (D3). The events are the ordinary
// ones, so Jira, mail, the SLA clock and the watcher see a Position like any other. Returns
// whether a Position was established; a target decided meanwhile, or already carrying this
// pair, gets nothing.
// sourceLabel names the source release for the rationale ("<project> <version>"; blank → id).
func (s *FindingService) ApplyScopedPosition(ctx context.Context, targetID domain.FindingID, source domain.Finding, sourceLabel string, pos domain.Position, level domain.RollForwardLevel) (bool, error) {
	pid := domain.ScopedProposalID(targetID, source.ID(), pos.Version())
	rationale := domain.ScopedRationale(source, sourceLabel, pos, level)
	in := pos.Inputs()
	terms := domain.AcceptanceTerms{
		ReviewBy: in.ReviewBy, Owner: in.Owner, Treatment: in.Treatment, Proof: in.Proof,
		Scope:          pos.Scope(),
		PropagatedFrom: domain.PropagationSource{FindingID: source.ID(), Version: pos.Version()},
	}
	applied := false
	err := s.mutate(ctx, targetID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		if _, decided := f.CurrentPosition(); decided {
			return nil, errNoop
		}
		// Asserted: the person stated this stance for this scope; it is their claim, not a
		// system's inference. It is accepted here and now by the same person, so no policy
		// ever sees it.
		p, err := domain.NewGovernanceProposal(pid, pos.Actor(), pos.Stance(), rationale, now, value.TrustAsserted)
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

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

// Harness integration (EDR-HARNESS-01): the three Governance acts that
// make an AI-runtime execution usable as proposal evidence —
// commission (before), withdraw, and raise a proposal on the
// reconstructed execution (after) — plus the correspondence check
// between them. Governance never reads the runtime record: the evidence
// arrives already derived by Themis's own intake CLI (D-I-1, D-C-5).

const (
	EventFindingCommissioned = "governance.finding_commissioned"
	EventCommissionWithdrawn = "governance.commission_withdrawn"
)

// ErrBusinessVerification: an evidence reference the proposal claims is
// not vouched by the Finding (EDR-TRUST-01 T8).
var ErrBusinessVerification = errors.New("governance: harness evidence reference is not vouched by the finding")

// Commission records authority to perform governed work against a
// Finding (D-C-1). The actor must be an authenticated human (D-C-6);
// the premise is captured by the aggregate; no investigation stage
// changes (D-C-4). Returns the Themis-minted commission id — the value
// the runtime will carry verbatim (D-C-5).
func (s *FindingService) Commission(ctx context.Context, findingID domain.FindingID, method domain.MethodIdentity, deployment domain.DeploymentIdentity, by domain.Actor, rationale string) (domain.CommissionID, error) {
	cid := domain.CommissionID(s.ids.NewID())
	err := s.mutate(ctx, findingID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		c, err := f.Commission(cid, method, deployment, by, rationale, now)
		if err != nil {
			return nil, err
		}
		return []OutboxNote{{EventType: EventFindingCommissioned, Event: domain.NewFindingCommissioned(*f, c, now), OccurredAt: now}}, nil
	})
	if err != nil {
		return "", err
	}
	return cid, nil
}

// WithdrawCommission is the forward-only transition (D-C-3): it affects
// future proposal admissibility only; historical executions stay
// inspectable evidence.
func (s *FindingService) WithdrawCommission(ctx context.Context, findingID domain.FindingID, id domain.CommissionID, by domain.Actor, rationale string) error {
	return s.mutate(ctx, findingID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		if err := f.WithdrawCommission(id, by, rationale, now); err != nil {
			return nil, err
		}
		return []OutboxNote{{EventType: EventCommissionWithdrawn, Event: domain.NewCommissionWithdrawn(*f, id, now), OccurredAt: now}}, nil
	})
}

// RaiseHarnessProposal raises a HUMAN proposal whose evidence basis is
// a commissioned, reconstructed harness execution (D-I-5). In causal
// order, first failure named (D-C-5 §4):
//
//	evidence shape → commission exists on THIS Finding → open →
//	method matches → deployment matches → submitted trust class equals
//	the derived class → Business Verification of the refs → raise.
//
// Governance performs equality checks only; it interprets no runtime
// identity and re-resolves nothing (D-I-1).
func (s *FindingService) RaiseHarnessProposal(ctx context.Context, findingID domain.FindingID, proposer domain.Actor, stance domain.Stance, rationale string, ev domain.HarnessExecution, submittedTrust value.TrustClass) (domain.ProposalID, error) {
	if err := ev.Validate(); err != nil {
		return "", err
	}
	if submittedTrust != ev.DerivedTrust() {
		return "", fmt.Errorf("%w: submitted %s, derived %s", domain.ErrHarnessEvidenceTrust, submittedTrust, ev.DerivedTrust())
	}
	pid := domain.ProposalID(s.ids.NewID())
	err := s.mutate(ctx, findingID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		var commission *domain.Commission
		for _, c := range f.Commissions() {
			if c.ID() == ev.CommissionID {
				cc := c
				commission = &cc
				break
			}
		}
		if commission == nil {
			return nil, fmt.Errorf("%w: %s on finding %s", domain.ErrCommissionNotFound, ev.CommissionID, f.ID())
		}
		if err := ev.Corresponds(*commission); err != nil {
			return nil, err
		}
		// Business Verification (EDR-TRUST-01 T8): the refs the proposal
		// rests on must be vouched by OUR truth. They come from the
		// recorded Finding bytes the execution read, never from the model.
		for _, ref := range ev.BusinessRefs {
			if !vouchesRef(*f, strings.TrimSpace(ref)) {
				return nil, fmt.Errorf("%w: %q", ErrBusinessVerification, ref)
			}
		}
		p, err := domain.NewHarnessProposal(pid, proposer, stance, rationale, now, ev)
		if err != nil {
			return nil, err
		}
		if err := f.RaiseProposal(p); err != nil {
			return nil, err
		}
		return []OutboxNote{{EventType: EventProposalRaised, Event: domain.NewProposalRaised(*f, p, now), OccurredAt: now}}, nil
	})
	if err != nil {
		return "", err
	}
	return pid, nil
}

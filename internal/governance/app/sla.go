package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The SLA policy and its clock (EDR-REMEDIATION-01 D1, D8 Q1/Q2/Q5, S1/S2). The arithmetic is
// domain.EvaluateSLA; this file resolves WHICH policy applies to a Finding, reads the facts the
// clock needs, and runs the sweep that announces a breach once per period. Nothing here writes
// a Finding aggregate: a breach is a reading plus an event (S1).

// EventSLABreached announces that a Finding's current SLA period ran past its due date. A fact,
// never a transition: no Position, stage or proposal changes because of it (S1).
const EventSLABreached = "governance.sla_breached"

// SLAEstateScope is the policy scope that applies to every Product without its own override.
const SLAEstateScope = ""

// ErrInvalidSLAPolicy is returned when a policy has an enforced bucket with no days, or negative
// days. Nothing is stored.
var ErrInvalidSLAPolicy = errors.New("governance: invalid SLA policy")

// SLAFacts is everything recorded about one Finding that its clock reads.
type SLAFacts struct {
	FindingID   domain.FindingID
	ReleaseID   string
	FaultlineID string
	CVE         string
	BaseScore   int
	Input       domain.SLAInput
}

// SLAPolicyRecord is one stored policy and its scope ("" = estate, else a Product id).
type SLAPolicyRecord struct {
	Scope     string
	Policy    domain.SLAPolicy
	UpdatedAt time.Time
	UpdatedBy string
}

// SLAStore is the SLA persistence seam: the policy table, the clock's facts, and the breach log.
type SLAStore interface {
	SLAPolicies(ctx context.Context) ([]SLAPolicyRecord, error)
	PutSLAPolicy(ctx context.Context, rec SLAPolicyRecord) error
	// SLAFactsForRelease returns the facts for every Finding of one Release.
	SLAFactsForRelease(ctx context.Context, releaseID string) ([]SLAFacts, error)
	// RunningSLAFacts pages through the Findings whose clock may still run (not resolved or
	// archived, not stopped by a Position), ordered by Finding id after `afterID`.
	RunningSLAFacts(ctx context.Context, afterID string, limit int) ([]SLAFacts, error)
	// RecordSLABreach writes the breach for (Finding, period) and its outbox note in one
	// transaction, once: it reports false when this period's breach was already recorded.
	RecordSLABreach(ctx context.Context, findingID domain.FindingID, periodStart time.Time, note OutboxNote) (bool, error)
}

// ProductOfRelease resolves a Release's owning Product (the Registry seam).
type ProductOfRelease interface {
	ProductAndProjectOfRelease(ctx context.Context, releaseID string) (productID, projectID string, err error)
}

// SLAService resolves policies and reads the clock.
type SLAService struct {
	store    SLAStore
	identity ProductOfRelease // may be nil: every Finding then reads the estate policy
	clock    Clock
}

// NewSLAService wires the SLA service.
func NewSLAService(store SLAStore, identity ProductOfRelease, clock Clock) *SLAService {
	return &SLAService{store: store, identity: identity, clock: clock}
}

// SLAPolicySet is the estate policy plus the per-Product overrides.
type SLAPolicySet struct {
	Estate    SLAPolicyRecord
	Overrides []SLAPolicyRecord
}

// Policies returns the estate policy (the Q5 defaults when none is stored) and the overrides.
func (s *SLAService) Policies(ctx context.Context) (SLAPolicySet, error) {
	recs, err := s.store.SLAPolicies(ctx)
	if err != nil {
		return SLAPolicySet{}, err
	}
	out := SLAPolicySet{Estate: SLAPolicyRecord{Scope: SLAEstateScope, Policy: domain.DefaultSLAPolicy()}}
	for _, r := range recs {
		if r.Scope == SLAEstateScope {
			out.Estate = r
			continue
		}
		out.Overrides = append(out.Overrides, r)
	}
	return out, nil
}

// PutPolicy stores the estate policy (scope "") or one Product's override.
func (s *SLAService) PutPolicy(ctx context.Context, scope string, p domain.SLAPolicy, actor string) (SLAPolicyRecord, error) {
	if !p.Valid() {
		return SLAPolicyRecord{}, ErrInvalidSLAPolicy
	}
	rec := SLAPolicyRecord{Scope: strings.TrimSpace(scope), Policy: p, UpdatedAt: s.clock.Now(), UpdatedBy: actor}
	if err := s.store.PutSLAPolicy(ctx, rec); err != nil {
		return SLAPolicyRecord{}, err
	}
	return rec, nil
}

// policyFor picks a Product's override, else the estate policy. An unresolvable Product (no
// Registry seam, or Registry down) reads the estate policy: a deadline is still shown, and the
// sweep may announce against the estate table until the Product resolves.
func (s *SLAService) policyFor(ctx context.Context, set SLAPolicySet, releaseID string) domain.SLAPolicy {
	if s.identity == nil || len(set.Overrides) == 0 {
		return set.Estate.Policy
	}
	productID, _, err := s.identity.ProductAndProjectOfRelease(ctx, releaseID)
	if err != nil {
		return set.Estate.Policy
	}
	for _, o := range set.Overrides {
		if o.Scope == productID {
			return o.Policy
		}
	}
	return set.Estate.Policy
}

// ReleaseStatus reads the clock for every Finding of one Release.
func (s *SLAService) ReleaseStatus(ctx context.Context, releaseID string) (map[domain.FindingID]domain.SLAStatus, error) {
	set, err := s.Policies(ctx)
	if err != nil {
		return nil, err
	}
	facts, err := s.store.SLAFactsForRelease(ctx, releaseID)
	if err != nil {
		return nil, err
	}
	policy := s.policyFor(ctx, set, releaseID)
	now := s.clock.Now()
	out := make(map[domain.FindingID]domain.SLAStatus, len(facts))
	for _, f := range facts {
		out[f.FindingID] = domain.EvaluateSLA(f.Input, policy, now)
	}
	return out, nil
}

// SLASweepBatch bounds one page of the sweep.
const SLASweepBatch = 500

// SweepBreaches pages through every running clock and records one breach per (Finding, period)
// that has passed its due date. It reports how many clocks it read and how many breaches it
// announced. It writes the breach log and the outbox only (S1).
func (s *SLAService) SweepBreaches(ctx context.Context) (checked, breached int, err error) {
	set, err := s.Policies(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("read SLA policies: %w", err)
	}
	policies := map[string]domain.SLAPolicy{} // per release, one Registry read per pass
	after := ""
	for {
		page, err := s.store.RunningSLAFacts(ctx, after, SLASweepBatch)
		if err != nil {
			return checked, breached, fmt.Errorf("list running SLA clocks: %w", err)
		}
		for _, f := range page {
			if err := ctx.Err(); err != nil {
				return checked, breached, err
			}
			checked++
			p, ok := policies[f.ReleaseID]
			if !ok {
				p = s.policyFor(ctx, set, f.ReleaseID)
				policies[f.ReleaseID] = p
			}
			now := s.clock.Now()
			st := domain.EvaluateSLA(f.Input, p, now)
			if st.State != domain.SLABreached {
				continue
			}
			ev := domain.SLABreachedEvent{
				FindingID: f.FindingID, ReleaseID: f.ReleaseID, FaultlineID: f.FaultlineID, CVE: f.CVE,
				Bucket: st.Bucket, PeriodStart: st.PeriodStart, Due: st.Due, KEVDueApplied: st.KEVDueApplied,
				OccurredAt: now,
			}
			recorded, err := s.store.RecordSLABreach(ctx, f.FindingID, st.PeriodStart,
				OutboxNote{EventType: EventSLABreached, Event: ev, OccurredAt: now})
			if err != nil {
				return checked, breached, fmt.Errorf("record SLA breach %s: %w", f.FindingID, err)
			}
			if recorded {
				breached++
			}
		}
		if len(page) < SLASweepBatch {
			return checked, breached, nil
		}
		after = string(page[len(page)-1].FindingID)
	}
}

// RunEvery runs the breach sweep on a cadence until ctx is cancelled.
func (s *SLAService) RunEvery(ctx context.Context, every time.Duration, report func(checked, breached int, err error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, n, err := s.SweepBreaches(ctx)
			if report != nil {
				report(c, n, err)
			}
		}
	}
}

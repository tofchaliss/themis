package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// maxSaveRetries bounds FoldProposal's optimistic-concurrency retry loop. Additive
// folds always converge, but each contended round lets only one version-guarded save
// win, so N concurrent folds of the same CVE need up to N attempts for the last writer.
// Sized well above realistic same-CVE concurrency (a handful of feeds); a pathological
// herd still surfaces ErrConcurrent rather than spinning forever.
const maxSaveRetries = 50

// FaultlineService orchestrates the Knowledge write use cases over its ports.
type FaultlineService struct {
	repo  Repository
	ids   IDGenerator
	clock Clock
	prec  domain.Precedence
	trust domain.TrustPolicy
}

// NewFaultlineService wires the use-case ports, the reconciliation precedence policy, and
// the source→trust-class policy (EDR-TRUST-01 T2). Both tables are injected rather than
// hard-coded: the domain owns the mechanism, the composition root owns the table.
func NewFaultlineService(
	repo Repository, ids IDGenerator, clock Clock, prec domain.Precedence, trust domain.TrustPolicy,
) *FaultlineService {
	return &FaultlineService{repo: repo, ids: ids, clock: clock, prec: prec, trust: trust}
}

// SupersedeFaultline retires the card for a CVE that has been WITHDRAWN or REJECTED upstream
// (D7 — a card is never deleted, only superseded).
//
// It closes the producer half of a path whose consumer half was already complete: the event type
// was registered, its v1 payload schema frozen, and Governance's coordinator turned it into a
// re-evaluation signal — but nothing in Knowledge ever called Supersede(), so a rejected CVE kept
// its card and its Finding kept demanding triage indefinitely. Observed live 2026-08-07:
// CVE-2021-20095 carries NVD `vulnStatus: "Rejected"` and was still open.
//
// found=false for a CVE with no card — a source may report a withdrawal for something the
// enterprise never held, which is not an error and not work.
//
// Idempotent: the lifecycle is forward-only, so superseding an already-superseded card changes
// nothing and emits nothing. A re-delivery or a repeated sweep is therefore free.
// source names who reported the withdrawal; its trust class is classified here and carried on the
// event (TRUST-4) so Governance reads the real provenance instead of assuming one.
func (s *FaultlineService) SupersedeFaultline(ctx context.Context, cve value.CVEID, source string) (bool, error) {
	if cve.IsZero() {
		return false, fmt.Errorf("knowledge: zero cve")
	}
	trust := s.trust.ClassOf(source)
	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		f, found, err := s.repo.GetByCVE(ctx, cve.String())
		if err != nil {
			return false, err
		}
		if !found {
			return false, nil
		}
		prevVersion := f.Version()
		if !f.Supersede() {
			return false, nil // already terminal — nothing changed, nothing to announce
		}
		now := s.clock.Now()
		notes := []OutboxNote{{
			EventType:  EventFaultlineSuperseded,
			Event:      domain.NewFaultlineSuperseded(f, trust, now),
			OccurredAt: now,
		}}
		switch err := s.repo.Save(ctx, f, false, prevVersion, notes); {
		case err == nil:
			return true, nil
		case errors.Is(err, ErrConcurrent):
			continue
		default:
			return false, err
		}
	}
	return false, ErrConcurrent
}

// FoldProposal finds-or-creates the Faultline for a canonical CVE and folds a source
// Proposal into it, reconciling the enterprise view and publishing completed-fact
// events on state change (D2/D8/D9). It retries on optimistic-concurrency conflicts,
// which converge because Proposals are additive and reconciliation is deterministic. It
// returns the folded aggregate so the caller can read the reconciled view (e.g.
// correlation gating a match against the reconciled affected range — D3).
// The bool reports whether the Proposal was RECORDED. A source restating itself verbatim is
// dropped (KN-PROPOSAL-BLOAT-1), and a sweep that counts its work must not count those: a feed
// writing nothing would otherwise log the same number as one doing full work, which is how a
// stalled feed comes to look healthy.
func (s *FaultlineService) FoldProposal(ctx context.Context, cve value.CVEID, p domain.Proposal) (domain.Faultline, bool, error) {
	if cve.IsZero() {
		return domain.Faultline{}, false, fmt.Errorf("knowledge: zero cve")
	}
	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		existing, found, err := s.repo.GetByCVE(ctx, cve.String())
		if err != nil {
			return domain.Faultline{}, false, err
		}
		now := s.clock.Now()

		var (
			f           domain.Faultline
			created     bool
			prevVersion int
			notes       []OutboxNote
		)
		if found {
			f = existing
			prevVersion = f.Version()
		} else {
			f, err = domain.NewFaultline(domain.FaultlineID(s.ids.NewID()), cve)
			if err != nil {
				return domain.Faultline{}, false, err
			}
			created = true
			notes = append(notes, OutboxNote{EventType: EventFaultlineCreated, Event: domain.NewFaultlineCreated(f, now), OccurredAt: now})
		}

		res := f.FoldProposal(p, s.prec, s.trust)
		if res.ViewChanged {
			notes = append(notes, OutboxNote{EventType: EventFaultlineEnriched, Event: domain.NewFaultlineEnriched(f, now), OccurredAt: now})
		}

		switch err := s.repo.Save(ctx, f, created, prevVersion, notes); {
		case err == nil:
			return f, res.Recorded, nil
		case errors.Is(err, ErrConcurrent):
			continue // reload and retry; additive folds converge
		default:
			return domain.Faultline{}, false, err
		}
	}
	return domain.Faultline{}, false, ErrConcurrent
}

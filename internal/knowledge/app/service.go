package app

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// matches is optional (nil = no re-announcement). It exists so a card that gains carrier
	// attribution after correlation can correct the classes already stamped on its matches.
	matches MatchReader
}

// WithMatchReader wires the optional match reader and returns the service for chaining. Kept off
// the constructor so every existing caller is unaffected; without it the service behaves exactly
// as before, which is the correct degradation for single-context dev.
func (s *FaultlineService) WithMatchReader(m MatchReader) *FaultlineService {
	s.matches = m
	return s
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
// reannounceMatches builds a ComponentMatched note per recorded occurrence of a card, carrying the
// freshly-computed claim class. No-op when no match reader is wired (single-context dev).
func (s *FaultlineService) reannounceMatches(ctx context.Context, f domain.Faultline, now time.Time) ([]OutboxNote, error) {
	if s.matches == nil {
		return nil, nil
	}
	occ, err := s.matches.MatchesForFaultline(ctx, string(f.ID()))
	if err != nil {
		return nil, err
	}
	view := f.View()
	notes := make([]OutboxNote, 0, len(occ))
	for _, o := range occ {
		comp := domain.MatchedComponent{
			PURL: o.Component.PURL, Name: o.Component.Name, Version: o.Component.Version,
			Ecosystem: o.Component.Ecosystem, Source: o.Component.Source,
			ClaimClass: domain.ClassifyClaim(view.CarrierProducts, componentPackage(o.Component), o.Component.Name),
		}
		ev := domain.NewComponentMatched(f, o.ReleaseID, []domain.MatchedComponent{comp}, now)
		notes = append(notes, OutboxNote{EventType: EventComponentMatched, Event: ev, OccurredAt: now})
	}
	return notes, nil
}

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

		hadCarriers := len(f.View().CarrierProducts) > 0
		res := f.FoldProposal(p, s.prec, s.trust)
		if res.ViewChanged {
			notes = append(notes, OutboxNote{EventType: EventFaultlineEnriched, Event: domain.NewFaultlineEnriched(f, now), OccurredAt: now})
		}
		// Carrier attribution arriving for the first time RE-ANNOUNCES this card's existing
		// matches (EDR-CORRELATION-01 D3/D4).
		//
		// Classification happens at correlation, but the evidence for it — NVD's CPE products —
		// arrives on NVD's own cadence, which is usually LATER. Without this the class stamped at
		// match time is the one that lasts: on a stable estate no new correlation ever runs, so
		// every component would stay `unknown` forever and step 2 would be inert. Measured on the
		// VM: 370 components, all unknown, while the cards were being enriched around them.
		//
		// Scoped to the empty→non-empty transition so it fires ONCE per card rather than on every
		// enrichment, and it is idempotent downstream: Governance's upsert only overwrites a class
		// with a non-empty one, and re-delivering a match adds no component.
		if !hadCarriers && len(f.View().CarrierProducts) > 0 {
			more, rerr := s.reannounceMatches(ctx, f, now)
			if rerr != nil {
				return domain.Faultline{}, false, rerr
			}
			notes = append(notes, more...)
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

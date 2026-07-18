package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

const maxSaveRetries = 5

// FaultlineService orchestrates the Knowledge write use cases over its ports.
type FaultlineService struct {
	repo  Repository
	ids   IDGenerator
	clock Clock
	prec  domain.Precedence
}

// NewFaultlineService wires the use-case ports and the reconciliation precedence policy.
func NewFaultlineService(repo Repository, ids IDGenerator, clock Clock, prec domain.Precedence) *FaultlineService {
	return &FaultlineService{repo: repo, ids: ids, clock: clock, prec: prec}
}

// FoldProposal finds-or-creates the Faultline for a canonical CVE and folds a source
// Proposal into it, reconciling the enterprise view and publishing completed-fact
// events on state change (D2/D8/D9). It retries on optimistic-concurrency conflicts,
// which converge because Proposals are additive and reconciliation is deterministic.
func (s *FaultlineService) FoldProposal(ctx context.Context, cve value.CVEID, p domain.Proposal) (domain.FaultlineID, error) {
	if cve.IsZero() {
		return "", fmt.Errorf("knowledge: zero cve")
	}
	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		existing, found, err := s.repo.GetByCVE(ctx, cve.String())
		if err != nil {
			return "", err
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
				return "", err
			}
			created = true
			notes = append(notes, OutboxNote{EventType: EventFaultlineCreated, Event: domain.NewFaultlineCreated(f, now), OccurredAt: now})
		}

		if res := f.FoldProposal(p, s.prec); res.ViewChanged {
			notes = append(notes, OutboxNote{EventType: EventFaultlineEnriched, Event: domain.NewFaultlineEnriched(f, now), OccurredAt: now})
		}

		switch err := s.repo.Save(ctx, f, created, prevVersion, notes); {
		case err == nil:
			return f.ID(), nil
		case errors.Is(err, ErrConcurrent):
			continue // reload and retry; additive folds converge
		default:
			return "", err
		}
	}
	return "", ErrConcurrent
}

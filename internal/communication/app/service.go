package app

import (
	"context"
	"errors"

	"github.com/themis-project/themis/internal/communication/domain"
)

const maxSaveRetries = 5

// PublicationService orchestrates the Communication write use cases over its ports. It never
// invents authority: it materializes an Enterprise Position into an artifact only on an
// explicit human trigger (D4), and the artifact's stance is fixed by the Position (D3).
type PublicationService struct {
	repo        Repository
	positions   PositionReader
	serializers Serializers
	ids         IDGenerator
	clock       Clock
}

// NewPublicationService wires the use-case ports.
func NewPublicationService(repo Repository, positions PositionReader, serializers Serializers, ids IDGenerator, clock Clock) *PublicationService {
	return &PublicationService{repo: repo, positions: positions, serializers: serializers, ids: ids, clock: clock}
}

// CreatePublication is the human-triggered publish flow (D4): fetch the Enterprise Position
// from Governance's read API (D2), materialize it into the chosen artifact type (D3),
// serialize it (D7), record an immutable Publication, and supersede the prior current
// Publication for the same (Release, Faultline, artifact-type, audience) if any (D5) — all
// atomically. Delivery is decoupled (the recorded Pending Publication is the durable delivery
// intent — D6). Retries on optimistic-concurrency conflicts.
func (s *PublicationService) CreatePublication(ctx context.Context, findingID string, typ domain.ArtifactType, format, audience, channel string) (domain.PublicationID, error) {
	snap, found, err := s.positions.GetPosition(ctx, findingID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrPositionNotFound
	}
	art, err := domain.Materialize(snap, typ)
	if err != nil {
		return "", err
	}
	payload, err := s.serializers.Render(format, art)
	if err != nil {
		return "", err
	}

	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		now := s.clock.Now()
		prior, hasPrior, err := s.repo.CurrentPublication(ctx, snap.Lineage.ReleaseID, snap.Lineage.FaultlineID, typ, audience)
		if err != nil {
			return "", err
		}

		pubID := domain.PublicationID(s.ids.NewID())
		var supersedesID domain.PublicationID
		if hasPrior {
			supersedesID = prior.ID()
		}
		pub, err := domain.NewPublication(pubID, art, format, audience, channel, payload, supersedesID, now)
		if err != nil {
			return "", err
		}
		notes := []OutboxNote{{EventType: EventPublicationCreated, Event: domain.NewPublicationCreated(pub, now), OccurredAt: now}}

		var priorPtr *domain.Publication
		priorPrev := 0
		if hasPrior {
			priorPrev = prior.Version()
			if err := prior.Supersede(pubID); err != nil {
				return "", err
			}
			priorPtr = &prior
			notes = append(notes, OutboxNote{EventType: EventPublicationSuperseded, Event: domain.NewPublicationSuperseded(prior, now), OccurredAt: now})
		}

		switch err := s.repo.Save(ctx, pub, priorPtr, priorPrev, notes); {
		case err == nil:
			return pubID, nil
		case errors.Is(err, ErrConcurrent):
			continue // a concurrent re-publish superseded the prior first — reload and retry
		default:
			return "", err
		}
	}
	return "", ErrConcurrent
}

// RecordPublishable updates the publishable-positions worklist projection from an inbound
// Position event (D2/D4): a new Position is ready to publish; a revised one is marked stale
// (re-publish needed — D5). It never auto-materializes (D4).
func (s *PublicationService) RecordPublishable(ctx context.Context, snap domain.PositionSnapshot, stale bool) error {
	return s.repo.MarkPublishable(ctx, QueueEntry{
		FindingID:   snap.FindingID,
		ReleaseID:   snap.Lineage.ReleaseID,
		FaultlineID: snap.Lineage.FaultlineID,
		CVE:         snap.Lineage.CVE,
		Version:     snap.Version,
		Stance:      snap.Stance,
		Stale:       stale,
	})
}

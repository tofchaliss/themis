package app

import (
	"context"

	"github.com/themis-project/themis/internal/communication/domain"
)

// ReadService serves the Communication read side (D10): single-Publication / list reads from
// the aggregate store (with on-the-fly payload regeneration when pruned), the analyst
// worklist, and a non-recording preview.
type ReadService struct {
	repo        Repository
	positions   PositionReader
	serializers Serializers
}

// NewReadService wires the read service.
func NewReadService(repo Repository, positions PositionReader, serializers Serializers) *ReadService {
	return &ReadService{repo: repo, positions: positions, serializers: serializers}
}

// GetPublication returns a Publication and its payload bytes. If the payload was pruned by
// retention (D1), it is regenerated deterministically from the persisted artifact + the
// serializer — identical bytes, no re-fetch of Governance state needed.
func (s *ReadService) GetPublication(ctx context.Context, id domain.PublicationID) (domain.Publication, []byte, error) {
	pub, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return domain.Publication{}, nil, err
	}
	if !pub.PayloadPruned() {
		return pub, pub.Payload(), nil
	}
	payload, err := s.serializers.Render(pub.Format(), pub.Artifact())
	if err != nil {
		return domain.Publication{}, nil, err
	}
	return pub, payload, nil
}

// ListByRelease returns all Publications for a Release, newest first (D10).
func (s *ReadService) ListByRelease(ctx context.Context, releaseID string) ([]domain.Publication, error) {
	return s.repo.ListByRelease(ctx, releaseID)
}

// PublishableQueue returns the analyst worklist projection — Positions ready to publish or
// gone stale (D4/D10).
func (s *ReadService) PublishableQueue(ctx context.Context) ([]QueueEntry, error) {
	return s.repo.PublishableQueue(ctx)
}

// Preview renders a Position into an artifact WITHOUT recording a Publication (D10) — a live
// read path, distinct from an act of publication. It fetches the Position, materializes, and
// serializes; found=false when the Finding has no current Position.
func (s *ReadService) Preview(ctx context.Context, findingID string, typ domain.ArtifactType, format string) ([]byte, bool, error) {
	snap, found, err := s.positions.GetPosition(ctx, findingID)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	art, err := domain.Materialize(snap, typ)
	if err != nil {
		return nil, false, err
	}
	payload, err := s.serializers.Render(format, art)
	if err != nil {
		return nil, false, err
	}
	return payload, true, nil
}

package app

import (
	"context"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// GetEvidence returns the Evidence facts (kind, subject, fingerprint, provenance,
// trust, filed-at) by id.
func (s *EvidenceService) GetEvidence(ctx context.Context, id domain.EvidenceID) (domain.Evidence, error) {
	return s.repo.GetByID(ctx, id)
}

// GetInventory returns the canonical component inventory by id — the read path
// downstream contexts use after EvidenceRegistered (D6).
func (s *EvidenceService) GetInventory(ctx context.Context, id domain.EvidenceID) (domain.Inventory, error) {
	return s.repo.GetInventory(ctx, id)
}

// ListByRelease returns evidence summaries filed against a release, newest first.
func (s *EvidenceService) ListByRelease(ctx context.Context, releaseID string) ([]EvidenceSummary, error) {
	return s.repo.ListByRelease(ctx, releaseID)
}

package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/registry/domain"
)

// Security requirements CR / IR / AR (EDR-SCORING-01 4.4, S3).

// ErrRequirementsUnavailable is returned when no requirement store is wired.
var ErrRequirementsUnavailable = errors.New("registry: security requirements are not enabled on this node")

// RequirementStore is the append-only requirement store.
type RequirementStore interface {
	// AppendRequirement records one change.
	AppendRequirement(ctx context.Context, r domain.RequirementRecord) error
	// RequirementHistory lists one entity's records, newest first.
	RequirementHistory(ctx context.Context, level domain.RequirementLevel, id string) ([]domain.RequirementRecord, error)
}

// WithRequirements wires the requirement store and the clock that stamps each change.
func (s *RegistryService) WithRequirements(store RequirementStore, now func() time.Time) *RegistryService {
	s.reqs, s.clock = store, now
	return s
}

// RequirementChange is one requested change at one level.
type RequirementChange struct {
	CR, IR, AR    string
	Reason, Actor string
	Via           string
}

// SetRequirements records a change of one entity's requirements and returns the record.
func (s *RegistryService) SetRequirements(ctx context.Context, level domain.RequirementLevel, id string, c RequirementChange) (domain.RequirementRecord, error) {
	if s.reqs == nil {
		return domain.RequirementRecord{}, ErrRequirementsUnavailable
	}
	rec, err := domain.NewRequirementRecord(level, id, c.CR, c.IR, c.AR, c.Reason, c.Actor, c.Via, s.clock())
	if err != nil {
		return domain.RequirementRecord{}, err
	}
	if err := s.exists(ctx, level, id); err != nil {
		return domain.RequirementRecord{}, err
	}
	if err := s.reqs.AppendRequirement(ctx, rec); err != nil {
		return domain.RequirementRecord{}, err
	}
	return rec, nil
}

// RequirementHistory lists one entity's recorded changes, newest first.
func (s *RegistryService) RequirementHistory(ctx context.Context, level domain.RequirementLevel, id string) ([]domain.RequirementRecord, error) {
	if s.reqs == nil {
		return nil, ErrRequirementsUnavailable
	}
	if err := s.exists(ctx, level, id); err != nil {
		return nil, err
	}
	return s.reqs.RequirementHistory(ctx, level, id)
}

func (s *RegistryService) currentRequirement(ctx context.Context, level domain.RequirementLevel, id string) (*domain.RequirementRecord, error) {
	h, err := s.reqs.RequirementHistory(ctx, level, id)
	if err != nil || len(h) == 0 {
		return nil, err
	}
	return &h[0], nil
}

// ReleaseRequirements are a release's resolved requirements and the current record of each
// level they were resolved from.
type ReleaseRequirements struct {
	Resolved                  domain.ResolvedRequirements
	Release, Project, Product *domain.RequirementRecord
}

// ResolvedRequirements resolves CR, IR and AR for a release, each metric on its own: Release,
// then Project, then Product, then X.
func (s *RegistryService) ResolvedRequirements(ctx context.Context, releaseID string) (ReleaseRequirements, error) {
	if s.reqs == nil {
		return ReleaseRequirements{}, ErrRequirementsUnavailable
	}
	if err := s.exists(ctx, domain.TagRelease, releaseID); err != nil {
		return ReleaseRequirements{}, err
	}
	rel, err := s.repo.GetRelease(ctx, domain.ReleaseID(releaseID))
	if err != nil {
		return ReleaseRequirements{}, err
	}
	proj, err := s.repo.GetProject(ctx, rel.ProjectID())
	if err != nil {
		return ReleaseRequirements{}, err
	}
	var out ReleaseRequirements
	for _, l := range []struct {
		dst   **domain.RequirementRecord
		level domain.RequirementLevel
		id    string
	}{
		{&out.Release, domain.TagRelease, releaseID},
		{&out.Project, domain.TagProject, string(proj.ID())},
		{&out.Product, domain.TagProduct, string(proj.ProductID())},
	} {
		if *l.dst, err = s.currentRequirement(ctx, l.level, l.id); err != nil {
			return ReleaseRequirements{}, err
		}
	}
	out.Resolved = domain.ResolveRequirements(out.Release, out.Project, out.Product)
	return out, nil
}

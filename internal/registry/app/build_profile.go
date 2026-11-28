package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/registry/domain"
)

// The build profile (EDR-REBUILD-01 D10, D16; step R2a). Registry stores it and answers which
// one applies to a Release. It reads nothing inside it and starts nothing.

var (
	// ErrBuildProfilesUnavailable is returned when no build profile store is wired.
	ErrBuildProfilesUnavailable = errors.New("registry: build profiles are not enabled on this node")
	// ErrNoBuildProfile is returned when the profile to remove does not exist.
	ErrNoBuildProfile = errors.New("registry: no build profile is stored at this level")
)

// BuildProfileStore is the append-only build profile store.
type BuildProfileStore interface {
	// AppendBuildProfile records one change as the entity's next revision and returns the
	// record with that revision set.
	AppendBuildProfile(ctx context.Context, r domain.BuildProfileRecord) (domain.BuildProfileRecord, error)
	// BuildProfileHistory lists one entity's records, newest first.
	BuildProfileHistory(ctx context.Context, level domain.BuildProfileLevel, id string) ([]domain.BuildProfileRecord, error)
}

// WithBuildProfiles wires the build profile store and the clock that stamps each change.
func (s *RegistryService) WithBuildProfiles(store BuildProfileStore, now func() time.Time) *RegistryService {
	s.profiles, s.profileClock = store, now
	return s
}

// SetBuildProfile records a new profile value for a Project or a Release.
func (s *RegistryService) SetBuildProfile(ctx context.Context, level domain.BuildProfileLevel, id string, raw []byte, actor, via string) (domain.BuildProfileRecord, error) {
	if s.profiles == nil {
		return domain.BuildProfileRecord{}, ErrBuildProfilesUnavailable
	}
	rec, err := domain.NewBuildProfileRecord(level, id, raw, actor, via, s.profileClock())
	if err != nil {
		return domain.BuildProfileRecord{}, err
	}
	if err := s.exists(ctx, level, id); err != nil {
		return domain.BuildProfileRecord{}, err
	}
	return s.profiles.AppendBuildProfile(ctx, rec)
}

// RemoveBuildProfile records the removal of a level's profile. A Release then takes its
// Project's again. ErrNoBuildProfile when the level states none.
func (s *RegistryService) RemoveBuildProfile(ctx context.Context, level domain.BuildProfileLevel, id, actor, via string) (domain.BuildProfileRecord, error) {
	if s.profiles == nil {
		return domain.BuildProfileRecord{}, ErrBuildProfilesUnavailable
	}
	rec, err := domain.NewBuildProfileRemoval(level, id, actor, via, s.profileClock())
	if err != nil {
		return domain.BuildProfileRecord{}, err
	}
	if err := s.exists(ctx, level, id); err != nil {
		return domain.BuildProfileRecord{}, err
	}
	cur, err := s.currentBuildProfile(ctx, level, id)
	if err != nil {
		return domain.BuildProfileRecord{}, err
	}
	if cur == nil || cur.Removed {
		return domain.BuildProfileRecord{}, ErrNoBuildProfile
	}
	return s.profiles.AppendBuildProfile(ctx, rec)
}

// BuildProfileHistory lists one entity's recorded changes, newest first.
func (s *RegistryService) BuildProfileHistory(ctx context.Context, level domain.BuildProfileLevel, id string) ([]domain.BuildProfileRecord, error) {
	if s.profiles == nil {
		return nil, ErrBuildProfilesUnavailable
	}
	if level != domain.TagProject && level != domain.TagRelease {
		return nil, domain.ErrInvalidBuildProfile
	}
	if err := s.exists(ctx, level, id); err != nil {
		return nil, err
	}
	return s.profiles.BuildProfileHistory(ctx, level, id)
}

func (s *RegistryService) currentBuildProfile(ctx context.Context, level domain.BuildProfileLevel, id string) (*domain.BuildProfileRecord, error) {
	h, err := s.profiles.BuildProfileHistory(ctx, level, id)
	if err != nil || len(h) == 0 {
		return nil, err
	}
	return &h[0], nil
}

// ReleaseBuildProfile is the profile that applies to one Release.
type ReleaseBuildProfile struct {
	ReleaseID string
	ProjectID string
	// Found is false when neither the Release nor its Project states a profile.
	Found bool
	// Record is the profile in force; its Level says where it came from (D16 scope).
	Record domain.BuildProfileRecord
}

// ResolvedBuildProfile answers which profile applies to a Release: its own, else its Project's.
func (s *RegistryService) ResolvedBuildProfile(ctx context.Context, releaseID string) (ReleaseBuildProfile, error) {
	if s.profiles == nil {
		return ReleaseBuildProfile{}, ErrBuildProfilesUnavailable
	}
	if err := s.exists(ctx, domain.TagRelease, releaseID); err != nil {
		return ReleaseBuildProfile{}, err
	}
	rel, err := s.repo.GetRelease(ctx, domain.ReleaseID(releaseID))
	if err != nil {
		return ReleaseBuildProfile{}, err
	}
	projectID := string(rel.ProjectID())
	own, err := s.currentBuildProfile(ctx, domain.TagRelease, releaseID)
	if err != nil {
		return ReleaseBuildProfile{}, err
	}
	inherited, err := s.currentBuildProfile(ctx, domain.TagProject, projectID)
	if err != nil {
		return ReleaseBuildProfile{}, err
	}
	out := ReleaseBuildProfile{ReleaseID: releaseID, ProjectID: projectID}
	out.Record, out.Found = domain.ResolveBuildProfile(own, inherited)
	return out, nil
}

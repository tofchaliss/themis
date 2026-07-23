package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/registry/domain"
)

// ErrUnknownProduct is returned when registering a Project against a Product that does
// not exist; ErrUnknownProject likewise for a Release against a missing Project.
var (
	ErrUnknownProduct = errors.New("registry: unknown product")
	ErrUnknownProject = errors.New("registry: unknown project")
)

// RegistryService orchestrates the registry use cases over its ports.
type RegistryService struct {
	repo Repository
	ids  IDGenerator
}

// NewRegistryService wires the use-case ports.
func NewRegistryService(repo Repository, ids IDGenerator) *RegistryService {
	return &RegistryService{repo: repo, ids: ids}
}

// RegisterProduct creates a Product and returns its new stable id.
func (s *RegistryService) RegisterProduct(ctx context.Context, name string) (domain.ProductID, error) {
	p, err := domain.NewProduct(domain.ProductID(s.ids.NewID()), name)
	if err != nil {
		return "", err
	}
	if err := s.repo.SaveProduct(ctx, p); err != nil {
		return "", err
	}
	return p.ID(), nil
}

// RegisterProject creates a Project under an existing Product. Unknown product → error.
func (s *RegistryService) RegisterProject(ctx context.Context, product domain.ProductID, name string) (domain.ProjectID, error) {
	ok, err := s.repo.ProductExists(ctx, string(product))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownProduct, product)
	}
	p, err := domain.NewProject(domain.ProjectID(s.ids.NewID()), product, name)
	if err != nil {
		return "", err
	}
	if err := s.repo.SaveProject(ctx, p); err != nil {
		return "", err
	}
	return p.ID(), nil
}

// RegisterRelease creates a Release under an existing Project. Unknown project → error.
func (s *RegistryService) RegisterRelease(ctx context.Context, project domain.ProjectID, version string) (domain.ReleaseID, error) {
	ok, err := s.repo.ProjectExists(ctx, string(project))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownProject, project)
	}
	r, err := domain.NewRelease(domain.ReleaseID(s.ids.NewID()), project, version)
	if err != nil {
		return "", err
	}
	if err := s.repo.SaveRelease(ctx, r); err != nil {
		return "", err
	}
	return r.ID(), nil
}

// ReleaseExists reports whether a Release with the given id exists. It backs Evidence's
// SubjectRef validation (EDR-EVIDENCE-01 D5).
func (s *RegistryService) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return s.repo.ReleaseExists(ctx, releaseID)
}

// GetRelease loads a Release by id.
func (s *RegistryService) GetRelease(ctx context.Context, id domain.ReleaseID) (domain.Release, error) {
	return s.repo.GetRelease(ctx, id)
}

// ListReleases returns the Releases belonging to a Project.
func (s *RegistryService) ListReleases(ctx context.Context, project domain.ProjectID) ([]domain.Release, error) {
	return s.repo.ListReleases(ctx, project)
}

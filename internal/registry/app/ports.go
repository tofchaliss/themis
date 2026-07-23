package app

import (
	"context"

	"github.com/themis-project/themis/internal/registry/domain"
)

// Repository persists and reads the registry aggregates (implemented by adapters/store).
type Repository interface {
	SaveProduct(ctx context.Context, p domain.Product) error
	SaveProject(ctx context.Context, p domain.Project) error
	SaveRelease(ctx context.Context, r domain.Release) error

	GetRelease(ctx context.Context, id domain.ReleaseID) (domain.Release, error)
	ListReleases(ctx context.Context, project domain.ProjectID) ([]domain.Release, error)

	// Existence checks back membership validation and Evidence's SubjectRef. They
	// take opaque string ids so callers need not construct a typed id first.
	ProductExists(ctx context.Context, productID string) (bool, error)
	ProjectExists(ctx context.Context, projectID string) (bool, error)
	ReleaseExists(ctx context.Context, releaseID string) (bool, error)
}

// IDGenerator assigns new opaque aggregate identities (backed by kernel/id in the
// composition root, keeping the app free of that dependency for tests).
type IDGenerator interface {
	NewID() string
}

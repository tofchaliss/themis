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

	// Estate graph (C1 — EDR-ESTATE-01): Product → Microservice → Deployment → Customer,
	// and the traversal that counts unique customers reached from a release.
	SaveCustomer(ctx context.Context, c domain.Customer) error
	SaveMicroservice(ctx context.Context, m domain.Microservice) error
	SaveDeployment(ctx context.Context, d domain.Deployment) error
	MicroserviceExists(ctx context.Context, microserviceID string) (bool, error)
	CustomerExists(ctx context.Context, customerID string) (bool, error)
	BlastRadiusCustomers(ctx context.Context, releaseID string) (int, error)
}

// IDGenerator assigns new opaque aggregate identities (backed by kernel/id in the
// composition root, keeping the app free of that dependency for tests).
type IDGenerator interface {
	NewID() string
}

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
	ErrUnknownProduct      = errors.New("registry: unknown product")
	ErrUnknownProject      = errors.New("registry: unknown project")
	ErrUnknownMicroservice = errors.New("registry: unknown microservice")
	ErrUnknownCustomer     = errors.New("registry: unknown customer")
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

// --- estate graph (C1 — EDR-ESTATE-01) -------------------------------------

// RegisterCustomer creates a Customer and returns its new stable id.
func (s *RegistryService) RegisterCustomer(ctx context.Context, name string) (domain.CustomerID, error) {
	c, err := domain.NewCustomer(domain.CustomerID(s.ids.NewID()), name)
	if err != nil {
		return "", err
	}
	if err := s.repo.SaveCustomer(ctx, c); err != nil {
		return "", err
	}
	return c.ID(), nil
}

// RegisterMicroservice creates a Microservice under an existing Product. Unknown product → error.
func (s *RegistryService) RegisterMicroservice(ctx context.Context, product domain.ProductID, name string) (domain.MicroserviceID, error) {
	ok, err := s.repo.ProductExists(ctx, string(product))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownProduct, product)
	}
	m, err := domain.NewMicroservice(domain.MicroserviceID(s.ids.NewID()), product, name)
	if err != nil {
		return "", err
	}
	if err := s.repo.SaveMicroservice(ctx, m); err != nil {
		return "", err
	}
	return m.ID(), nil
}

// RegisterDeployment places an existing Microservice into an environment for an existing
// Customer. Unknown microservice or customer → error.
func (s *RegistryService) RegisterDeployment(ctx context.Context, microservice domain.MicroserviceID, customer domain.CustomerID, environment string) (domain.DeploymentID, error) {
	ok, err := s.repo.MicroserviceExists(ctx, string(microservice))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownMicroservice, microservice)
	}
	ok, err = s.repo.CustomerExists(ctx, string(customer))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownCustomer, customer)
	}
	d, err := domain.NewDeployment(domain.DeploymentID(s.ids.NewID()), microservice, customer, environment)
	if err != nil {
		return "", err
	}
	if err := s.repo.SaveDeployment(ctx, d); err != nil {
		return "", err
	}
	return d.ID(), nil
}

// BlastRadius returns the number of unique customers reached from a release through the
// estate graph — the input to Governance's blast-radius multiplier (C2).
func (s *RegistryService) BlastRadius(ctx context.Context, releaseID string) (int, error) {
	return s.repo.BlastRadiusCustomers(ctx, releaseID)
}

// GetRelease loads a Release by id.
func (s *RegistryService) GetRelease(ctx context.Context, id domain.ReleaseID) (domain.Release, error) {
	return s.repo.GetRelease(ctx, id)
}

// GetProject loads a Project by id — the upward name-chain hop (D13.4).
func (s *RegistryService) GetProject(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	return s.repo.GetProject(ctx, id)
}

// GetProduct loads a Product by id — the top of the name chain (D13.4).
func (s *RegistryService) GetProduct(ctx context.Context, id domain.ProductID) (domain.Product, error) {
	return s.repo.GetProduct(ctx, id)
}

// ListProducts returns products, optionally filtered by exact name (DASH-1).
func (s *RegistryService) ListProducts(ctx context.Context, name string) ([]domain.Product, error) {
	return s.repo.ListProducts(ctx, name)
}

// ListProjects returns the Projects under a Product, optionally filtered by exact name (DASH-1).
// A product that does not exist is reported as such rather than as an empty list — "no projects"
// and "no such product" are different answers and a caller must be able to tell them apart.
func (s *RegistryService) ListProjects(ctx context.Context, product domain.ProductID, name string) ([]domain.Project, error) {
	ok, err := s.repo.ProductExists(ctx, string(product))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrUnknownProduct
	}
	return s.repo.ListProjects(ctx, product, name)
}

// ListReleases returns the Releases belonging to a Project.
func (s *RegistryService) ListReleases(ctx context.Context, project domain.ProjectID) ([]domain.Release, error) {
	// Same distinction as ListProjects: "this project has no releases" and "there is no such
	// project" are different answers, and collapsing them sends a caller hunting for a typo in
	// the wrong place.
	ok, err := s.repo.ProjectExists(ctx, string(project))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrUnknownProject
	}
	return s.repo.ListReleases(ctx, project)
}

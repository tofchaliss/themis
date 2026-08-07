// Package store is the registry's Postgres persistence adapter: it owns the
// products/projects/releases tables (its own migrations) and implements the
// application Repository port. Opaque TEXT ids; foreign keys enforce membership at
// the database, mirroring the domain invariants.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/registry/domain"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("registry: not found")

// Store is the registry's Postgres-backed repository.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// SaveProduct inserts a Product.
func (s *Store) SaveProduct(ctx context.Context, p domain.Product) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1,$2)`, string(p.ID()), p.Name())
	return err
}

// SaveProject inserts a Project (its product_id FK enforces the Product exists).
func (s *Store) SaveProject(ctx context.Context, p domain.Project) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO projects (id, product_id, name) VALUES ($1,$2,$3)`,
		string(p.ID()), string(p.ProductID()), p.Name())
	return err
}

// SaveRelease inserts a Release (its project_id FK enforces the Project exists).
func (s *Store) SaveRelease(ctx context.Context, r domain.Release) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO releases (id, project_id, version) VALUES ($1,$2,$3)`,
		string(r.ID()), string(r.ProjectID()), r.Version())
	return err
}

// GetRelease loads a Release by id; a missing row yields ErrNotFound.
func (s *Store) GetRelease(ctx context.Context, id domain.ReleaseID) (domain.Release, error) {
	var projectID, version string
	err := s.pool.QueryRow(ctx, `SELECT project_id, version FROM releases WHERE id = $1`, string(id)).
		Scan(&projectID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Release{}, ErrNotFound
	}
	if err != nil {
		return domain.Release{}, err
	}
	return domain.NewRelease(id, domain.ProjectID(projectID), version)
}

// ListReleases returns the Releases belonging to a Project, ordered by id.
func (s *Store) ListReleases(ctx context.Context, project domain.ProjectID) ([]domain.Release, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, version FROM releases WHERE project_id = $1 ORDER BY id`, string(project))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Release
	for rows.Next() {
		var id, version string
		if err := rows.Scan(&id, &version); err != nil {
			return nil, err
		}
		r, err := domain.NewRelease(domain.ReleaseID(id), project, version)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListProducts returns products, optionally filtered by exact name (DASH-1).
//
// Exact match, not a prefix or a LIKE: the caller here is a human or a GUI who KNOWS the product
// they mean, and a fuzzy match would return a set they then have to disambiguate — which is the
// problem this endpoint exists to remove, not a smaller version of it.
func (s *Store) ListProducts(ctx context.Context, name string) ([]domain.Product, error) {
	q, args := `SELECT id, name FROM products ORDER BY name`, []any{}
	if name != "" {
		q, args = `SELECT id, name FROM products WHERE name = $1 ORDER BY name`, []any{name}
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Product
	for rows.Next() {
		var id, n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		p, err := domain.NewProduct(domain.ProductID(id), n)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListProjects returns the projects under a product, optionally filtered by exact name (DASH-1).
func (s *Store) ListProjects(ctx context.Context, product domain.ProductID, name string) ([]domain.Project, error) {
	q := `SELECT id, name FROM projects WHERE product_id = $1 ORDER BY name`
	args := []any{string(product)}
	if name != "" {
		q = `SELECT id, name FROM projects WHERE product_id = $1 AND name = $2 ORDER BY name`
		args = append(args, name)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Project
	for rows.Next() {
		var id, n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		p, err := domain.NewProject(domain.ProjectID(id), product, n)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProductExists reports whether a Product with the given id exists.
func (s *Store) ProductExists(ctx context.Context, productID string) (bool, error) {
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM products WHERE id = $1)`, productID)
}

// ProjectExists reports whether a Project with the given id exists.
func (s *Store) ProjectExists(ctx context.Context, projectID string) (bool, error) {
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, projectID)
}

// ReleaseExists reports whether a Release with the given id exists (backs Evidence's
// SubjectRef).
func (s *Store) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE id = $1)`, releaseID)
}

func (s *Store) exists(ctx context.Context, query, id string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, query, id).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

// --- estate graph (C1) -----------------------------------------------------

// SaveCustomer inserts a Customer.
func (s *Store) SaveCustomer(ctx context.Context, c domain.Customer) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO customers (id, name) VALUES ($1,$2)`, string(c.ID()), c.Name())
	return err
}

// SaveMicroservice inserts a Microservice (its product_id FK enforces the Product exists).
func (s *Store) SaveMicroservice(ctx context.Context, m domain.Microservice) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO microservices (id, product_id, name) VALUES ($1,$2,$3)`,
		string(m.ID()), string(m.ProductID()), m.Name())
	return err
}

// SaveDeployment inserts a Deployment (its FKs enforce the Microservice + Customer exist).
func (s *Store) SaveDeployment(ctx context.Context, d domain.Deployment) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO deployments (id, microservice_id, customer_id, environment) VALUES ($1,$2,$3,$4)`,
		string(d.ID()), string(d.MicroserviceID()), string(d.CustomerID()), d.Environment())
	return err
}

// MicroserviceExists reports whether a Microservice with the given id exists.
func (s *Store) MicroserviceExists(ctx context.Context, microserviceID string) (bool, error) {
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM microservices WHERE id = $1)`, microserviceID)
}

// CustomerExists reports whether a Customer with the given id exists.
func (s *Store) CustomerExists(ctx context.Context, customerID string) (bool, error) {
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM customers WHERE id = $1)`, customerID)
}

// BlastRadiusCustomers returns the count of DISTINCT customers reached from a release's
// product through its microservices' deployments (C1 — the estate traversal). An unpopulated
// (or unknown) release yields 0.
func (s *Store) BlastRadiusCustomers(ctx context.Context, releaseID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT d.customer_id)
		FROM releases r
		JOIN projects pr     ON r.project_id = pr.id
		JOIN microservices m ON m.product_id = pr.product_id
		JOIN deployments d   ON d.microservice_id = m.id
		WHERE r.id = $1`, releaseID).Scan(&n)
	return n, err
}

// Purge removes all registry rows. It is a development/test-only affordance for
// resetting data; callers must gate it behind a non-production environment flag.
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE deployments, microservices, customers, releases, projects, products RESTART IDENTITY CASCADE`)
	return err
}

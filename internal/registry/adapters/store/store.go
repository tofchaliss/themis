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

// Purge removes all registry rows. It is a development/test-only affordance for
// resetting data; callers must gate it behind a non-production environment flag.
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE releases, projects, products RESTART IDENTITY CASCADE`)
	return err
}

// Package store is the registry's Postgres persistence adapter: it owns the
// products/projects/releases tables (its own migrations) and implements the
// application Repository port. Opaque TEXT ids; foreign keys enforce membership at
// the database, mirroring the domain invariants.
package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/registry/app"
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

// --- find-or-create (EDR-INTAKE-01 B4) -------------------------------------
//
// Uniqueness is enforced by the DATABASE, never by check-then-insert: a SELECT-then-INSERT
// is a time-of-check/time-of-use race, and two bots building the same version at the same
// moment is the normal case. Each upsert therefore insists on the matching unique index from
// migration 000003 and lets Postgres decide the winner.

// UpsertProduct finds or creates the Product named name and reports whether it created it.
//
// Case is folded (registry_products_name_key is UNIQUE on lower(name)), so "OAMP" and "oamp"
// are one Product — a human-typed label must not fork on a shift key. The stored casing is the
// FIRST caller's: a later "oamp" gets the existing "OAMP" row, with its spelling, and nothing
// is renamed or normalized (B4).
func (s *Store) UpsertProduct(ctx context.Context, name string) (string, bool, error) {
	return s.findOrCreate(ctx,
		`INSERT INTO products (id, name) VALUES ($1,$2)
		 ON CONFLICT (lower(name)) DO NOTHING
		 RETURNING id`,
		[]any{uuid.NewString(), name},
		`SELECT id FROM products WHERE lower(name) = lower($1)`,
		[]any{name})
}

// UpsertProject finds or creates the Project named name under product, and reports whether it
// created it. Uniqueness is scoped to the Product (registry_projects_product_name_key is UNIQUE
// on (product_id, lower(name))), so the same project name under a different Product is a
// different row. An unknown product is the foreign key's answer, not this method's.
func (s *Store) UpsertProject(ctx context.Context, productID, name string) (string, bool, error) {
	return s.findOrCreate(ctx,
		`INSERT INTO projects (id, product_id, name) VALUES ($1,$2,$3)
		 ON CONFLICT (product_id, lower(name)) DO NOTHING
		 RETURNING id`,
		[]any{uuid.NewString(), productID, name},
		`SELECT id FROM projects WHERE product_id = $1 AND lower(name) = lower($2)`,
		[]any{productID, name})
}

// UpsertRelease finds or creates the Release at version under project, and reports whether it
// created it.
//
// Version matching is EXACT (registry_releases_project_version_key is UNIQUE on
// (project_id, version), with no lower()): a version is a machine build string whose case
// Themis does not own, so "r1917.256" is not "R1917.256" and "R1917.25" is not "R1917.256".
// Folding versions would merge two builds.
func (s *Store) UpsertRelease(ctx context.Context, projectID, version string) (string, bool, error) {
	return s.findOrCreate(ctx,
		`INSERT INTO releases (id, project_id, version) VALUES ($1,$2,$3)
		 ON CONFLICT (project_id, version) DO NOTHING
		 RETURNING id`,
		[]any{uuid.NewString(), projectID, version},
		`SELECT id FROM releases WHERE project_id = $1 AND version = $2`,
		[]any{projectID, version})
}

// findOrCreate runs an `ON CONFLICT … DO NOTHING RETURNING id` insert and, when the conflict
// swallowed it, reads the winner back by the SAME key.
//
// Two traps, both deliberate (design §5):
//
//  1. An expression index needs its expression restated: `ON CONFLICT (name)` does not infer an
//     index on `lower(name)`, so every caller above writes the index expression verbatim — and
//     the lookup repeats it, because the row it has to find is the one the index matched.
//  2. The id minted for a losing insert is DISCARDED. `DO NOTHING` returns no row, so the id
//     this process generated was never stored; returning it would hand the caller an identity
//     that does not exist. The winner's id is the only answer, and `created=false` says so.
func (s *Store) findOrCreate(ctx context.Context, insert string, insertArgs []any, lookup string, lookupArgs []any) (string, bool, error) {
	var out string
	err := s.pool.QueryRow(ctx, insert, insertArgs...).Scan(&out)
	if err == nil {
		return out, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}
	if err := s.pool.QueryRow(ctx, lookup, lookupArgs...).Scan(&out); err != nil {
		return "", false, err
	}
	return out, false, nil
}

// --- exact-name lookups that abstain (EDR-INTAKE-01 B4) --------------------
//
// These back Evidence's read-only release resolution: an intake names a release by
// {product, project, version} and the registry answers with the id, or declines to.
//
// Three answers, and all three are distinct on purpose:
//
//	0 matches  → empty id, nil error      — "not found" is an answer, not a fault
//	1 match    → the id
//	>1 matches → app.ErrAmbiguousName     — the name is ambiguous, NOT unregistered
//
// Picking the first of several matches would be inventing the operator's intent, and it
// is what `ReleaseIDByVersion` used to do (it scanned a project's releases in the
// composition root and took the first exact hit), which silently chose a winner the
// moment two existed.
//
// Matching mirrors the uniqueness indexes 000003 builds, which is what makes a lookup
// find the row an upsert would have returned: names fold case (`lower(name)`), a version
// is exact. `LIMIT 2` is the whole multiplicity test — one more row than an unambiguous
// answer allows is all this needs to know, and it costs no count over the table.

// ProductIDByName resolves an exact Product name, folding case, and abstains on anything
// but a single match.
func (s *Store) ProductIDByName(ctx context.Context, name string) (string, error) {
	return s.idOfSingleMatch(ctx,
		`SELECT id FROM products WHERE lower(name) = lower($1) LIMIT 2`, name)
}

// ProjectIDByName resolves an exact Project name within a Product, folding case, and
// abstains on anything but a single match. The same name under a different Product is a
// different row, so the scoping is part of the key and not a filter on the answer.
func (s *Store) ProjectIDByName(ctx context.Context, productID, name string) (string, error) {
	return s.idOfSingleMatch(ctx,
		`SELECT id FROM projects WHERE product_id = $1 AND lower(name) = lower($2) LIMIT 2`,
		productID, name)
}

// ReleaseIDByVersion resolves an EXACT version string within a Project — never by prefix
// and never by case ("R1917.25" is not "R1917.256", and "r1917.256" is not "R1917.256") —
// and abstains on anything but a single match.
func (s *Store) ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error) {
	return s.idOfSingleMatch(ctx,
		`SELECT id FROM releases WHERE project_id = $1 AND version = $2 LIMIT 2`,
		projectID, version)
}

// idOfSingleMatch returns the id of the one matching row, the empty string when nothing
// matched, and app.ErrAmbiguousName as soon as a second row appears.
func (s *Store) idOfSingleMatch(ctx context.Context, query string, args ...any) (string, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	if !rows.Next() {
		return "", rows.Err()
	}
	var id string
	if err := rows.Scan(&id); err != nil {
		return "", err
	}
	if rows.Next() {
		return "", app.ErrAmbiguousName
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return id, nil
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

// GetProject loads a Project by id; a missing row yields ErrNotFound.
func (s *Store) GetProject(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	var productID, name string
	err := s.pool.QueryRow(ctx, `SELECT product_id, name FROM projects WHERE id = $1`, string(id)).
		Scan(&productID, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Project{}, ErrNotFound
	}
	if err != nil {
		return domain.Project{}, err
	}
	return domain.NewProject(id, domain.ProductID(productID), name)
}

// GetProduct loads a Product by id; a missing row yields ErrNotFound.
func (s *Store) GetProduct(ctx context.Context, id domain.ProductID) (domain.Product, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM products WHERE id = $1`, string(id)).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Product{}, ErrNotFound
	}
	if err != nil {
		return domain.Product{}, err
	}
	return domain.NewProduct(id, name)
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

// ProductOfRelease returns the id of the Product that OWNS a release, walking
// release -> project -> product in ONE query (EDR-INTAKE-01 B7: the `release_id`
// path authorizes the resolved Product before anything is written).
//
// An unknown release is an EMPTY id and a nil error, the same contract the name
// lookups above keep: "no such release" is an answer, not a fault, and a caller
// that cannot tell the two apart ends up reporting a database outage as a missing
// release. There is no ambiguity case — a release id is unique by construction and
// its project FK gives exactly one product.
func (s *Store) ProductOfRelease(ctx context.Context, releaseID string) (string, error) {
	var productID string
	err := s.pool.QueryRow(ctx, `
		SELECT pr.product_id
		FROM releases r
		JOIN projects pr ON r.project_id = pr.id
		WHERE r.id = $1`, releaseID).Scan(&productID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return productID, nil
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

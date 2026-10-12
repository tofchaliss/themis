// Package userstore is the dashboard's own login directory: the `dashboard_users` table in
// the shared `auth` database, holding a username, a bcrypt password hash, and the stamp that
// makes a password change end other sessions.
//
// It is DASHBOARD-LOCAL on purpose (EDR-GUI-01 D12): a browser password is a concern no other
// node has, so it does not grow `internal/platform/auth`. The table lives in the `auth`
// database because that is where infrastructure identity lives, and it carries its own
// golang-migrate bookkeeping table (see ../migrations) so two binaries migrating one database
// cannot read each other's version number.
//
// The package does no logging at all. The shipped default password appears here exactly once,
// as the seed constant, and is never written to a log or an error string.
package userstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// DefaultMigrationsPath is where this table's migrations live, applied against the `auth`
// database by cmd/dashboard (mirrors auth.DefaultMigrationsPath and each context's
// THEMIS_<CTX>_MIGRATIONS default).
const DefaultMigrationsPath = "internal/dashboard/migrations"

// MigrationsTable is the dashboard's OWN golang-migrate bookkeeping table. The `auth`
// database is also migrated by the authadmin CLI, and golang-migrate defaults to one shared
// `schema_migrations` table — so whichever migrated second would read the other's version,
// conclude it was up to date, and silently skip its own CREATE TABLE (the defect Registry
// hit in the `evidence` database, fixed the same way).
const MigrationsTable = "dashboard_schema_migrations"

const (
	// AdminUsername is the single seeded account. It is a SHARED account, which is the
	// acknowledged trade-off of password login (EDR-GUI-01 D3 amendment 2026-10-12): every
	// decision taken through it is stamped `admin` in the audit trail, so a named operator
	// who wants their own name on a record signs in with their own API key.
	AdminUsername = "admin"

	// DefaultAdminPassword is the shipped default, documented in INSTALLATION.md and meant to
	// be changed in the Admin tab on first sign-in. This constant and the docs are the ONLY
	// places the plaintext appears — never a log line, never an error.
	DefaultAdminPassword = "Themis@123"
)

// ErrNotFound reports that no row exists for the username.
var ErrNotFound = errors.New("userstore: no such dashboard user")

// ErrTableMissing reports that `dashboard_users` does not exist — the dashboard was started
// against an auth database that has never had its migrations applied. It is a distinct error
// because the only honest response is one operator-facing warning naming the fix
// (THEMIS_DASHBOARD_MIGRATE=1), while API-key login keeps working.
var ErrTableMissing = errors.New("userstore: the dashboard_users table does not exist")

// undefinedTable is Postgres's SQLSTATE for "relation does not exist".
const undefinedTable = "42P01"

// User is one login row. PasswordHash is a bcrypt hash; the password itself is never stored.
type User struct {
	Username          string
	PasswordHash      []byte
	IsDefaultPassword bool
	UpdatedAt         time.Time
}

// Store is the Postgres-backed login directory over the shared `auth` database.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a Store over a pool against the `auth` database (the same pool the
// dashboard uses to read api_keys — one database, two tables, one connection pool).
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// TableExists reports whether `dashboard_users` is present. Used at startup to decide between
// seeding and warning, so the dashboard degrades instead of refusing to boot.
func (s *Store) TableExists(ctx context.Context) (bool, error) {
	var present bool
	err := s.pool.QueryRow(ctx, `SELECT to_regclass('dashboard_users') IS NOT NULL`).Scan(&present)
	if err != nil {
		return false, fmt.Errorf("userstore: probe dashboard_users: %w", err)
	}
	return present, nil
}

// GetUser reads one login row. A missing row is ErrNotFound; a missing table is
// ErrTableMissing, so a caller can tell "wrong username" from "never migrated".
func (s *Store) GetUser(ctx context.Context, username string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT username, password_hash, is_default_password, updated_at
		   FROM dashboard_users
		  WHERE username = $1`, username).
		Scan(&u.Username, &u.PasswordHash, &u.IsDefaultPassword, &u.UpdatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return User{}, ErrNotFound
	case err != nil:
		return User{}, classify(err, "read dashboard user")
	}
	return u, nil
}

// Exists reports whether the username has a row.
func (s *Store) Exists(ctx context.Context, username string) (bool, error) {
	_, err := s.GetUser(ctx, username)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// EnsureAdminSeed creates the `admin` row with the shipped default password when it is
// absent, and reports whether it created one. It NEVER overwrites an existing row — a
// restart must not undo a password the operator changed — which is `ON CONFLICT DO NOTHING`,
// not a read-then-write (two dashboards starting together would otherwise race).
func (s *Store) EnsureAdminSeed(ctx context.Context) (bool, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(DefaultAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("userstore: hash the default password: %w", err)
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO dashboard_users (username, password_hash, is_default_password)
		 VALUES ($1, $2, TRUE)
		 ON CONFLICT (username) DO NOTHING`, AdminUsername, hash)
	if err != nil {
		return false, classify(err, "seed the dashboard admin")
	}
	return tag.RowsAffected() == 1, nil
}

// UpdatePassword replaces the hash, clears the default-password flag, and bumps updated_at —
// the stamp the session layer compares on every mutation, so this one statement is also what
// ends the user's other sessions (EDR-GUI-01 D12). It returns the new stamp.
func (s *Store) UpdatePassword(ctx context.Context, username string, hash []byte) (time.Time, error) {
	var updatedAt time.Time
	err := s.pool.QueryRow(ctx,
		`UPDATE dashboard_users
		    SET password_hash = $2, is_default_password = FALSE, updated_at = now()
		  WHERE username = $1
		RETURNING updated_at`, username, hash).Scan(&updatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return time.Time{}, ErrNotFound
	case err != nil:
		return time.Time{}, classify(err, "update the dashboard password")
	}
	return updatedAt, nil
}

// classify turns Postgres's undefined-table SQLSTATE into ErrTableMissing and wraps anything
// else. The distinction is what lets startup warn once instead of failing opaquely.
func classify(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == undefinedTable {
		return ErrTableMissing
	}
	return fmt.Errorf("userstore: %s: %w", what, err)
}

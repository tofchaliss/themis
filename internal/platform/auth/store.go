package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ErrNotFound is returned when a key lookup finds no matching row.
var ErrNotFound = errors.New("auth: not found")

// APIKey is a stored key metadata row. The raw token is never persisted — only its bcrypt
// hash (D3).
type APIKey struct {
	ID        string
	Name      string
	KeyHash   string
	Scopes    []string
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// KeyStore is the identity-store port the authentication middleware depends on. Keeping the
// middleware behind this interface (not the concrete Store) lets tests inject fakes and lets
// the persistence mechanism evolve without touching enforcement (D1 governing principle).
type KeyStore interface {
	// ActiveKeys returns all non-revoked keys. The middleware bcrypt-compares the presented
	// token against each and checks expiry (ported from the monolith's FindActiveKeys scan).
	ActiveKeys(ctx context.Context) ([]APIKey, error)
}

// Store is the Postgres-backed identity store over the shared `auth` database.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a Store over the given pool (a pool against the `auth` DB).
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ActiveKeys returns every key that has not been revoked.
func (s *Store) ActiveKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, key_hash, scopes, expires_at, revoked_at
		   FROM api_keys
		  WHERE revoked_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.Scopes, &k.ExpiresAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// CreateKey inserts a key row (the CLI generates the token and passes its hash — D6). A nil
// scope slice is normalized to an empty array so it maps to the NOT NULL scopes column
// (a scopeless key is authenticated but carries no authority).
func (s *Store) CreateKey(ctx context.Context, k APIKey) error {
	scopes := k.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO api_keys (id, name, key_hash, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		k.ID, k.Name, k.KeyHash, scopes, k.ExpiresAt)
	return err
}

// RevokeKey marks a key revoked; a missing (or already-revoked) key yields ErrNotFound.
func (s *Store) RevokeKey(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GenerateKey mints a new opaque bearer token and its bcrypt hash. The raw token is returned
// once (to be shown to the operator and never stored); only the hash is persisted (D3).
func GenerateKey() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: generate key: %w", err)
	}
	raw = "thm_" + base64.RawURLEncoding.EncodeToString(buf)
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("auth: hash key: %w", err)
	}
	return raw, string(h), nil
}

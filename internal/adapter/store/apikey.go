package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// ErrAPIKeyNotFound indicates the key id does not exist or is already revoked.
var ErrAPIKeyNotFound = errors.New("api key not found or already revoked")

// PostgresAPIKeyRepository loads API key records for authentication.
type PostgresAPIKeyRepository struct {
	pool pgQueryPool
}

// NewPostgresAPIKeyRepository creates an API key repository.
func NewPostgresAPIKeyRepository(pool pgQueryPool) *PostgresAPIKeyRepository {
	return &PostgresAPIKeyRepository{pool: pool}
}

func (r *PostgresAPIKeyRepository) FindByHashPrefix(_ context.Context) ([]domain.APIKeyRecord, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *PostgresAPIKeyRepository) FindActiveKeys(ctx context.Context) ([]domain.APIKeyRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, key_hash, scopes, expires_at, revoked_at
		FROM api_keys
		WHERE revoked_at IS NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []domain.APIKeyRecord
	for rows.Next() {
		var key domain.APIKeyRecord
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyHash, &key.Scopes, &key.ExpiresAt, &key.RevokedAt); err != nil {
			return nil, err
		}
		if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
			continue
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *PostgresAPIKeyRepository) Create(ctx context.Context, input domain.APIKeyCreateInput) (domain.APIKeyRecord, error) {
	var record domain.APIKeyRecord
	err := r.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_hash, scopes, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, key_hash, scopes, expires_at, revoked_at
	`, input.Name, input.KeyHash, input.Scopes, input.ExpiresAt).Scan(
		&record.ID,
		&record.Name,
		&record.KeyHash,
		&record.Scopes,
		&record.ExpiresAt,
		&record.RevokedAt,
	)
	if err != nil {
		return domain.APIKeyRecord{}, fmt.Errorf("create api key: %w", err)
	}
	return record, nil
}

func (r *PostgresAPIKeyRepository) Revoke(ctx context.Context, keyID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE api_keys
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`, keyID)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Release-rollup persistence (EDR-COMMUNICATION-01 D13). Implements app.RollupStore with the
// same append-and-supersede + optimistic-concurrency discipline as per-Finding publications.

const rollupColumns = `id, release_id, product_purl, format, audience, payload, input_set,
	as_of, statements, withdrawn_excluded, supersedes_id, superseded_by, version, created_at`

// SaveRollup records the new rollup and supersedes the prior one atomically (D5); a version
// mismatch on the prior returns app.ErrConcurrent.
func (s *Store) SaveRollup(ctx context.Context, pub domain.RollupPublication, prior *domain.RollupPublication, priorPrevVersion int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	inputSet, err := json.Marshal(pub.InputSet())
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO release_rollups (`+rollupColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		string(pub.ID()), pub.ReleaseID(), pub.ProductPURL(), pub.Format(), pub.Audience(),
		pub.Payload(), string(inputSet), pub.AsOf(), pub.Statements(), pub.WithdrawnExcluded(),
		string(pub.Supersedes()), string(pub.SupersededBy()), pub.Version(), pub.CreatedAt()); err != nil {
		return err
	}
	if prior != nil {
		ct, err := tx.Exec(ctx,
			`UPDATE release_rollups SET superseded_by=$1, version=$2 WHERE id=$3 AND version=$4`,
			string(prior.SupersededBy()), prior.Version(), string(prior.ID()), priorPrevVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return app.ErrConcurrent
		}
	}
	return tx.Commit(ctx)
}

// CurrentRollup returns the latest non-superseded rollup for (release, format, audience).
func (s *Store) CurrentRollup(ctx context.Context, releaseID, format, audience string) (domain.RollupPublication, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+rollupColumns+` FROM release_rollups
		WHERE release_id=$1 AND format=$2 AND audience=$3 AND superseded_by=''
		ORDER BY created_at DESC LIMIT 1`, releaseID, format, audience)
	pub, err := scanRollup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RollupPublication{}, false, nil
	}
	if err != nil {
		return domain.RollupPublication{}, false, err
	}
	return pub, true, nil
}

// GetRollup loads one rollup by id.
func (s *Store) GetRollup(ctx context.Context, id domain.RollupPublicationID) (domain.RollupPublication, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+rollupColumns+` FROM release_rollups WHERE id=$1`, string(id))
	pub, err := scanRollup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RollupPublication{}, domain.ErrRollupNotFound
	}
	return pub, err
}

// ListRollups returns a release's rollups, newest first (the full supersession history — D5
// keeps both).
func (s *Store) ListRollups(ctx context.Context, releaseID string) ([]domain.RollupPublication, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+rollupColumns+` FROM release_rollups
		WHERE release_id=$1 ORDER BY created_at DESC, id`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RollupPublication
	for rows.Next() {
		pub, err := scanRollup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRollup(row rowScanner) (domain.RollupPublication, error) {
	var (
		id, releaseID, productPURL, format, audience, supersedes, supersededBy string
		payload, inputRaw                                                      []byte
		statements, withdrawn, version                                         int
	)
	var asOf, createdAt time.Time
	if err := row.Scan(&id, &releaseID, &productPURL, &format, &audience, &payload, &inputRaw,
		&asOf, &statements, &withdrawn, &supersedes, &supersededBy, &version, &createdAt); err != nil {
		return domain.RollupPublication{}, err
	}
	var inputSet []domain.RollupInputRecord
	if len(inputRaw) > 0 {
		if err := json.Unmarshal(inputRaw, &inputSet); err != nil {
			return domain.RollupPublication{}, err
		}
	}
	return domain.ReconstituteRollupPublication(domain.RollupPublicationID(id), releaseID, productPURL,
		format, audience, payload, inputSet, asOf, statements, withdrawn,
		domain.RollupPublicationID(supersedes), domain.RollupPublicationID(supersededBy), version, createdAt), nil
}

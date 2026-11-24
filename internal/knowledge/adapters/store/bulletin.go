package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The PSIRT bulletin register (EDR-PSIRT-01 revision 3), migration 000014. Every write and its
// history row commit together; a removal is a tombstone.

var _ app.BulletinStore = (*Store)(nil)

const bulletinColumns = `id, bulletin_id, title, bulletin_url, alert_url, note, cve, report_date,
	created_at, created_by, updated_at, updated_by`

// bulletinJSON is the history's frozen copy of a bulletin. Its keys are the API's, so a history
// row reads the same in ten years whatever the Go type becomes.
type bulletinJSON struct {
	ID          string    `json:"id"`
	BulletinID  string    `json:"bulletin_id"`
	Title       string    `json:"title"`
	BulletinURL string    `json:"bulletin_url"`
	AlertURL    string    `json:"alert_url"`
	Note        string    `json:"note"`
	CVE         string    `json:"cve"`
	ReportDate  time.Time `json:"report_date"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by"`
}

func toBulletinJSON(b *domain.Bulletin) []byte {
	if b == nil {
		return nil
	}
	raw, _ := json.Marshal(bulletinJSON{
		ID: b.ID, BulletinID: b.BulletinID, Title: b.Title, BulletinURL: b.BulletinURL, AlertURL: b.AlertURL,
		Note: b.Note, CVE: b.CVE, ReportDate: b.ReportDate, CreatedAt: b.CreatedAt, CreatedBy: b.CreatedBy,
		UpdatedAt: b.UpdatedAt, UpdatedBy: b.UpdatedBy,
	})
	return raw
}

func fromBulletinJSON(raw []byte) (*domain.Bulletin, error) {
	if raw == nil {
		return nil, nil
	}
	var j bulletinJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	return &domain.Bulletin{
		ID: j.ID, BulletinInput: domain.BulletinInput{BulletinID: j.BulletinID, Title: j.Title, BulletinURL: j.BulletinURL,
			AlertURL: j.AlertURL, Note: j.Note, CVE: j.CVE, ReportDate: j.ReportDate},
		CreatedAt: j.CreatedAt, CreatedBy: j.CreatedBy, UpdatedAt: j.UpdatedAt, UpdatedBy: j.UpdatedBy,
	}, nil
}

func scanBulletin(row pgx.Row) (domain.Bulletin, error) {
	var b domain.Bulletin
	err := row.Scan(&b.ID, &b.BulletinID, &b.Title, &b.BulletinURL, &b.AlertURL, &b.Note, &b.CVE, &b.ReportDate,
		&b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy)
	b.ReportDate = b.ReportDate.UTC()
	b.CreatedAt, b.UpdatedAt = b.CreatedAt.UTC(), b.UpdatedAt.UTC()
	return b, err
}

// ListBulletins returns every live bulletin, newest report date first, then newest created.
func (s *Store) ListBulletins(ctx context.Context) ([]domain.Bulletin, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+bulletinColumns+` FROM psirt_bulletins
		WHERE removed_at IS NULL ORDER BY report_date DESC, created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Bulletin
	for rows.Next() {
		b, err := scanBulletin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBulletin returns one live bulletin; a removed or unknown id is app.ErrBulletinNotFound.
func (s *Store) GetBulletin(ctx context.Context, id string) (domain.Bulletin, error) {
	b, err := scanBulletin(s.pool.QueryRow(ctx, `SELECT `+bulletinColumns+` FROM psirt_bulletins
		WHERE id = $1 AND removed_at IS NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Bulletin{}, app.ErrBulletinNotFound
	}
	return b, err
}

// CreateBulletin inserts a bulletin and its "created" history row.
func (s *Store) CreateBulletin(ctx context.Context, b domain.Bulletin) error {
	return s.bulletinWrite(ctx, b.ID, b.CreatedBy, b.CreatedAt, app.BulletinCreated, nil, &b, func(tx pgx.Tx) (int64, error) {
		tag, err := tx.Exec(ctx, `INSERT INTO psirt_bulletins (`+bulletinColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			b.ID, b.BulletinID, b.Title, b.BulletinURL, b.AlertURL, b.Note, b.CVE, b.ReportDate,
			b.CreatedAt, b.CreatedBy, b.UpdatedAt, b.UpdatedBy)
		return tag.RowsAffected(), err
	})
}

// UpdateBulletin replaces a live bulletin's fields and appends the "updated" history row.
func (s *Store) UpdateBulletin(ctx context.Context, before, after domain.Bulletin) error {
	return s.bulletinWrite(ctx, after.ID, after.UpdatedBy, after.UpdatedAt, app.BulletinUpdated, &before, &after, func(tx pgx.Tx) (int64, error) {
		tag, err := tx.Exec(ctx, `UPDATE psirt_bulletins SET bulletin_id=$2, title=$3, bulletin_url=$4, alert_url=$5,
			note=$6, cve=$7, report_date=$8, updated_at=$9, updated_by=$10 WHERE id=$1 AND removed_at IS NULL`,
			after.ID, after.BulletinID, after.Title, after.BulletinURL, after.AlertURL, after.Note, after.CVE,
			after.ReportDate, after.UpdatedAt, after.UpdatedBy)
		return tag.RowsAffected(), err
	})
}

// RemoveBulletin tombstones a live bulletin and appends the "removed" history row.
func (s *Store) RemoveBulletin(ctx context.Context, b domain.Bulletin, actor string, at time.Time) error {
	return s.bulletinWrite(ctx, b.ID, actor, at, app.BulletinRemoved, &b, nil, func(tx pgx.Tx) (int64, error) {
		tag, err := tx.Exec(ctx, `UPDATE psirt_bulletins SET removed_at=$2 WHERE id=$1 AND removed_at IS NULL`, b.ID, at)
		return tag.RowsAffected(), err
	})
}

// bulletinWrite runs one change and its history row in one transaction. No row changed is
// app.ErrBulletinNotFound (removed meanwhile); a live duplicate is app.ErrBulletinConflict.
func (s *Store) bulletinWrite(ctx context.Context, id, actor string, at time.Time, action string, before, after *domain.Bulletin,
	change func(pgx.Tx) (int64, error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n, err := change(tx)
	if isUniqueViolation(err) {
		return app.ErrBulletinConflict
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return app.ErrBulletinNotFound
	}
	if _, err := tx.Exec(ctx, `INSERT INTO psirt_bulletin_history (bulletin, at, actor, action, before_json, after_json)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, at, actor, action, toBulletinJSON(before), toBulletinJSON(after)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// BulletinHistory returns every change of one bulletin, oldest first, a removed one included.
func (s *Store) BulletinHistory(ctx context.Context, id string) ([]app.BulletinChange, error) {
	rows, err := s.pool.Query(ctx, `SELECT at, actor, action, before_json, after_json FROM psirt_bulletin_history
		WHERE bulletin = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.BulletinChange
	for rows.Next() {
		var c app.BulletinChange
		var before, after []byte
		if err := rows.Scan(&c.At, &c.Actor, &c.Action, &before, &after); err != nil {
			return nil, err
		}
		c.At = c.At.UTC()
		if c.Before, err = fromBulletinJSON(before); err != nil {
			return nil, err
		}
		if c.After, err = fromBulletinJSON(after); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

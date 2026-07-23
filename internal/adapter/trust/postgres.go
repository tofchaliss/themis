package trust

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/themis-project/themis/internal/domain"
)

type pgConn interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// PostgresRepository implements TrustRepository against PostgreSQL.
type PostgresRepository struct {
	conn pgConn
}

// NewPostgresRepository creates a PostgreSQL-backed trust repository.
func NewPostgresRepository(conn pgConn) *PostgresRepository {
	return &PostgresRepository{conn: conn}
}

func (r *PostgresRepository) FindSBOMByDedupKey(ctx context.Context, imageDigest, checksumSHA256 string) (string, bool, error) {
	var id string
	err := r.conn.QueryRow(ctx, `
		SELECT sr.id::text
		FROM scan_reports sr
		JOIN sboms sb ON sb.id = sr.sbom_id
		JOIN artifacts a ON a.id = sr.artifact_id
		WHERE a.image_digest = $1 AND sb.sbom_checksum = $2 AND sr.deleted_at IS NULL
		ORDER BY sr.scanned_at DESC
		LIMIT 1
	`, imageDigest, checksumSHA256).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("find sbom dedup key: %w", err)
	}
	return id, true, nil
}

func (r *PostgresRepository) FindVEXByDedupKey(ctx context.Context, sbomChecksum, checksumSHA256 string) (string, bool, error) {
	var id string
	err := r.conn.QueryRow(ctx, `
		SELECT id::text
		FROM vex_documents
		WHERE sbom_checksum = $1 AND checksum_sha256 = $2
	`, sbomChecksum, checksumSHA256).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("find vex dedup key: %w", err)
	}
	return id, true, nil
}

func (r *PostgresRepository) ImageDigestExists(ctx context.Context, digest string) (bool, error) {
	var exists bool
	err := r.conn.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM artifacts WHERE image_digest = $1)
	`, digest).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("image digest exists: %w", err)
	}
	return exists, nil
}

func (r *PostgresRepository) SBOMChecksumExists(ctx context.Context, checksum string) (bool, error) {
	var exists bool
	err := r.conn.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM sboms WHERE sbom_checksum = $1)
	`, checksum).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("sbom checksum exists: %w", err)
	}
	return exists, nil
}

// PostgresAuditRecorder writes trust gate events to audit_log.
type PostgresAuditRecorder struct {
	conn pgConn
}

// NewPostgresAuditRecorder creates a PostgreSQL audit recorder.
func NewPostgresAuditRecorder(conn pgConn) *PostgresAuditRecorder {
	return &PostgresAuditRecorder{conn: conn}
}

func (a *PostgresAuditRecorder) Record(ctx context.Context, entry domain.AuditEntry) error {
	return recordAudit(ctx, a.conn, entry)
}

func (a *PostgresAuditRecorder) CountByAction(ctx context.Context, action string) (int, error) {
	var count int
	err := a.conn.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_log WHERE action = $1
	`, action).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count audit log: %w", err)
	}
	return count, nil
}

func recordAudit(ctx context.Context, conn pgConn, entry domain.AuditEntry) error {
	details, err := jsonMarshalAuditDetails(entry.Details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}

	var resourceID *uuid.UUID
	if entry.ResourceID != "" {
		parsed, parseErr := uuid.Parse(entry.ResourceID)
		if parseErr == nil {
			resourceID = &parsed
		}
	}

	var sourceIP *string
	if entry.SourceIP != "" {
		sourceIP = &entry.SourceIP
	}
	_, err = conn.Exec(ctx, `
		INSERT INTO audit_log (actor, action, resource_type, resource_id, details, source_ip)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)
	`, entry.Actor, entry.Action, entry.ResourceType, resourceID, details, sourceIP)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

var jsonMarshalAuditDetails = func(details map[string]string) ([]byte, error) {
	return json.Marshal(details)
}

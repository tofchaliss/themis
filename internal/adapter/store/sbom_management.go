package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresSBOMManagementRepository lists and soft-deletes SBOM documents.
type PostgresSBOMManagementRepository struct {
	pool    pgQueryPool
	catalog *PostgresProductCatalogRepository
}

// NewPostgresSBOMManagementRepository creates an SBOM management repository.
func NewPostgresSBOMManagementRepository(pool pgQueryPool) *PostgresSBOMManagementRepository {
	return &PostgresSBOMManagementRepository{
		pool:    pool,
		catalog: NewPostgresProductCatalogRepository(pool),
	}
}

func (r *PostgresSBOMManagementRepository) ListSBOMs(ctx context.Context, page domain.PageRequest) ([]domain.SBOMListEntry, int, domain.PageResult, error) {
	return r.listSBOMs(ctx, "", page)
}

func (r *PostgresSBOMManagementRepository) ListProductSBOMs(ctx context.Context, productID string, page domain.PageRequest) ([]domain.SBOMListEntry, int, domain.PageResult, error) {
	if _, err := r.catalog.GetProduct(ctx, productID); err != nil {
		return nil, 0, domain.PageResult{}, err
	}
	return r.listSBOMs(ctx, productID, page)
}

func (r *PostgresSBOMManagementRepository) listSBOMs(ctx context.Context, productID string, page domain.PageRequest) ([]domain.SBOMListEntry, int, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{}
	where := []string{"s.deleted_at IS NULL"}
	argIdx := 1
	if productID != "" {
		where = append(where, fmt.Sprintf("i.product_id = $%d", argIdx))
		args = append(args, productID)
		argIdx++
	}
	if page.Cursor != "" {
		parts := strings.SplitN(page.Cursor, "|", 2)
		if len(parts) == 2 {
			cursorTime, err := time.Parse(time.RFC3339Nano, parts[0])
			if err != nil {
				return nil, 0, domain.PageResult{}, fmt.Errorf("invalid cursor: %w", err)
			}
			where = append(where, fmt.Sprintf("(s.ingested_at, s.id) < ($%d::timestamptz, $%d::uuid)", argIdx, argIdx+1))
			args = append(args, cursorTime, parts[1])
			argIdx += 2
		}
	}
	limitArg := argIdx
	args = append(args, limit+1)
	total, err := r.countActiveSBOMs(ctx, productID)
	if err != nil {
		return nil, 0, domain.PageResult{}, err
	}
	query := fmt.Sprintf(`
		SELECT s.id::text, i.product_id::text, p.name,
		       COALESCE(pv.version, ''),
		       COALESCE(NULLIF(i.repository, ''), i.digest),
		       s.image_digest, s.format, s.is_latest, s.ingested_at,
		       (SELECT COUNT(*) FROM component_versions cv WHERE cv.sbom_document_id = s.id),
		       (SELECT COUNT(*) FROM component_vulnerabilities cv WHERE cv.sbom_document_id = s.id)
		FROM sbom_documents s
		JOIN images i ON i.id = s.image_id
		JOIN products p ON p.id = i.product_id
		LEFT JOIN artifacts a ON a.id = i.artifact_id
		LEFT JOIN product_versions pv ON pv.id = a.product_version_id
		WHERE %s
		ORDER BY s.ingested_at DESC, s.id DESC
		LIMIT $%d
	`, strings.Join(where, " AND "), limitArg)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, domain.PageResult{}, fmt.Errorf("list sboms: %w", err)
	}
	defer rows.Close()

	var items []domain.SBOMListEntry
	for rows.Next() {
		var item domain.SBOMListEntry
		if err := rows.Scan(
			&item.ID, &item.ProductID, &item.ProductName, &item.ProductVersion,
			&item.ImageName, &item.ImageDigest, &item.Format, &item.IsLatest, &item.UploadedAt,
			&item.ComponentCount, &item.VulnerabilityCount,
		); err != nil {
			return nil, 0, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		last := items[limit-1]
		next.NextCursor = last.UploadedAt.UTC().Format(time.RFC3339Nano) + "|" + last.ID
		items = items[:limit]
	}
	return items, total, next, nil
}

func (r *PostgresSBOMManagementRepository) countActiveSBOMs(ctx context.Context, productID string) (int, error) {
	var count int
	if productID == "" {
		err := r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM sbom_documents WHERE deleted_at IS NULL
		`).Scan(&count)
		return count, err
	}
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM sbom_documents s
		JOIN images i ON i.id = s.image_id
		WHERE s.deleted_at IS NULL AND i.product_id = $1
	`, productID).Scan(&count)
	return count, err
}

func (r *PostgresSBOMManagementRepository) SoftDeleteSBOM(ctx context.Context, id string, force bool) (domain.SBOMDeleteSummary, error) {
	var isLatest bool
	var deletedAt *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT is_latest, deleted_at FROM sbom_documents WHERE id = $1
	`, id).Scan(&isLatest, &deletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.SBOMDeleteSummary{}, domain.ErrSBOMNotFound
		}
		return domain.SBOMDeleteSummary{}, fmt.Errorf("load sbom: %w", err)
	}
	if deletedAt != nil {
		return domain.SBOMDeleteSummary{}, domain.ErrSBOMNotFound
	}
	if isLatest && !force {
		return domain.SBOMDeleteSummary{}, domain.ErrCannotDeleteLatestSBOM
	}

	var componentCount, findingCount int
	if err := r.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM component_versions WHERE sbom_document_id = $1),
			(SELECT COUNT(*) FROM component_vulnerabilities WHERE sbom_document_id = $1)
	`, id).Scan(&componentCount, &findingCount); err != nil {
		return domain.SBOMDeleteSummary{}, fmt.Errorf("count sbom data: %w", err)
	}

	tag, err := r.pool.Exec(ctx, `
		UPDATE sbom_documents SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL
	`, id)
	if err != nil {
		return domain.SBOMDeleteSummary{}, fmt.Errorf("soft delete sbom: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.SBOMDeleteSummary{}, domain.ErrSBOMNotFound
	}
	return domain.SBOMDeleteSummary{
		SBOMID:         id,
		ComponentCount: componentCount,
		FindingCount:   findingCount,
	}, nil
}

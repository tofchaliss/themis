package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresProductCatalogRepository manages products and projects.
type PostgresProductCatalogRepository struct {
	pool pgQueryPool
}

// NewPostgresProductCatalogRepository creates a catalog repository.
func NewPostgresProductCatalogRepository(pool pgQueryPool) *PostgresProductCatalogRepository {
	return &PostgresProductCatalogRepository{pool: pool}
}

// defaultProjectName is the slug of the auto-created default project (D5).
const defaultProjectName = "default"

func (r *PostgresProductCatalogRepository) CreateProduct(ctx context.Context, name, description string) (domain.Product, error) {
	id := uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO products (id, name, description)
		VALUES ($1, $2, NULLIF($3, ''))
		RETURNING created_at
	`, id, name, description).Scan(new(time.Time))
	if err != nil {
		return domain.Product{}, fmt.Errorf("create product: %w", err)
	}
	if _, err := r.ensureDefaultProject(ctx, id); err != nil {
		return domain.Product{}, err
	}
	return domain.Product{ID: id, Name: name, Description: description}, nil
}

// ensureDefaultProject returns the product's default project, creating it if absent
// (idempotent — reused, never duplicated).
func (r *PostgresProductCatalogRepository) ensureDefaultProject(ctx context.Context, productID string) (string, error) {
	id := uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO projects (id, product_id, name, is_default)
		VALUES ($1, $2, $3, TRUE)
		ON CONFLICT (product_id, name) DO UPDATE SET name = projects.name
		RETURNING id
	`, id, productID, defaultProjectName).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("ensure default project: %w", err)
	}
	return id, nil
}

func (r *PostgresProductCatalogRepository) CreateVersion(ctx context.Context, projectID, version string) (domain.ProductVersion, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, projectID).Scan(&exists); err != nil {
		return domain.ProductVersion{}, fmt.Errorf("lookup project: %w", err)
	}
	if !exists {
		return domain.ProductVersion{}, domain.ErrProjectNotFound
	}
	id := uuid.NewString()
	var createdAt time.Time
	err := r.pool.QueryRow(ctx, `
		INSERT INTO versions (id, project_id, version)
		VALUES ($1, $2, $3)
		ON CONFLICT (project_id, version) DO NOTHING
		RETURNING id, created_at
	`, id, projectID, version).Scan(&id, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProductVersion{}, domain.ErrVersionConflict
	}
	if err != nil {
		return domain.ProductVersion{}, fmt.Errorf("create version: %w", err)
	}
	return domain.ProductVersion{ID: id, ProjectID: projectID, Version: version, ReleaseStatus: "draft", CreatedAt: createdAt}, nil
}

func (r *PostgresProductCatalogRepository) RegisterArtifact(ctx context.Context, productID, version, imageDigest, repository string) (domain.Artifact, error) {
	// Duplicate digest maps to the existing artifact (digest is globally unique).
	var existing domain.Artifact
	err := r.pool.QueryRow(ctx, `
		SELECT id, version_id, artifact_type, image_digest, COALESCE(repository, '')
		FROM artifacts WHERE image_digest = $1
	`, imageDigest).Scan(&existing.ID, &existing.VersionID, &existing.ArtifactType, &existing.ImageDigest, &existing.Repository)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.Artifact{}, fmt.Errorf("lookup artifact: %w", err)
	}

	if _, err := r.GetProduct(ctx, productID); err != nil {
		return domain.Artifact{}, err
	}
	projectID, err := r.ensureDefaultProject(ctx, productID)
	if err != nil {
		return domain.Artifact{}, err
	}
	if version == "" {
		version = "latest"
	}
	versionID := uuid.NewString()
	if err := r.pool.QueryRow(ctx, `
		INSERT INTO versions (id, project_id, version)
		VALUES ($1, $2, $3)
		ON CONFLICT (project_id, version) DO UPDATE SET version = versions.version
		RETURNING id
	`, versionID, projectID, version).Scan(&versionID); err != nil {
		return domain.Artifact{}, fmt.Errorf("resolve version: %w", err)
	}

	artifactID := uuid.NewString()
	if err := r.pool.QueryRow(ctx, `
		INSERT INTO artifacts (id, version_id, artifact_type, image_digest, repository)
		VALUES ($1, $2, 'image', $3, NULLIF($4, ''))
		RETURNING id
	`, artifactID, versionID, imageDigest, repository).Scan(&artifactID); err != nil {
		return domain.Artifact{}, fmt.Errorf("register artifact: %w", err)
	}
	return domain.Artifact{
		ID: artifactID, VersionID: versionID, ArtifactType: "image",
		ImageDigest: imageDigest, Repository: repository,
	}, nil
}

func (r *PostgresProductCatalogRepository) ListProducts(ctx context.Context, page domain.PageRequest, productScope string) ([]domain.Product, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{limit + 1}
	where := ""
	if productScope != "" {
		where = "WHERE id = $2"
		args = append(args, productScope)
	}
	if page.Cursor != "" {
		if where == "" {
			where = "WHERE name > $2"
		} else {
			where += " AND name > $3"
		}
		args = append(args, page.Cursor)
	}
	query := fmt.Sprintf(`
		SELECT id, name, COALESCE(description, ''), created_at
		FROM products
		%s
		ORDER BY name ASC
		LIMIT $1
	`, where)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list products: %w", err)
	}
	defer rows.Close()

	var items []domain.Product
	for rows.Next() {
		var item domain.Product
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.CreatedAt); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	return paginateProducts(items, limit)
}

func paginateProducts(items []domain.Product, limit int) ([]domain.Product, domain.PageResult, error) {
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].Name
		items = items[:limit]
	}
	return items, next, nil
}

func (r *PostgresProductCatalogRepository) GetProduct(ctx context.Context, id string) (domain.Product, error) {
	var item domain.Product
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description, ''), created_at
		FROM products WHERE id = $1
	`, id).Scan(&item.ID, &item.Name, &item.Description, &item.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.Product{}, domain.ErrProductNotFound
		}
		return domain.Product{}, fmt.Errorf("get product: %w", err)
	}
	return item, nil
}

func (r *PostgresProductCatalogRepository) CreateProject(ctx context.Context, productID, name, description string) (domain.Project, error) {
	if _, err := r.GetProduct(ctx, productID); err != nil {
		return domain.Project{}, err
	}
	id := uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO projects (id, product_id, name, description)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING created_at
	`, id, productID, name, description).Scan(new(time.Time))
	if err != nil {
		return domain.Project{}, fmt.Errorf("create project: %w", err)
	}
	return domain.Project{ID: id, ProductID: productID, Name: name, Description: description}, nil
}

func (r *PostgresProductCatalogRepository) ListProjects(ctx context.Context, productID string, page domain.PageRequest) ([]domain.Project, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{productID, limit + 1}
	where := "WHERE product_id = $1"
	if page.Cursor != "" {
		where += " AND name > $3"
		args = append(args, page.Cursor)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, product_id, name, COALESCE(description, ''), created_at
		FROM projects
		`+where+`
		ORDER BY name ASC
		LIMIT $2
	`, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var items []domain.Project
	for rows.Next() {
		var item domain.Project
		if err := rows.Scan(&item.ID, &item.ProductID, &item.Name, &item.Description, &item.CreatedAt); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].Name
		items = items[:limit]
	}
	return items, next, nil
}

func (r *PostgresProductCatalogRepository) ListProductVersions(ctx context.Context, productID string, page domain.PageRequest) ([]domain.ProductVersion, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{productID, limit + 1}
	where := "WHERE p.product_id = $1"
	if page.Cursor != "" {
		where += " AND v.version > $3"
		args = append(args, page.Cursor)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT v.id, v.project_id, v.version, v.release_status, v.released_at, v.created_at
		FROM versions v
		JOIN projects p ON p.id = v.project_id
		`+where+`
		ORDER BY v.version ASC
		LIMIT $2
	`, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list product versions: %w", err)
	}
	defer rows.Close()

	var items []domain.ProductVersion
	for rows.Next() {
		var item domain.ProductVersion
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.Version, &item.ReleaseStatus, &item.ReleasedAt, &item.CreatedAt); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].Version
		items = items[:limit]
	}
	return items, next, nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 100 {
		return 100
	}
	return limit
}

// PostgresScanQueryRepository reads scans and vulnerabilities.
type PostgresScanQueryRepository struct {
	pool pgQueryPool
}

// NewPostgresScanQueryRepository creates a scan query repository.
func NewPostgresScanQueryRepository(pool pgQueryPool) *PostgresScanQueryRepository {
	return &PostgresScanQueryRepository{pool: pool}
}

func (r *PostgresScanQueryRepository) ListProjectScans(ctx context.Context, projectID string, page domain.PageRequest) ([]domain.ScanSummary, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{projectID, limit + 1}
	where := "WHERE proj.id = $1 AND sr.deleted_at IS NULL"
	if page.Cursor != "" {
		where += " AND sr.scanned_at < $3"
		args = append(args, page.Cursor)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT sr.id, proj.id::text, proj.product_id::text,
		       sr.image_digest, sb.format, sr.trust_status, sr.scanned_at,
		       COALESCE(j.id::text, '')
		FROM scan_reports sr
		JOIN sboms sb ON sb.id = sr.sbom_id
		JOIN artifacts a ON a.id = sr.artifact_id
		JOIN versions ver ON ver.id = a.version_id
		JOIN projects proj ON proj.id = ver.project_id
		LEFT JOIN LATERAL (
			SELECT id
			FROM ingestion_jobs
			WHERE payload->>'scan_id' = sr.id::text
			ORDER BY created_at DESC
			LIMIT 1
		) j ON true
		`+where+`
		ORDER BY sr.scanned_at DESC
		LIMIT $2
	`, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	var items []domain.ScanSummary
	for rows.Next() {
		var item domain.ScanSummary
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.ProductID, &item.ImageDigest,
			&item.Format, &item.TrustStatus, &item.IngestedAt, &item.IngestionID); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].IngestedAt.UTC().Format(time.RFC3339Nano)
		items = items[:limit]
	}
	return items, next, nil
}

func (r *PostgresScanQueryRepository) GetScan(ctx context.Context, id string) (domain.ScanDetail, error) {
	var detail domain.ScanDetail
	err := r.pool.QueryRow(ctx, `
		SELECT sr.id, proj.id::text, proj.product_id::text,
		       sr.image_digest, sb.format, sr.trust_status, sr.scanned_at,
		       COALESCE(j.id::text, '')
		FROM scan_reports sr
		JOIN sboms sb ON sb.id = sr.sbom_id
		JOIN artifacts a ON a.id = sr.artifact_id
		JOIN versions ver ON ver.id = a.version_id
		JOIN projects proj ON proj.id = ver.project_id
		LEFT JOIN LATERAL (
			SELECT id
			FROM ingestion_jobs
			WHERE payload->>'scan_id' = sr.id::text
			ORDER BY created_at DESC
			LIMIT 1
		) j ON true
		WHERE sr.id = $1 AND sr.deleted_at IS NULL
	`, id).Scan(&detail.ID, &detail.ProjectID, &detail.ProductID, &detail.ImageDigest,
		&detail.Format, &detail.TrustStatus, &detail.IngestedAt, &detail.IngestionID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.ScanDetail{}, fmt.Errorf("scan %q not found", id)
		}
		return domain.ScanDetail{}, fmt.Errorf("get scan: %w", err)
	}
	counts, err := r.countSeverities(ctx, id)
	if err != nil {
		return domain.ScanDetail{}, err
	}
	detail.VulnerabilityCounts = counts
	return detail, nil
}

func (r *PostgresScanQueryRepository) countSeverities(ctx context.Context, scanID string) (map[string]int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(v.severity, 'none'), COUNT(*)
		FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.scan_report_id = $1
		GROUP BY COALESCE(v.severity, 'none')
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		out[severity] = count
	}
	return out, rows.Err()
}

func (r *PostgresScanQueryRepository) ListScanVulnerabilities(
	ctx context.Context,
	scanID string,
	filter domain.ScanVulnerabilityFilter,
	page domain.PageRequest,
) ([]domain.ScanVulnerability, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{scanID, limit + 1}
	where := []string{"cv.scan_report_id = $1"}
	argIdx := 3
	if filter.Severity != "" {
		where = append(where, fmt.Sprintf("COALESCE(v.severity, 'none') = $%d", argIdx))
		args = append(args, filter.Severity)
		argIdx++
	}
	if filter.EffectiveState != "" {
		where = append(where, fmt.Sprintf("COALESCE(rc.effective_state, 'open') = $%d", argIdx))
		args = append(args, filter.EffectiveState)
		argIdx++
	}
	if filter.CVEID != "" {
		where = append(where, fmt.Sprintf("v.cve_id = $%d", argIdx))
		args = append(args, filter.CVEID)
		argIdx++
	}
	if page.Cursor != "" {
		where = append(where, fmt.Sprintf("cv.id > $%d", argIdx))
		args = append(args, page.Cursor)
	}
	query := fmt.Sprintf(`
		SELECT cv.id, v.cve_id, COALESCE(v.severity, 'unknown'),
		       COALESCE(rc.effective_state, 'open'), COALESCE(c.purl, ''), proj.product_id::text,
		       rc.exploit_public, rc.risk_score, rc.epss_score, rc.kev_listed,
		       rc.deterministic_level, rc.blast_radius_score, rc.upstream_vex_coverage
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id AND sr.deleted_at IS NULL
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		LEFT JOIN risk_context rc ON rc.artifact_id = sr.artifact_id
			AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		JOIN component_versions cvn ON cvn.id = cv.component_version_id
		JOIN components c ON c.id = cvn.component_id
		JOIN artifacts a ON a.id = sr.artifact_id
		JOIN versions ver ON ver.id = a.version_id
		JOIN projects proj ON proj.id = ver.project_id
		WHERE %s
		ORDER BY cv.id ASC
		LIMIT $2
	`, strings.Join(where, " AND "))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list scan vulnerabilities: %w", err)
	}
	defer rows.Close()

	var items []domain.ScanVulnerability
	for rows.Next() {
		var item domain.ScanVulnerability
		var exploitPublic *bool
		var riskScore, epssScore, blastRadius *float64
		var kevListed *bool
		var deterministicLevel, upstreamVEX *string
		if err := rows.Scan(
			&item.ID, &item.CVEID, &item.Severity, &item.EffectiveState, &item.ComponentPURL, &item.ProductID,
			&exploitPublic, &riskScore, &epssScore, &kevListed,
			&deterministicLevel, &blastRadius, &upstreamVEX,
		); err != nil {
			return nil, domain.PageResult{}, err
		}
		if exploitPublic != nil || riskScore != nil || epssScore != nil || kevListed != nil ||
			deterministicLevel != nil || blastRadius != nil || upstreamVEX != nil {
			item.Enrichment = &domain.ScanVulnerabilityEnrichment{
				ExploitPublic:       exploitPublic,
				RiskScore:           riskScore,
				EPSSScore:           epssScore,
				KEVListed:           kevListed,
				DeterministicLevel:  deterministicLevel,
				BlastRadiusScore:    blastRadius,
				UpstreamVEXCoverage: upstreamVEX,
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].ID
		items = items[:limit]
	}
	return items, next, nil
}

func (r *PostgresScanQueryRepository) GetProjectProductID(ctx context.Context, projectID string) (string, error) {
	var productID string
	err := r.pool.QueryRow(ctx, `SELECT product_id::text FROM projects WHERE id = $1`, projectID).Scan(&productID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("project %q not found", projectID)
		}
		return "", fmt.Errorf("get project product: %w", err)
	}
	return productID, nil
}

// PostgresComponentCatalogRepository lists catalog components.
type PostgresComponentCatalogRepository struct {
	pool pgQueryPool
}

// NewPostgresComponentCatalogRepository creates a component catalog repository.
func NewPostgresComponentCatalogRepository(pool pgQueryPool) *PostgresComponentCatalogRepository {
	return &PostgresComponentCatalogRepository{pool: pool}
}

func (r *PostgresComponentCatalogRepository) ListComponents(ctx context.Context, purl, productID string, page domain.PageRequest) ([]domain.CatalogComponent, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{limit + 1}
	where := []string{"1=1"}
	argIdx := 2
	if purl != "" {
		where = append(where, fmt.Sprintf("c.purl = $%d", argIdx))
		args = append(args, purl)
		argIdx++
	}
	if productID != "" {
		where = append(where, fmt.Sprintf("proj.product_id = $%d", argIdx))
		args = append(args, productID)
		argIdx++
	}
	if page.Cursor != "" {
		where = append(where, fmt.Sprintf("c.purl > $%d", argIdx))
		args = append(args, page.Cursor)
	}
	query := fmt.Sprintf(`
		SELECT DISTINCT c.purl, c.name, c.ecosystem, cv.version, proj.product_id::text
		FROM components c
		JOIN component_versions cv ON cv.component_id = c.id
		JOIN sboms s ON s.id = cv.sbom_id
		JOIN scan_reports sr ON sr.sbom_id = s.id AND sr.deleted_at IS NULL
		JOIN artifacts a ON a.id = s.artifact_id
		JOIN versions ver ON ver.id = a.version_id
		JOIN projects proj ON proj.id = ver.project_id
		WHERE %s
		ORDER BY c.purl ASC
		LIMIT $1
	`, strings.Join(where, " AND "))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list components: %w", err)
	}
	defer rows.Close()

	var items []domain.CatalogComponent
	for rows.Next() {
		var item domain.CatalogComponent
		if err := rows.Scan(&item.PURL, &item.Name, &item.Ecosystem, &item.Version, &item.ProductID); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].PURL
		items = items[:limit]
	}
	return items, next, nil
}

// PostgresCVEWatchFindingRepository lists watch findings.
type PostgresCVEWatchFindingRepository struct {
	pool pgQueryPool
}

// NewPostgresCVEWatchFindingRepository creates a CVE watch repository.
func NewPostgresCVEWatchFindingRepository(pool pgQueryPool) *PostgresCVEWatchFindingRepository {
	return &PostgresCVEWatchFindingRepository{pool: pool}
}

func (r *PostgresCVEWatchFindingRepository) ListFindings(ctx context.Context, productID, severity string, page domain.PageRequest) ([]domain.CVEWatchFinding, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{limit + 1}
	where := []string{"1=1"}
	argIdx := 2
	if productID != "" {
		where = append(where, fmt.Sprintf("product_id = $%d", argIdx))
		args = append(args, productID)
		argIdx++
	}
	if severity != "" {
		where = append(where, fmt.Sprintf("details->>'severity' = $%d", argIdx))
		args = append(args, severity)
		argIdx++
	}
	if page.Cursor != "" {
		where = append(where, fmt.Sprintf("id > $%d", argIdx))
		args = append(args, page.Cursor)
	}
	query := fmt.Sprintf(`
		SELECT id, cve_id, COALESCE(product_id::text, ''), COALESCE(project_id::text, ''), status, detected_at
		FROM cve_watch_findings
		WHERE %s
		ORDER BY id ASC
		LIMIT $1
	`, strings.Join(where, " AND "))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list cve watch findings: %w", err)
	}
	defer rows.Close()

	var items []domain.CVEWatchFinding
	for rows.Next() {
		var item domain.CVEWatchFinding
		if err := rows.Scan(&item.ID, &item.CVEID, &item.ProductID, &item.ProjectID, &item.Status, &item.DetectedAt); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].ID
		items = items[:limit]
	}
	return items, next, nil
}

// PostgresNotificationConfigRepository manages notification rules.
type PostgresNotificationConfigRepository struct {
	pool pgQueryPool
}

// NewPostgresNotificationConfigRepository creates a notification config repository.
func NewPostgresNotificationConfigRepository(pool pgQueryPool) *PostgresNotificationConfigRepository {
	return &PostgresNotificationConfigRepository{pool: pool}
}

func (r *PostgresNotificationConfigRepository) ListRules(ctx context.Context) ([]domain.NotificationRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, event_type, channel, destination, filter, enabled
		FROM notification_rules
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list notification rules: %w", err)
	}
	defer rows.Close()
	var rules []domain.NotificationRule
	for rows.Next() {
		var rule domain.NotificationRule
		var filterJSON []byte
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.EventType, &rule.Channel, &rule.Destination, &filterJSON, &rule.Enabled,
		); err != nil {
			return nil, err
		}
		if len(filterJSON) > 0 {
			if err := json.Unmarshal(filterJSON, &rule.Filter); err != nil {
				return nil, fmt.Errorf("decode notification rule filter: %w", err)
			}
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *PostgresNotificationConfigRepository) ReplaceRules(ctx context.Context, rules []domain.NotificationRule) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM notification_rules`); err != nil {
		return fmt.Errorf("clear notification rules: %w", err)
	}
	for _, rule := range rules {
		id := rule.ID
		if id == "" {
			id = uuid.NewString()
		}
		filterJSON, err := json.Marshal(rule.Filter)
		if err != nil {
			return fmt.Errorf("encode notification rule filter: %w", err)
		}
		_, err = r.pool.Exec(ctx, `
			INSERT INTO notification_rules (id, name, event_type, channel, destination, filter, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, id, rule.Name, rule.EventType, rule.Channel, rule.Destination, filterJSON, rule.Enabled)
		if err != nil {
			return fmt.Errorf("insert notification rule: %w", err)
		}
	}
	return nil
}

// PostgresScannerConfigRepository stores scanner settings in audit_log metadata bucket.
type PostgresScannerConfigRepository struct {
	pool pgPool
}

const scannerConfigResourceID = "00000000-0000-0000-0000-000000000001"

// NewPostgresScannerConfigRepository creates a scanner config repository.
func NewPostgresScannerConfigRepository(pool pgPool) *PostgresScannerConfigRepository {
	return &PostgresScannerConfigRepository{pool: pool}
}

func (r *PostgresScannerConfigRepository) Get(ctx context.Context) (domain.ScannerSettings, error) {
	var details []byte
	err := r.pool.QueryRow(ctx, `
		SELECT details
		FROM audit_log
		WHERE resource_type = 'scanner_config' AND resource_id = $1
		ORDER BY occurred_at DESC
		LIMIT 1
	`, scannerConfigResourceID).Scan(&details)
	if err != nil {
		if err == pgx.ErrNoRows {
			return defaultScannerSettings(), nil
		}
		return domain.ScannerSettings{}, fmt.Errorf("get scanner config: %w", err)
	}
	var settings domain.ScannerSettings
	if err := json.Unmarshal(details, &settings); err != nil {
		return domain.ScannerSettings{}, fmt.Errorf("decode scanner config: %w", err)
	}
	return settings, nil
}

func (r *PostgresScannerConfigRepository) Save(ctx context.Context, settings domain.ScannerSettings) error {
	payload, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_log (id, actor, action, resource_type, resource_id, details)
		VALUES ($1, 'system', 'UPDATE_SCANNER_CONFIG', 'scanner_config', $2, $3::jsonb)
	`, uuid.NewString(), scannerConfigResourceID, payload)
	if err != nil {
		return fmt.Errorf("save scanner config: %w", err)
	}
	return nil
}

func defaultScannerSettings() domain.ScannerSettings {
	return domain.ScannerSettings{
		EnabledFormats:      []string{"cyclonedx", "spdx", "trivy"},
		MaxComponents:       50000,
		ParseTimeoutSeconds: 300,
	}
}

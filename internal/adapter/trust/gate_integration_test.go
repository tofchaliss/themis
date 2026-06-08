//go:build integration

package trust

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/domain"
)

func TestGateIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dir := t.TempDir()
	_ = dir
	port := uint32(15440)
	dsn := startEmbeddedPostgresAtPort(t, port)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := runMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:integration"
	doc := []byte(cycloneDoc)
	checksum := checksumSHA256(doc)
	sbomID := uuid.NewString()

	if _, err := pool.Exec(ctx, `
		INSERT INTO products (id, name) VALUES ($1, 'integration-product')
	`, productID); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO artifacts (id, artifact_type) VALUES ($1, 'image')
	`, artifactID); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO images (id, artifact_id, product_id, repository, digest)
		VALUES ($1, $2, $3, 'themis/app', $4)
	`, imageID, artifactID, productID, digest); err != nil {
		t.Fatalf("insert image: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, image_digest, checksum_sha256, format, raw_document)
		VALUES ($1, $2, $3, $4, 'cyclonedx', $5::jsonb)
	`, sbomID, imageID, digest, checksum, doc); err != nil {
		t.Fatalf("insert sbom: %v", err)
	}

	repo := NewPostgresRepository(pool)
	audit := NewPostgresAuditRecorder(pool)
	gate := &Gate{Verifier: StubVerifier{}, Repo: repo, Audit: audit}

	duplicateOutcome := gate.Evaluate(ctx, domain.RawArtifact{
		Kind:             domain.ArtifactKindSBOM,
		Format:           "cyclonedx",
		SpecVersion:      "1.5",
		RawDocument:      doc,
		ImageDigest:      digest,
		CIJobID:          "job",
		CIPipelineURL:    "https://ci.example",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
		Actor:            "integration-test",
		SourceIP:         "127.0.0.1",
	}, domain.TrustPolicyStandard)
	if !duplicateOutcome.Accepted || duplicateOutcome.DuplicateID != sbomID {
		t.Fatalf("duplicate outcome = %+v", duplicateOutcome)
	}

	rejectOutcome := gate.Evaluate(ctx, domain.RawArtifact{
		Kind:             domain.ArtifactKindSBOM,
		Format:           "cyclonedx",
		SpecVersion:      "1.5",
		RawDocument:      doc,
		ImageDigest:      "sha256:missing",
		CIJobID:          "job",
		CIPipelineURL:    "https://ci.example",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
		Actor:            "integration-test",
	}, domain.TrustPolicyStandard)
	if rejectOutcome.Accepted || rejectOutcome.Message != "image not found — ingest parent first" {
		t.Fatalf("reject outcome = %+v", rejectOutcome)
	}

	count, err := audit.CountByAction(ctx, domain.AuditActionArtifactAccepted)
	if err != nil {
		t.Fatal(err)
	}
	if count < 1 {
		t.Fatalf("accepted audit count = %d", count)
	}
	rejectedCount, err := audit.CountByAction(ctx, domain.AuditActionArtifactRejected)
	if err != nil {
		t.Fatal(err)
	}
	if rejectedCount < 1 {
		t.Fatalf("rejected audit count = %d", rejectedCount)
	}

	vexDoc := []byte(openvexDoc)
	vexChecksum := checksumSHA256(vexDoc)
	if _, err := pool.Exec(ctx, `
		INSERT INTO vex_documents (id, sbom_document_id, sbom_checksum, checksum_sha256, format, raw_document)
		VALUES ($1, $2, $3, $4, 'openvex', $5::jsonb)
	`, uuid.NewString(), sbomID, checksum, vexChecksum, vexDoc); err != nil {
		t.Fatalf("insert vex: %v", err)
	}

	vexDuplicate := gate.Evaluate(ctx, domain.RawArtifact{
		Kind:             domain.ArtifactKindVEX,
		Format:           "openvex",
		SpecVersion:      "1.0.0",
		RawDocument:      vexDoc,
		SBOMChecksum:     checksum,
		CIJobID:          "job",
		CIPipelineURL:    "https://ci.example",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
		Actor:            "integration-test",
	}, domain.TrustPolicyStandard)
	if !vexDuplicate.Accepted || vexDuplicate.HTTPStatus != 200 {
		t.Fatalf("vex duplicate outcome = %+v", vexDuplicate)
	}

	exists, err := repo.SBOMChecksumExists(ctx, checksum)
	if err != nil || !exists {
		t.Fatalf("SBOMChecksumExists() = %v, %v", exists, err)
	}
}

func runMigrations(dsn, migrationsPath string) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
	}()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

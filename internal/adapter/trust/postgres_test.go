package trust

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/themis-project/themis/internal/domain"
)

type errRow struct{ err error }

func (r errRow) Scan(_ ...any) error { return r.err }

type fakeConn struct {
	queryErr error
	execErr  error
}

func (f fakeConn) QueryRow(context.Context, string, ...any) pgx.Row {
	return errRow{err: f.queryErr}
}

func (f fakeConn) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, f.execErr
}

func TestNewPostgresConstructors(t *testing.T) {
	if repo := NewPostgresRepository(nil); repo == nil {
		t.Fatal("expected repository")
	}
	if audit := NewPostgresAuditRecorder(nil); audit == nil {
		t.Fatal("expected audit recorder")
	}
}

func TestPostgresRepositoryQueryErrors(t *testing.T) {
	ctx := context.Background()
	repo := &PostgresRepository{conn: fakeConn{queryErr: errors.New("query failed")}}

	if _, _, err := repo.FindSBOMByDedupKey(ctx, "a", "b"); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := repo.FindVEXByDedupKey(ctx, "a", "b"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := repo.ImageDigestExists(ctx, "a"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := repo.SBOMChecksumExists(ctx, "a"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPostgresAuditRecorderErrors(t *testing.T) {
	ctx := context.Background()
	audit := &PostgresAuditRecorder{conn: fakeConn{execErr: errors.New("exec failed")}}
	if err := audit.Record(ctx, domain.AuditEntry{
		Actor:        "tester",
		Action:       domain.AuditActionArtifactAccepted,
		ResourceType: "sbom",
		Details:      map[string]string{"message": "ok"},
	}); err == nil {
		t.Fatal("expected exec error")
	}

	auditCount := &PostgresAuditRecorder{conn: fakeConn{queryErr: errors.New("query failed")}}
	if _, err := auditCount.CountByAction(ctx, domain.AuditActionArtifactAccepted); err == nil {
		t.Fatal("expected query error")
	}
}

func TestPostgresRepositoryNoRows(t *testing.T) {
	ctx := context.Background()
	repo := &PostgresRepository{conn: fakeConn{queryErr: pgx.ErrNoRows}}

	if _, found, err := repo.FindSBOMByDedupKey(ctx, "a", "b"); err != nil || found {
		t.Fatalf("FindSBOMByDedupKey() = found=%v err=%v", found, err)
	}
	if _, found, err := repo.FindVEXByDedupKey(ctx, "a", "b"); err != nil || found {
		t.Fatalf("FindVEXByDedupKey() = found=%v err=%v", found, err)
	}
}

func TestRecordAuditMarshalError(t *testing.T) {
	original := jsonMarshalAuditDetails
	jsonMarshalAuditDetails = func(map[string]string) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	t.Cleanup(func() { jsonMarshalAuditDetails = original })

	err := recordAudit(context.Background(), fakeConn{}, domain.AuditEntry{
		Details: map[string]string{"message": "ok"},
	})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

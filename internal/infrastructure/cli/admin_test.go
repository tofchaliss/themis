package cli_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/cli"
)

type memoryAPIKeys struct {
	records []domain.APIKeyRecord
}

func (m *memoryAPIKeys) FindByPrefix(_ context.Context, prefix string) ([]domain.APIKeyRecord, error) {
	var out []domain.APIKeyRecord
	for _, r := range m.records {
		if r.KeyPrefix == prefix {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memoryAPIKeys) FindActiveKeys(context.Context) ([]domain.APIKeyRecord, error) {
	return m.records, nil
}

func (m *memoryAPIKeys) Create(_ context.Context, input domain.APIKeyCreateInput) (domain.APIKeyRecord, error) {
	record := domain.APIKeyRecord{
		ID:        "key-1",
		Name:      input.Name,
		KeyHash:   input.KeyHash,
		KeyPrefix: input.KeyPrefix,
		Scopes:    input.Scopes,
		ExpiresAt: input.ExpiresAt,
	}
	m.records = append(m.records, record)
	return record, nil
}

type revokeErrKeys struct {
	memoryAPIKeys
	revokeErr error
}

func (m *revokeErrKeys) Revoke(context.Context, string) error {
	return m.revokeErr
}

func (m *memoryAPIKeys) Revoke(_ context.Context, keyID string) error {
	for i := range m.records {
		if m.records[i].ID == keyID {
			now := time.Now()
			m.records[i].RevokedAt = &now
			return nil
		}
	}
	return store.ErrAPIKeyNotFound
}

func TestCreateKeyAdminScope(t *testing.T) {
	repo := &memoryAPIKeys{}
	result, err := cli.CreateKey(context.Background(), repo, cli.CreateKeyOptions{
		Name:  "ops",
		Admin: true,
	}, func() (string, error) { return "raw-secret", nil }, func(raw string) (string, error) {
		return "hash:" + raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "key-1" || result.RawKey != "raw-secret" {
		t.Fatalf("result = %+v", result)
	}
	if len(repo.records) != 1 || repo.records[0].KeyHash != "hash:raw-secret" {
		t.Fatalf("records = %+v", repo.records)
	}
}

func TestCreateKeyProductScopeWithExpiry(t *testing.T) {
	repo := &memoryAPIKeys{}
	result, err := cli.CreateKey(context.Background(), repo, cli.CreateKeyOptions{
		ProductID: "11111111-1111-4111-8111-111111111111",
		Expires:   "90d",
	}, func() (string, error) { return "product-key", nil }, func(raw string) (string, error) {
		return "hash:" + raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RawKey != "product-key" {
		t.Fatalf("result = %+v", result)
	}
	if repo.records[0].Scopes[0] != domain.ProductScopePrefix+"11111111-1111-4111-8111-111111111111" {
		t.Fatalf("scopes = %+v", repo.records[0].Scopes)
	}
	if repo.records[0].ExpiresAt == nil {
		t.Fatal("expected expiry")
	}
}

func TestCreateKeyRequiresScope(t *testing.T) {
	_, err := cli.CreateKey(context.Background(), &memoryAPIKeys{}, cli.CreateKeyOptions{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}

func TestRevokeKey(t *testing.T) {
	repo := &memoryAPIKeys{}
	if _, err := cli.CreateKey(context.Background(), repo, cli.CreateKeyOptions{Admin: true}, func() (string, error) {
		return "raw", nil
	}, func(raw string) (string, error) { return raw, nil }); err != nil {
		t.Fatal(err)
	}
	if err := cli.RevokeKey(context.Background(), repo, "key-1"); err != nil {
		t.Fatal(err)
	}
	if repo.records[0].RevokedAt == nil {
		t.Fatal("expected revoked_at")
	}
}

func TestRevokeKeyNotFound(t *testing.T) {
	err := cli.RevokeKey(context.Background(), &memoryAPIKeys{}, "missing")
	if err == nil || !errors.Is(err, store.ErrAPIKeyNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseExpires(t *testing.T) {
	expiresAt, err := cli.ParseExpires("24h")
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt == nil || expiresAt.Before(time.Now()) {
		t.Fatalf("expiresAt = %v", expiresAt)
	}
	if _, err := cli.ParseExpires("bad"); err == nil {
		t.Fatal("expected invalid expiry error")
	}
}

func TestRunAdminUnknownSubcommand(t *testing.T) {
	err := cli.RunAdmin(context.Background(), []string{"rotate-key"})
	if err == nil || !strings.Contains(err.Error(), "unknown admin subcommand") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunAdminMissingSubcommand(t *testing.T) {
	err := cli.RunAdmin(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "admin subcommand required") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunAdminCreateKeyCommand(t *testing.T) {
	t.Cleanup(func() { cli.SetOpenAPIKeyRepository(nil) })
	cli.SetOpenAPIKeyRepository(func(context.Context) (domain.APIKeyRepository, func(), error) {
		return &memoryAPIKeys{}, func() {}, nil
	})
	err := cli.RunAdmin(context.Background(), []string{"create-key", "--admin", "--name", "ops"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunAdminRevokeKeyCommand(t *testing.T) {
	t.Cleanup(func() { cli.SetOpenAPIKeyRepository(nil) })
	repo := &memoryAPIKeys{}
	cli.SetOpenAPIKeyRepository(func(context.Context) (domain.APIKeyRepository, func(), error) {
		return repo, func() {}, nil
	})
	if _, err := cli.CreateKey(context.Background(), repo, cli.CreateKeyOptions{Admin: true}, func() (string, error) {
		return "raw", nil
	}, func(raw string) (string, error) { return raw, nil }); err != nil {
		t.Fatal(err)
	}
	err := cli.RunAdmin(context.Background(), []string{"revoke-key", "--key-id", "key-1"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunAdminCreateKeyValidation(t *testing.T) {
	t.Cleanup(func() { cli.SetOpenAPIKeyRepository(nil) })
	cli.SetOpenAPIKeyRepository(func(context.Context) (domain.APIKeyRepository, func(), error) {
		return &memoryAPIKeys{}, func() {}, nil
	})
	err := cli.RunAdmin(context.Background(), []string{"create-key"})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunAdminRevokeKeyValidation(t *testing.T) {
	err := cli.RunAdmin(context.Background(), []string{"revoke-key"})
	if err == nil || !strings.Contains(err.Error(), "key-id") {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateKeyConflictingScopes(t *testing.T) {
	_, err := cli.CreateKey(context.Background(), &memoryAPIKeys{}, cli.CreateKeyOptions{
		Admin:     true,
		ProductID: "11111111-1111-4111-8111-111111111111",
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("err = %v", err)
	}
}

func TestRevokeKeyRepositoryError(t *testing.T) {
	err := cli.RevokeKey(context.Background(), &revokeErrKeys{revokeErr: errors.New("db down")}, "key-1")
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunAdminCreateKeyInvalidFlag(t *testing.T) {
	err := cli.RunAdmin(context.Background(), []string{"create-key", "-not-a-flag"})
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestParseExpiresInvalidValues(t *testing.T) {
	for _, value := range []string{"0d", "-1h", "abc"} {
		if _, err := cli.ParseExpires(value); err == nil {
			t.Fatalf("expected error for %q", value)
		}
	}
}

func TestRunAdminCreateKeyConfigError(t *testing.T) {
	t.Cleanup(func() { cli.SetOpenAPIKeyRepository(nil) })
	path := filepath.Join(t.TempDir(), "themis.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THEMIS_CONFIG_PATH", path)
	err := cli.RunAdmin(context.Background(), []string{"create-key", "--admin"})
	if err == nil {
		t.Fatal("expected missing dsn error")
	}
}

func TestRevokeKeyEmptyID(t *testing.T) {
	err := cli.RevokeKey(context.Background(), &memoryAPIKeys{}, "  ")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseExpiresDays(t *testing.T) {
	expiresAt, err := cli.ParseExpires("7d")
	if err != nil || expiresAt == nil {
		t.Fatalf("expiresAt=%v err=%v", expiresAt, err)
	}
}

func TestRunAdminRevokeKeyDatabaseError(t *testing.T) {
	t.Cleanup(func() { cli.SetOpenAPIKeyRepository(nil) })
	path := filepath.Join(t.TempDir(), "themis.yaml")
	if err := os.WriteFile(path, []byte("database:\n  dsn: postgres://127.0.0.1:1/nope?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THEMIS_CONFIG_PATH", path)
	err := cli.RunAdmin(context.Background(), []string{"revoke-key", "--key-id", "key-1"})
	if err == nil {
		t.Fatal("expected database connection error")
	}
}

func TestRunAdminCreateKeyDatabaseError(t *testing.T) {
	t.Cleanup(func() { cli.SetOpenAPIKeyRepository(nil) })
	path := filepath.Join(t.TempDir(), "themis.yaml")
	if err := os.WriteFile(path, []byte("database:\n  dsn: postgres://127.0.0.1:1/nope?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THEMIS_CONFIG_PATH", path)
	err := cli.RunAdmin(context.Background(), []string{"create-key", "--admin"})
	if err == nil {
		t.Fatal("expected database connection error")
	}
}

func TestCreateKeyGenerateAndHashErrors(t *testing.T) {
	_, err := cli.CreateKey(context.Background(), &memoryAPIKeys{}, cli.CreateKeyOptions{Admin: true},
		func() (string, error) { return "", errors.New("generate failed") }, nil)
	if err == nil || !strings.Contains(err.Error(), "generate") {
		t.Fatalf("err = %v", err)
	}
	_, err = cli.CreateKey(context.Background(), &memoryAPIKeys{}, cli.CreateKeyOptions{Admin: true},
		func() (string, error) { return "raw", nil }, func(string) (string, error) {
			return "", errors.New("hash failed")
		})
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultGenerateAndHashKey(t *testing.T) {
	raw, err := cli.GenerateAPIKey()
	if err != nil || len(raw) != 64 {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	hash, err := cli.HashAPIKey(raw)
	if err != nil || hash == "" || hash == raw {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
}

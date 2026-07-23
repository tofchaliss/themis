package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestPostgresAPIKeyRepository(t *testing.T) {
	ctx := context.Background()
	future := time.Now().UTC().Add(time.Hour)
	past := time.Now().UTC().Add(-time.Hour)

	activeRows := &fakeRows{data: [][]any{
		{"key-1", "admin", "hash-1", "", []string{"read"}, &future, nil},
		{"key-2", "expired", "hash-2", "", []string{"write"}, &past, nil},
	}}
	listPool := storeFakePool{conn: storeFakeConn{}, rows: activeRows}
	keys, err := NewPostgresAPIKeyRepository(listPool).FindActiveKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].ID != "key-1" {
		t.Fatalf("keys=%+v err=%v", keys, err)
	}

	createPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"key-3", "ops", "hash-3", "", []string{"admin"}, nil, nil}}},
	}}
	record, err := NewPostgresAPIKeyRepository(createPool).Create(ctx, domain.APIKeyCreateInput{
		Name: "ops", KeyHash: "hash-3", Scopes: []string{"admin"},
	})
	if err != nil || record.Name != "ops" {
		t.Fatalf("record=%+v err=%v", record, err)
	}

	revokePool := storeFakePool{conn: storeFakeConn{rowsAffected: 1}}
	if err := NewPostgresAPIKeyRepository(revokePool).Revoke(ctx, "key-1"); err != nil {
		t.Fatal(err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{rowsAffected: 0}}
	if err := NewPostgresAPIKeyRepository(notFoundPool).Revoke(ctx, "missing"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("err=%v", err)
	}

	if _, err := NewPostgresAPIKeyRepository(storeFakePool{conn: storeFakeConn{queryErr: errors.New("boom")}}).FindByPrefix(ctx, "abcd1234"); err == nil {
		t.Fatal("expected query error")
	}

	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	if _, err := NewPostgresAPIKeyRepository(queryErr).FindActiveKeys(ctx); err == nil {
		t.Fatal("expected list keys error")
	}
}

func TestPostgresAPIKeyConstructor(t *testing.T) {
	if NewPostgresAPIKeyRepository(nil) == nil {
		t.Fatal("expected api key repository")
	}
}

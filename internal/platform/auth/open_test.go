package auth

import (
	"context"
	"testing"
)

func TestOpen(t *testing.T) {
	// A well-formed DSN parses (pgxpool connects lazily, so no server is needed here).
	a, closeFn, err := Open(context.Background(), "postgres://u:p@localhost:5432/authdb?sslmode=disable")
	if err != nil {
		t.Fatalf("Open valid dsn: %v", err)
	}
	if a == nil || a.Keys == nil {
		t.Fatalf("Open returned an Authenticator without a key store")
	}
	closeFn()

	// A malformed DSN fails at config parse.
	if _, _, err := Open(context.Background(), "://not-a-dsn"); err == nil {
		t.Errorf("Open malformed dsn: want error, got nil")
	}
}

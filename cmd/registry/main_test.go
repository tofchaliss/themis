package main

import (
	"net/url"
	"strings"
	"testing"
)

// Registry co-locates its tables in Evidence's database, so both binaries migrate the same DB.
// Without a distinct bookkeeping table, golang-migrate's shared `schema_migrations` means
// whichever runs second reads the other's version and silently skips its own CREATE TABLEs.
func TestMigrationDSN_CarriesRegistrysOwnMigrationsTable(t *testing.T) {
	got, err := migrationDSN("postgres://u:p@localhost:5432/evidence?sslmode=disable")
	if err != nil {
		t.Fatalf("migrationDSN: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}
	if u.Query().Get("x-migrations-table") != registryMigrationsTable {
		t.Errorf("x-migrations-table = %q, want %q", u.Query().Get("x-migrations-table"), registryMigrationsTable)
	}
	// Pre-existing parameters must survive — dropping sslmode would change how the migration
	// connects, which is not this function's business.
	if u.Query().Get("sslmode") != "disable" {
		t.Errorf("sslmode = %q, want it preserved", u.Query().Get("sslmode"))
	}
}

// The trap this fixes. Putting x-migrations-table on the SHARED DSN makes migration succeed and
// then kills the service: pgx forwards the unknown parameter to Postgres as a startup option and
// every runtime connection fails with `FATAL: unrecognized configuration parameter`. So the
// input string must come back untouched.
func TestMigrationDSN_DoesNotMutateTheCallersDSN(t *testing.T) {
	const pool = "postgres://u:p@localhost:5432/evidence?sslmode=disable"
	if _, err := migrationDSN(pool); err != nil {
		t.Fatalf("migrationDSN: %v", err)
	}
	if strings.Contains(pool, "x-migrations-table") {
		t.Fatal("the pool DSN was mutated — pgx must never see the migrations-table parameter")
	}
}

func TestMigrationDSN_AddsAQueryStringWhenThereIsNone(t *testing.T) {
	got, err := migrationDSN("postgres://u:p@localhost:5432/evidence")
	if err != nil {
		t.Fatalf("migrationDSN: %v", err)
	}
	if !strings.Contains(got, "x-migrations-table="+registryMigrationsTable) {
		t.Errorf("got %q, want the parameter appended", got)
	}
}

func TestMigrationDSN_RejectsAnUnparseableDSN(t *testing.T) {
	if _, err := migrationDSN("postgres://u:p@%%/evidence"); err == nil {
		t.Error("want an error for an unparseable DSN, so a bad config fails at startup rather than mid-migration")
	}
}

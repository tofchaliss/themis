//go:build integration

package userstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/dashboard/userstore"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "dashboard-userstore-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15588).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping dashboard userstore integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15588/themis?sslmode=disable"
	if err := migrateUp(); err != nil {
		_ = db.Stop()
		panic(err)
	}
	code := m.Run()
	_ = db.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// migrationsDir points at the dashboard's own migrations (../migrations) — the ones
// cmd/dashboard applies against the auth database under dashboard_schema_migrations.
func migrationsDir() string {
	path, _ := filepath.Abs("../migrations")
	return "file://" + path
}

func migrator(t *testing.T) *migrate.Migrate {
	t.Helper()
	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	return m
}

func migrateUp() error {
	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func newStore(t *testing.T) *userstore.Store {
	t.Helper()
	if testDSN == "" {
		t.Skip("no database")
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), `DELETE FROM dashboard_users`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	return userstore.NewStore(pool)
}

// Up and down both work, and down really drops the table — a migration that cannot be
// reversed is a migration nobody can roll back on a bad release.
func TestDashboardMigrations_UpDown(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	if present, err := store.TableExists(ctx); err != nil || !present {
		t.Fatalf("after up: (%v, %v), want the table present", present, err)
	}

	m := migrator(t)
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("down: %v", err)
	}
	_, _ = m.Close()

	if present, err := store.TableExists(ctx); err != nil || present {
		t.Fatalf("after down: (%v, %v), want the table gone", present, err)
	}
	// With the table gone, every store call says exactly that — the one error startup turns
	// into a warning naming THEMIS_DASHBOARD_MIGRATE=1, rather than an opaque failure.
	if _, err := store.GetUser(ctx, userstore.AdminUsername); !errors.Is(err, userstore.ErrTableMissing) {
		t.Errorf("GetUser err = %v, want ErrTableMissing", err)
	}
	if _, err := store.EnsureAdminSeed(ctx); !errors.Is(err, userstore.ErrTableMissing) {
		t.Errorf("EnsureAdminSeed err = %v, want ErrTableMissing", err)
	}
	if _, err := store.UpdatePassword(ctx, userstore.AdminUsername, []byte("x")); !errors.Is(err, userstore.ErrTableMissing) {
		t.Errorf("UpdatePassword err = %v, want ErrTableMissing", err)
	}
	if _, err := store.Exists(ctx, userstore.AdminUsername); !errors.Is(err, userstore.ErrTableMissing) {
		t.Errorf("Exists err = %v, want ErrTableMissing", err)
	}

	if err := migrateUp(); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if present, err := store.TableExists(ctx); err != nil || !present {
		t.Fatalf("after re-up: (%v, %v), want the table back", present, err)
	}
}

// The seed runs on every startup, so "create it once and NEVER overwrite" is the whole
// invariant: a restart must not undo a password the operator changed.
func TestEnsureAdminSeed_CreatesOnceAndNeverOverwrites(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	created, err := store.EnsureAdminSeed(ctx)
	if err != nil || !created {
		t.Fatalf("first seed = (%v, %v), want the row created", created, err)
	}
	u, err := store.GetUser(ctx, userstore.AdminUsername)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !u.IsDefaultPassword {
		t.Error("the seeded row does not flag the default password, so the GUI could not warn about it")
	}
	if bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(userstore.DefaultAdminPassword)) != nil {
		t.Error("the seeded hash does not match the shipped default password")
	}

	// A second startup: no row is created and nothing is touched.
	seeded := u
	for i := 0; i < 2; i++ {
		created, err = store.EnsureAdminSeed(ctx)
		if err != nil || created {
			t.Fatalf("re-seed %d = (%v, %v), want no row created", i, created, err)
		}
	}
	again, err := store.GetUser(ctx, userstore.AdminUsername)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if string(again.PasswordHash) != string(seeded.PasswordHash) || !again.UpdatedAt.Equal(seeded.UpdatedAt) {
		t.Error("a re-seed rewrote the existing row")
	}

	// And a row the operator already changed survives a restart untouched — the failure this
	// invariant exists to prevent: a reboot silently restoring the default password.
	stamp, err := store.UpdatePassword(ctx, userstore.AdminUsername, []byte("their-own-hash"))
	if err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if created, err = store.EnsureAdminSeed(ctx); err != nil || created {
		t.Fatalf("seed after a change = (%v, %v), want no row created", created, err)
	}
	changed, _ := store.GetUser(ctx, userstore.AdminUsername)
	if string(changed.PasswordHash) != "their-own-hash" || changed.IsDefaultPassword || !changed.UpdatedAt.Equal(stamp) {
		t.Errorf("a restart undid the operator's password change: %+v", changed)
	}
}

// UpdatePassword is also the session-invalidation mechanism (D12): the bumped updated_at is
// the stamp every live session is compared against, so the bump is not incidental.
func TestUpdatePassword_StoresTheHashClearsTheFlagAndBumpsTheStamp(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	if _, err := store.EnsureAdminSeed(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := store.GetUser(ctx, userstore.AdminUsername)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte("quiet-mountain"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	stamp, err := store.UpdatePassword(ctx, userstore.AdminUsername, newHash)
	if err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if !stamp.After(before.UpdatedAt) {
		t.Errorf("stamp %v did not advance past %v — every other session would stay valid", stamp, before.UpdatedAt)
	}
	after, err := store.GetUser(ctx, userstore.AdminUsername)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !after.UpdatedAt.Equal(stamp) {
		t.Errorf("returned stamp %v != stored %v — the session would be invalidated by its own change", stamp, after.UpdatedAt)
	}
	if after.IsDefaultPassword {
		t.Error("the default-password flag survived a change")
	}
	if bcrypt.CompareHashAndPassword(after.PasswordHash, []byte("quiet-mountain")) != nil {
		t.Error("the stored hash does not match the new password")
	}

	if _, err := store.UpdatePassword(ctx, "nobody", newHash); !errors.Is(err, userstore.ErrNotFound) {
		t.Errorf("UpdatePassword on a missing row = %v, want ErrNotFound", err)
	}
}

func TestGetUserAndExists(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	if present, err := store.Exists(ctx, userstore.AdminUsername); err != nil || present {
		t.Fatalf("empty table = (%v, %v), want absent", present, err)
	}
	if _, err := store.GetUser(ctx, userstore.AdminUsername); !errors.Is(err, userstore.ErrNotFound) {
		t.Errorf("GetUser on an empty table = %v, want ErrNotFound", err)
	}
	if _, err := store.EnsureAdminSeed(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if present, err := store.Exists(ctx, userstore.AdminUsername); err != nil || !present {
		t.Fatalf("after the seed = (%v, %v), want present", present, err)
	}
}

// A store error that is NOT "table missing" must surface as itself, never as ErrTableMissing
// — the warning naming the migration flag would be a lie, and the operator would chase a
// migration they had already run.
func TestStoreErrorsAreNotMisreadAsAMissingTable(t *testing.T) {
	store := newStore(t)
	dead, cancel := context.WithCancel(context.Background())
	cancel()

	for name, err := range map[string]error{
		"GetUser":     errFrom(func() error { _, e := store.GetUser(dead, userstore.AdminUsername); return e }),
		"TableExists": errFrom(func() error { _, e := store.TableExists(dead); return e }),
		"EnsureAdminSeed": errFrom(func() error {
			_, e := store.EnsureAdminSeed(dead)
			return e
		}),
		"UpdatePassword": errFrom(func() error {
			_, e := store.UpdatePassword(dead, userstore.AdminUsername, []byte("x"))
			return e
		}),
	} {
		if err == nil {
			t.Errorf("%s: want an error on a cancelled context", name)
			continue
		}
		if errors.Is(err, userstore.ErrTableMissing) {
			t.Errorf("%s: a cancelled context was reported as a missing table (%v)", name, err)
		}
	}
}

func errFrom(f func() error) error { return f() }

// The stamp's resolution has to be finer than two consecutive changes, or a second change
// inside the same clock tick would leave the other sessions valid.
func TestUpdatePassword_ConsecutiveChangesGetDistinctStamps(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	if _, err := store.EnsureAdminSeed(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var stamps []time.Time
	for i := 0; i < 3; i++ {
		s, err := store.UpdatePassword(ctx, userstore.AdminUsername, []byte(fmt.Sprintf("hash-%d", i)))
		if err != nil {
			t.Fatalf("change %d: %v", i, err)
		}
		stamps = append(stamps, s)
	}
	for i := 1; i < len(stamps); i++ {
		if !stamps[i].After(stamps[i-1]) {
			t.Errorf("stamp %d (%v) did not advance past %d (%v)", i, stamps[i], i-1, stamps[i-1])
		}
	}
}

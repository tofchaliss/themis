// Command authadmin manages API keys in the shared `auth` database (EDR-SECURITY-01 D6).
//
//	authadmin create-key --name ci --scopes admin[,read,product:<id>] [--ttl 720h]
//	authadmin revoke-key --id key-<uuid>
//
// create-key mints an opaque token, prints it ONCE, and stores only its bcrypt hash;
// revoke-key disables a key by id. Both read the store DSN from THEMIS_AUTH_DATABASE_DSN
// (set THEMIS_AUTH_MIGRATE=1 to apply the auth migrations first).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/platform/auth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "create-key":
		os.Exit(createKey(os.Args[2:]))
	case "revoke-key":
		os.Exit(revokeKey(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  authadmin create-key --name <name> [--scopes admin,read,product:<id>] [--ttl 720h]")
	fmt.Fprintln(os.Stderr, "  authadmin revoke-key --id <key-id>")
	fmt.Fprintln(os.Stderr, "\nreads THEMIS_AUTH_DATABASE_DSN (THEMIS_AUTH_MIGRATE=1 applies migrations first)")
}

func createKey(args []string) int {
	fs := flag.NewFlagSet("create-key", flag.ExitOnError)
	name := fs.String("name", "", "human label for the key (required)")
	scopes := fs.String("scopes", "", "comma-separated scopes: admin,read,product:<id>")
	ttl := fs.Duration("ttl", 0, "optional lifetime, e.g. 720h; 0 = no expiry")
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "create-key: --name is required")
		return 2
	}

	pool, closePool, err := openAuthDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "create-key:", err)
		return 1
	}
	defer closePool()

	raw, hash, err := auth.GenerateKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "create-key:", err)
		return 1
	}
	k := auth.APIKey{
		ID:      "key-" + uuid.NewString(),
		Name:    *name,
		KeyHash: hash,
		Scopes:  parseScopes(*scopes),
	}
	if *ttl > 0 {
		exp := time.Now().Add(*ttl).UTC()
		k.ExpiresAt = &exp
	}
	if err := auth.NewStore(pool).CreateKey(context.Background(), k); err != nil {
		fmt.Fprintln(os.Stderr, "create-key:", err)
		return 1
	}

	fmt.Printf("created key %s (%s) scopes=%v\n", k.ID, k.Name, k.Scopes)
	fmt.Printf("\nAPI key — shown once, store it now:\n\n  %s\n\n", raw)
	return 0
}

func revokeKey(args []string) int {
	fs := flag.NewFlagSet("revoke-key", flag.ExitOnError)
	id := fs.String("id", "", "key id to revoke (required)")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Fprintln(os.Stderr, "revoke-key: --id is required")
		return 2
	}

	pool, closePool, err := openAuthDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke-key:", err)
		return 1
	}
	defer closePool()

	if err := auth.NewStore(pool).RevokeKey(context.Background(), *id); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "revoke-key: no active key %q\n", *id)
			return 1
		}
		fmt.Fprintln(os.Stderr, "revoke-key:", err)
		return 1
	}
	fmt.Printf("revoked key %s\n", *id)
	return 0
}

func openAuthDB() (*pgxpool.Pool, func(), error) {
	dsn := os.Getenv("THEMIS_AUTH_DATABASE_DSN")
	if dsn == "" {
		return nil, nil, errors.New("THEMIS_AUTH_DATABASE_DSN is required")
	}
	if os.Getenv("THEMIS_AUTH_MIGRATE") == "1" {
		path := envDefault("THEMIS_AUTH_MIGRATIONS", auth.DefaultMigrationsPath)
		m, err := migrate.New("file://"+path, dsn)
		if err != nil {
			return nil, nil, err
		}
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			_, _ = m.Close()
			return nil, nil, err
		}
		_, _ = m.Close()
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, nil, err
	}
	return pool, pool.Close, nil
}

func parseScopes(csv string) []string {
	out := []string{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

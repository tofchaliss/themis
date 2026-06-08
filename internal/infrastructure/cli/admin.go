package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	"github.com/themis-project/themis/internal/infrastructure/db"
)

var openAPIKeyRepository = defaultOpenAPIKeyRepository

// CreateKeyResult is returned when a new API key is created.
type CreateKeyResult struct {
	ID     string
	RawKey string
	Scopes []string
}

// KeyGenerator creates random API key material.
type KeyGenerator func() (string, error)

// HashGenerator hashes raw API key material for storage.
type HashGenerator func(raw string) (string, error)

// CreateKeyOptions configures API key creation.
type CreateKeyOptions struct {
	Name      string
	ProductID string
	Admin     bool
	Expires   string
}

// RunAdmin executes admin subcommands.
func RunAdmin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("admin subcommand required (create-key, revoke-key)")
	}
	switch args[0] {
	case "create-key":
		return runCreateKey(ctx, args[1:])
	case "revoke-key":
		return runRevokeKey(ctx, args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runCreateKey(ctx context.Context, args []string) error {
	opts, err := parseCreateKeyArgs(args)
	if err != nil {
		return err
	}
	keys, cleanup, err := openAPIKeyRepository(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	result, err := CreateKey(ctx, keys, opts, nil, nil)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "key_id=%s\n", result.ID)
	_, _ = fmt.Fprintf(os.Stdout, "api_key=%s\n", result.RawKey)
	return nil
}

func runRevokeKey(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("revoke-key", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	keyID := fs.String("key-id", "", "API key id to revoke")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*keyID) == "" {
		return errors.New("--key-id is required")
	}

	keys, cleanup, err := openAPIKeyRepository(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := RevokeKey(ctx, keys, strings.TrimSpace(*keyID)); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "revoked key_id=%s\n", strings.TrimSpace(*keyID))
	return nil
}

// CreateKey generates, hashes, and stores a new API key.
func CreateKey(
	ctx context.Context,
	keys domain.APIKeyRepository,
	opts CreateKeyOptions,
	generate KeyGenerator,
	hash HashGenerator,
) (CreateKeyResult, error) {
	if generate == nil {
		generate = defaultGenerateKey
	}
	if hash == nil {
		hash = defaultHashKey
	}

	scopes, err := scopesForCreate(opts)
	if err != nil {
		return CreateKeyResult{}, err
	}
	expiresAt, err := ParseExpires(opts.Expires)
	if err != nil {
		return CreateKeyResult{}, err
	}

	rawKey, err := generate()
	if err != nil {
		return CreateKeyResult{}, fmt.Errorf("generate api key: %w", err)
	}
	keyHash, err := hash(rawKey)
	if err != nil {
		return CreateKeyResult{}, fmt.Errorf("hash api key: %w", err)
	}

	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = "cli-created"
	}

	record, err := keys.Create(ctx, domain.APIKeyCreateInput{
		Name:      name,
		KeyHash:   keyHash,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return CreateKeyResult{}, err
	}
	return CreateKeyResult{ID: record.ID, RawKey: rawKey, Scopes: record.Scopes}, nil
}

// RevokeKey marks an API key as revoked.
func RevokeKey(ctx context.Context, keys domain.APIKeyRepository, keyID string) error {
	if strings.TrimSpace(keyID) == "" {
		return errors.New("key id is required")
	}
	if err := keys.Revoke(ctx, keyID); err != nil {
		if errors.Is(err, store.ErrAPIKeyNotFound) {
			return fmt.Errorf("revoke api key: %w", err)
		}
		return err
	}
	return nil
}

func parseCreateKeyArgs(args []string) (CreateKeyOptions, error) {
	fs := flag.NewFlagSet("create-key", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "cli-created", "Human-readable key name")
	productID := fs.String("product-id", "", "Product scope for the key")
	admin := fs.Bool("admin", false, "Create a global admin key")
	expires := fs.String("expires", "", "Optional expiry duration (e.g. 90d, 24h)")
	if err := fs.Parse(args); err != nil {
		return CreateKeyOptions{}, err
	}
	return CreateKeyOptions{
		Name:      *name,
		ProductID: strings.TrimSpace(*productID),
		Admin:     *admin,
		Expires:   strings.TrimSpace(*expires),
	}, nil
}

func scopesForCreate(opts CreateKeyOptions) ([]string, error) {
	switch {
	case opts.Admin && opts.ProductID != "":
		return nil, errors.New("specify either --admin or --product-id, not both")
	case opts.Admin:
		return []string{domain.ScopeAdmin}, nil
	case opts.ProductID != "":
		return []string{domain.ProductScopePrefix + opts.ProductID}, nil
	default:
		return nil, errors.New("either --admin or --product-id is required")
	}
}

// ParseExpires converts CLI expiry values such as 90d or 24h.
func ParseExpires(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil || days <= 0 {
			return nil, fmt.Errorf("invalid expiry duration %q", value)
		}
		expiresAt := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		return &expiresAt, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return nil, fmt.Errorf("invalid expiry duration %q", value)
	}
	expiresAt := time.Now().Add(duration)
	return &expiresAt, nil
}

func defaultGenerateKey() (string, error) {
	return GenerateAPIKey()
}

func defaultHashKey(raw string) (string, error) {
	return HashAPIKey(raw)
}

// GenerateAPIKey returns random API key material.
func GenerateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// HashAPIKey hashes raw API key material for storage.
func HashAPIKey(raw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// SetOpenAPIKeyRepository overrides repository wiring for tests.
func SetOpenAPIKeyRepository(
	opener func(context.Context) (domain.APIKeyRepository, func(), error),
) {
	if opener == nil {
		openAPIKeyRepository = defaultOpenAPIKeyRepository
		return
	}
	openAPIKeyRepository = opener
}

func defaultOpenAPIKeyRepository(ctx context.Context) (domain.APIKeyRepository, func(), error) {
	configPath := os.Getenv("THEMIS_CONFIG_PATH")
	if configPath == "" {
		configPath = "themis.yaml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	pool, err := db.Connect(ctx, cfg.Database.DSN, cfg.Database.MaxPoolSize)
	if err != nil {
		return nil, nil, err
	}
	return store.NewPostgresAPIKeyRepository(pool), func() { pool.Close() }, nil
}

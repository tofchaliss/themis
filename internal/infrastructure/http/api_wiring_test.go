package httpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/infrastructure/config"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestMountAPIWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	workers, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     queue.NewMemoryJobStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := workers.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		_ = workers.Stop(stopCtx)
	})

	router := chi.NewRouter()
	MountAPI(ctx, router, APIConfig{
		Pool: mountFakePool{},
		AppConfig: config.Config{
			Upload:    config.UploadConfig{MaxSizeBytes: 1024},
			Trust:     config.TrustConfig{DefaultPolicy: config.TrustPolicyStandard},
			Webhook:   config.WebhookConfig{Secret: "test-webhook"},
			EPSSKev:   config.EPSSKevConfig{PollInterval: time.Hour},
			ExploitDB: config.ExploitDBConfig{PollInterval: time.Hour},
			VEXFeed:   config.VEXFeedConfig{PollInterval: time.Hour},
			NVD:       config.NVDConfig{PollInterval: time.Hour},
			OSV:       config.OSVConfig{RateLimitRPS: 1},
			SMTP:      config.SMTPConfig{Host: "localhost", Port: 25, From: "test@example.com"},
			Worker:    config.WorkerConfig{MaxRetry: 1, BaseDelay: time.Millisecond},
		},
		InProcessQueue: workers,
	})
}

func TestNVDRateLimit(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.NVDConfig
		want float64
	}{
		{"explicit override wins", config.NVDConfig{RateLimitRPS: 3, APIKey: "k"}, 3},
		{"keyed auto", config.NVDConfig{APIKey: "k"}, 1.5},
		{"unkeyed auto", config.NVDConfig{}, 0.15},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nvdRateLimit(tc.cfg); got != tc.want {
				t.Fatalf("nvdRateLimit(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestPresentOrAbsent(t *testing.T) {
	if got := presentOrAbsent("some-secret"); got != "present" {
		t.Fatalf("present case = %q", got)
	}
	if got := presentOrAbsent(""); got != "absent" {
		t.Fatalf("absent case = %q", got)
	}
}

type mountFakePool struct{}

func (mountFakePool) QueryRow(context.Context, string, ...any) pgx.Row {
	return mountErrRow{err: pgx.ErrNoRows}
}

func (mountFakePool) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (mountFakePool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return mountEmptyRows{}, nil
}

func (mountFakePool) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("tx unavailable in mount fake pool")
}

type mountErrRow struct{ err error }

func (r mountErrRow) Scan(...any) error { return r.err }

type mountEmptyRows struct{}

func (mountEmptyRows) Close()                                       {}
func (mountEmptyRows) Err() error                                   { return nil }
func (mountEmptyRows) Next() bool                                   { return false }
func (mountEmptyRows) Scan(...any) error                            { return errors.New("scan") }
func (mountEmptyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (mountEmptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (mountEmptyRows) RawValues() [][]byte                          { return nil }
func (mountEmptyRows) Values() ([]any, error)                       { return nil, nil }
func (mountEmptyRows) Conn() *pgx.Conn                              { return nil }

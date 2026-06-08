//go:build integration

package httpserver_test

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

func startAPIIntegrationPostgres(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	port := uint32(15450)
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		})

	var lastErr error
	for attempt := range 5 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		dbInstance := embeddedpostgres.NewDatabase(cfg)
		if err := dbInstance.Start(); err != nil {
			lastErr = err
			continue
		}
		t.Cleanup(func() {
			_ = dbInstance.Stop()
		})
		return "postgres://themis:themis@localhost:" + strconv.FormatUint(uint64(port), 10) + "/themis?sslmode=disable"
	}
	t.Skipf("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres): %v", lastErr)
	return ""
}

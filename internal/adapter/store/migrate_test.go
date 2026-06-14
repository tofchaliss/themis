package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/themis-project/themis/internal/adapter/store"
)

func TestBinarySchemaVersion(t *testing.T) {
	if store.BinarySchemaVersion != 19 {
		t.Fatalf("BinarySchemaVersion = %d, want 19", store.BinarySchemaVersion)
	}
}

func TestParseMigrationVersion(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    uint
		wantErr bool
	}{
		{name: "up migration", file: "000001_layer1.up.sql", want: 1},
		{name: "down migration", file: "000009_indexes.down.sql", want: 9},
		{name: "path prefix", file: filepath.Join("migrations", "000003_layer1_components.up.sql"), want: 3},
		{name: "missing underscore", file: "000001layer1.up.sql", wantErr: true},
		{name: "invalid suffix", file: "000001_layer1.sql", wantErr: true},
		{name: "non numeric", file: "00000a_layer1.up.sql", wantErr: true},
		{name: "zero version", file: "000000_layer1.up.sql", wantErr: true},
		{name: "too short", file: "1.up.sql", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.ParseMigrationVersion(tt.file)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMigrationVersion() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseMigrationVersion() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSortVersions(t *testing.T) {
	got := store.SortVersions([]uint{9, 1, 5, 3})
	want := []uint{1, 3, 5, 9}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SortVersions() = %v, want %v", got, want)
		}
	}
}

func TestValidateMigrationSet(t *testing.T) {
	valid := []string{
		"000001_layer1_products_artifacts.up.sql",
		"000001_layer1_products_artifacts.down.sql",
		"000002_layer1_sbom_documents.up.sql",
		"000002_layer1_sbom_documents.down.sql",
		"000003_layer1_components.up.sql",
		"000003_layer1_components.down.sql",
		"000004_layer1_vulnerabilities.up.sql",
		"000004_layer1_vulnerabilities.down.sql",
		"000005_layer2_vex.up.sql",
		"000005_layer2_vex.down.sql",
		"000006_layer2_intelligence.up.sql",
		"000006_layer2_intelligence.down.sql",
		"000007_layer3_risk_context.up.sql",
		"000007_layer3_risk_context.down.sql",
		"000008_operational_tables.up.sql",
		"000008_operational_tables.down.sql",
		"000009_indexes.up.sql",
		"000009_indexes.down.sql",
		"000010_risk_context_enrichment.up.sql",
		"000010_risk_context_enrichment.down.sql",
		"000011_triage_history.up.sql",
		"000011_triage_history.down.sql",
		"000012_system_state.up.sql",
		"000012_system_state.down.sql",
		"000013_vulnerability_package_index.up.sql",
		"000013_vulnerability_package_index.down.sql",
		"000014_phase2a_asset_graph.up.sql",
		"000014_phase2a_asset_graph.down.sql",
		"000015_epss_kev_signals.up.sql",
		"000015_epss_kev_signals.down.sql",
		"000016_risk_context_phase2a.up.sql",
		"000016_risk_context_phase2a.down.sql",
		"000017_phase2a_indexes.up.sql",
		"000017_phase2a_indexes.down.sql",
		"000018_sbom_soft_delete.up.sql",
		"000018_sbom_soft_delete.down.sql",
		"000019_vendor_vex_feed.up.sql",
		"000019_vendor_vex_feed.down.sql",
	}

	if err := store.ValidateMigrationSet(valid); err != nil {
		t.Fatalf("ValidateMigrationSet(valid) error = %v", err)
	}

	tests := []struct {
		name string
		files []string
	}{
		{name: "empty", files: nil},
		{name: "missing down", files: []string{"000001_layer1.up.sql"}},
		{name: "ahead of binary", files: []string{
			"000010_future.up.sql",
			"000010_future.down.sql",
		}},
		{name: "invalid filename", files: []string{"bad-name.sql"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.ValidateMigrationSet(tt.files); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestListMigrationFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "000001_test.up.sql"), []byte(""), 0o600); err != nil {
		t.Fatalf("write up migration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "000001_test.down.sql"), []byte(""), 0o600); err != nil {
		t.Fatalf("write down migration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(""), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	files, err := store.ListMigrationFiles(dir)
	if err != nil {
		t.Fatalf("ListMigrationFiles() error = %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("ListMigrationFiles() = %v, want 2 files", files)
	}
	if files[0] != "000001_test.down.sql" || files[1] != "000001_test.up.sql" {
		t.Fatalf("unexpected sort order: %v", files)
	}

	if _, err := store.ListMigrationFiles(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing directory error")
	}
}

func TestCompareSchemaVersion(t *testing.T) {
	if err := store.CompareSchemaVersion(9, false, store.BinarySchemaVersion); err != nil {
		t.Fatalf("matching version: %v", err)
	}
	if err := store.CompareSchemaVersion(1, false, store.BinarySchemaVersion); err != nil {
		t.Fatalf("older version: %v", err)
	}
	if err := store.CompareSchemaVersion(2, true, store.BinarySchemaVersion); err == nil {
		t.Fatal("expected dirty error")
	}

	err := store.CompareSchemaVersion(store.BinarySchemaVersion+1, false, store.BinarySchemaVersion)
	if !errors.Is(err, store.ErrSchemaAhead) {
		t.Fatalf("expected ErrSchemaAhead, got %v", err)
	}
}

func TestExpectedTablesAndIndexes(t *testing.T) {
	tables := store.ExpectedTables()
	if len(tables) != 31 {
		t.Fatalf("ExpectedTables() len = %d, want 31", len(tables))
	}

	missing := store.MissingTables([]string{"products", "projects"})
	if len(missing) != 29 {
		t.Fatalf("MissingTables() len = %d, want 29", len(missing))
	}

	indexes := store.ExpectedIndexes()
	if len(indexes) != 10 {
		t.Fatalf("ExpectedIndexes() len = %d, want 10", len(indexes))
	}

	missingIndexes := store.MissingIndexes([]string{indexes[0]})
	if len(missingIndexes) != 9 {
		t.Fatalf("MissingIndexes() len = %d, want 9", len(missingIndexes))
	}
}

func TestValidateRepositoryMigrationSet(t *testing.T) {
	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	files, err := store.ListMigrationFiles(migrationsPath)
	if err != nil {
		t.Fatalf("ListMigrationFiles() error = %v", err)
	}
	if err := store.ValidateMigrationSet(files); err != nil {
		t.Fatalf("ValidateMigrationSet() error = %v", err)
	}
}

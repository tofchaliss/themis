package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// BinarySchemaVersion is the highest migration version embedded in this binary.
const BinarySchemaVersion uint = 19

// ErrSchemaAhead indicates the database schema is newer than this binary supports.
var ErrSchemaAhead = errors.New("database schema version is ahead of binary version")

// ParseMigrationVersion extracts the numeric prefix from a migration filename.
func ParseMigrationVersion(filename string) (uint, error) {
	base := filepath.Base(filename)
	if len(base) < 8 {
		return 0, fmt.Errorf("invalid migration filename %q", filename)
	}

	versionPart := base[:6]
	if base[6] != '_' {
		return 0, fmt.Errorf("invalid migration filename %q", filename)
	}

	version, err := strconv.ParseUint(versionPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid migration version in %q: %w", filename, err)
	}
	if version == 0 {
		return 0, fmt.Errorf("invalid migration version in %q", filename)
	}

	lower := strings.ToLower(base)
	if !strings.HasSuffix(lower, ".up.sql") && !strings.HasSuffix(lower, ".down.sql") {
		return 0, fmt.Errorf("invalid migration filename %q", filename)
	}

	return uint(version), nil
}

// SortVersions returns a sorted copy of migration version numbers.
func SortVersions(versions []uint) []uint {
	sorted := slices.Clone(versions)
	slices.Sort(sorted)
	return sorted
}

// ValidateMigrationSet ensures migration files form a contiguous up/down pair set.
func ValidateMigrationSet(filenames []string) error {
	if len(filenames) == 0 {
		return errors.New("no migration files")
	}

	ups := make(map[uint]struct{})
	downs := make(map[uint]struct{})

	for _, name := range filenames {
		version, err := ParseMigrationVersion(name)
		if err != nil {
			return err
		}

		lower := strings.ToLower(filepath.Base(name))
		switch {
		case strings.HasSuffix(lower, ".up.sql"):
			ups[version] = struct{}{}
		case strings.HasSuffix(lower, ".down.sql"):
			downs[version] = struct{}{}
		default:
			return fmt.Errorf("invalid migration filename %q", name)
		}

		if version > BinarySchemaVersion {
			return fmt.Errorf(
				"migration version %d exceeds binary schema version %d",
				version,
				BinarySchemaVersion,
			)
		}
	}

	for version := uint(1); version <= BinarySchemaVersion; version++ {
		if _, ok := ups[version]; !ok {
			return fmt.Errorf("missing up migration for version %d", version)
		}
		if _, ok := downs[version]; !ok {
			return fmt.Errorf("missing down migration for version %d", version)
		}
	}

	return nil
}

// ListMigrationFiles returns sorted SQL migration filenames from dir.
func ListMigrationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migration directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".up.sql") || strings.HasSuffix(lower, ".down.sql") {
			files = append(files, name)
		}
	}

	slices.Sort(files)
	return files, nil
}

// CompareSchemaVersion validates the database schema version against the binary.
func CompareSchemaVersion(dbVersion uint, dirty bool, binaryVersion uint) error {
	if dirty {
		return fmt.Errorf("database schema version %d is dirty", dbVersion)
	}
	if dbVersion > binaryVersion {
		return fmt.Errorf("%w: db=%d binary=%d", ErrSchemaAhead, dbVersion, binaryVersion)
	}
	return nil
}

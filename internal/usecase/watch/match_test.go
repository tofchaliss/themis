package watch_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/watch"
)

func TestVersionMatches(t *testing.T) {
	tests := []struct {
		name      string
		affected  []string
		version   string
		wantMatch bool
	}{
		{name: "empty affected matches all", affected: nil, version: "1.0.0", wantMatch: true},
		{name: "exact match", affected: []string{"4.17.21"}, version: "4.17.21", wantMatch: true},
		{name: "wildcard", affected: []string{"*"}, version: "9.9.9", wantMatch: true},
		{name: "no match", affected: []string{"1.0.0"}, version: "2.0.0", wantMatch: false},
		{name: "less than boundary affected", affected: []string{"< 4.17.21"}, version: "4.17.20", wantMatch: true},
		{name: "less than boundary not affected", affected: []string{"< 4.17.21"}, version: "4.17.21", wantMatch: false},
		{name: "less than or equal boundary", affected: []string{"<= 4.17.21"}, version: "4.17.21", wantMatch: true},
		{name: "greater than boundary", affected: []string{"> 2.0.0"}, version: "2.0.1", wantMatch: true},
		{name: "greater than or equal boundary", affected: []string{">= 2.0.0"}, version: "2.0.0", wantMatch: true},
		{name: "greater than not affected", affected: []string{"> 2.0.0"}, version: "1.0.0", wantMatch: false},
		{name: "shorter version compared", affected: []string{"> 1.0"}, version: "1.0.0", wantMatch: true},
		{name: "lexicographic less than", affected: []string{"< 2.0"}, version: "1.9", wantMatch: true},
		{name: "lexicographic greater than", affected: []string{"> 1.5"}, version: "2.0", wantMatch: true},
		{name: "equal version parts", affected: []string{">= 1.0.0"}, version: "1.0.0", wantMatch: true},
		{name: "shorter version less than bound", affected: []string{"< 1.0.0"}, version: "1.0", wantMatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := watch.VersionMatches(tt.affected, tt.version)
			if got != tt.wantMatch {
				t.Fatalf("VersionMatches(%v, %q) = %v, want %v", tt.affected, tt.version, got, tt.wantMatch)
			}
		})
	}
}

func TestGroupByEcosystem(t *testing.T) {
	entries := []domain.WatchCatalogEntry{
		{Ecosystem: "npm", Name: "a"},
		{Ecosystem: "npm", Name: "b"},
		{Ecosystem: "maven", Name: "c"},
	}
	grouped := watch.GroupByEcosystem(entries)
	if len(grouped["npm"]) != 2 || len(grouped["maven"]) != 1 {
		t.Fatalf("grouped = %#v", grouped)
	}
}

func TestUniquePackageNames(t *testing.T) {
	entries := []domain.WatchCatalogEntry{
		{Name: "lodash"},
		{Name: "lodash"},
		{Name: "express"},
	}
	names := watch.UniquePackageNames(entries)
	if len(names) != 2 {
		t.Fatalf("names = %#v", names)
	}
}

func TestUniquePackageNamesSkipsEmpty(t *testing.T) {
	names := watch.UniquePackageNames([]domain.WatchCatalogEntry{{Name: ""}})
	if len(names) != 0 {
		t.Fatalf("names = %#v", names)
	}
}

func TestPackageMatches(t *testing.T) {
	entry := domain.WatchCatalogEntry{Name: "lodash", Ecosystem: "npm", Version: "1.0.0"}
	if !watch.PackageMatches(domain.FeedVulnerability{PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"1.0.0"}}, entry) {
		t.Fatal("expected match")
	}
	if watch.PackageMatches(domain.FeedVulnerability{PackageName: "express", Ecosystem: "npm"}, entry) {
		t.Fatal("expected name mismatch")
	}
	if watch.PackageMatches(domain.FeedVulnerability{PackageName: "lodash", Ecosystem: "maven"}, entry) {
		t.Fatal("expected ecosystem mismatch")
	}
}

func TestCompareVersionsPadding(t *testing.T) {
	if !watch.VersionMatches([]string{">= 1.0"}, "1.0.0") {
		t.Fatal("expected padded version comparison")
	}
}

func TestMatchCatalog(t *testing.T) {
	entries := []domain.WatchCatalogEntry{
		{Name: "lodash", Ecosystem: "npm", Version: "4.17.20"},
		{Name: "lodash", Ecosystem: "npm", Version: "4.17.21"},
	}
	vulns := []domain.FeedVulnerability{
		{PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"< 4.17.21"}},
	}
	pairs := watch.MatchCatalog(entries, vulns)
	if len(pairs) != 1 {
		t.Fatalf("pairs = %d, want 1", len(pairs))
	}
}

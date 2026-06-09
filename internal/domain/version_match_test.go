package domain

import "testing"

func TestNormalizeEcosystem(t *testing.T) {
	tests := map[string]string{
		"golang": "go",
		"Go":     "go",
		"python": "pypi",
		"npm":    "npm",
		"nuget":  "nuget",
		"cargo":  "cargo",
	}
	for in, want := range tests {
		if got := NormalizeEcosystem(in); got != want {
			t.Fatalf("NormalizeEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPackageIdentityMatch(t *testing.T) {
	if !PackageIdentityMatch("npm", "lodash", "npm", "lodash") {
		t.Fatal("expected exact npm match")
	}
	if !PackageIdentityMatch("Maven", "commons-lang3", "maven", "org.apache.commons:commons-lang3") {
		t.Fatal("expected maven artifact suffix match")
	}
	if PackageIdentityMatch("npm", "lodash", "pypi", "lodash") {
		t.Fatal("ecosystem mismatch should not match")
	}
	if PackageIdentityMatch("npm", "", "npm", "lodash") {
		t.Fatal("empty package name should not match")
	}
	if !PackageIdentityMatch("maven", "org.apache.commons:commons-lang3", "maven", "commons-lang3") {
		t.Fatal("expected record name suffix match")
	}
	if PackageIdentityMatch("npm", "other", "npm", "lodash") {
		t.Fatal("unrelated names should not match")
	}
}

func TestCompareVersions(t *testing.T) {
	if CompareVersions("1.0.0", "1.0.0") != 0 {
		t.Fatal("expected equal versions")
	}
	if CompareVersions("1.0", "1.0.1") >= 0 {
		t.Fatal("expected left version lower")
	}
	if CompareVersions("2.0.0", "1.9.9") <= 0 {
		t.Fatal("expected left version higher")
	}
	if CompareVersions("1.", "1.0") >= 0 {
		t.Fatal("expected shorter segment to compare lower")
	}
	if CompareVersions("1.0.0", "1.0") <= 0 {
		t.Fatal("expected longer left version to compare higher")
	}
}

func TestVersionMatches(t *testing.T) {
	tests := []struct {
		name      string
		affected  []string
		version   string
		wantMatch bool
	}{
		{"empty affected", nil, "1.2.3", true},
		{"exact", []string{"1.2.3"}, "1.2.3", true},
		{"wildcard", []string{"*"}, "9.9.9", true},
		{"unknown", []string{"unknown"}, "0.0.1", true},
		{"less than spaced", []string{"< 2.0.0"}, "1.9.9", true},
		{"less than spaced miss", []string{"< 2.0.0"}, "2.0.0", false},
		{"less or equal", []string{"<= 2.0.0"}, "2.0.0", true},
		{"greater or equal", []string{">= 1.0.0"}, "1.0.0", true},
		{"greater than", []string{"> 1.0.0"}, "1.0.1", true},
	}
	for _, tc := range tests {
		got := VersionMatches(tc.affected, tc.version)
		if got != tc.wantMatch {
			t.Fatalf("%s: VersionMatches(%v, %q) = %v, want %v", tc.name, tc.affected, tc.version, got, tc.wantMatch)
		}
	}
}

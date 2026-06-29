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

// TestPackageIdentityMatchDistroAuthoritative locks in the el8 openssl over-match
// fix: an upstream NVD catalog row (stored ecosystem-less, "openssl:openssl") must
// NOT name-match an rpm/apk component, because a distro component's CVEs come only
// from its backport-aware distro feed. Genuine same-distro-class rows still match,
// and app ecosystems keep the looser blank-ecosystem name match.
func TestPackageIdentityMatchDistroAuthoritative(t *testing.T) {
	tests := []struct {
		name                          string
		recEco, recName, compEco, comp string
		want                          bool
	}{
		// The bug: empty-ecosystem NVD openssl flagged every upstream CVE on el8.
		{"nvd empty-eco rejected for rpm", "", "openssl", "rpm", "openssl", false},
		{"nvd empty-eco rejected for apk", "", "openssl", "apk", "openssl", false},
		// Genuine distro-feed rows (same class) still match — rpm/rocky/redhat all RPM.
		{"rpm record matches rpm component", "rpm", "openssl", "rpm", "openssl", true},
		{"rocky record matches rpm component", "rocky", "openssl", "rpm", "openssl", true},
		{"alpine record matches apk component", "alpine", "busybox", "apk", "busybox", true},
		// Cross-distro-class never matches (apk fix never applies to rpm).
		{"apk record rejected for rpm component", "apk", "openssl", "rpm", "openssl", false},
		// App ecosystems keep the looser blank-record-ecosystem name match unchanged.
		{"npm component keeps blank-eco name match", "", "lodash", "npm", "lodash", true},
		{"generic component keeps blank-eco name match", "", "lodash", "", "lodash", true},
	}
	for _, tc := range tests {
		if got := PackageIdentityMatch(tc.recEco, tc.recName, tc.compEco, tc.comp); got != tc.want {
			t.Errorf("%s: PackageIdentityMatch(%q,%q,%q,%q) = %v, want %v",
				tc.name, tc.recEco, tc.recName, tc.compEco, tc.comp, got, tc.want)
		}
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

// TestCompareVersionsNumericAndApk locks in the two ordering bugs the lexical
// comparator had: multi-digit minor versions and Alpine apk "-rN" suffixes.
func TestCompareVersionsNumericAndApk(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"8.14.1", "8.9.0", 1},          // 14 > 9 numerically (lexical wrongly said <)
		{"8.9.0", "8.14.1", -1},         // antisymmetric
		{"8.14.1-r2", "8.5.0-r0", 1},    // multi-digit minor with apk revision
		{"8.14.1-r2", "8.14.1-r10", -1}, // r10 newer than r2 (numeric revision)
		{"8.14.1-r2", "8.14.1", 1},      // a revision is newer than none
		{"8.14.1", "8.14.1-r2", -1},
		{"1.0a", "1.0b", -1},  // letter run compare
		{"1.0a", "1.0", 1},    // numeric/none then letter remainder is newer
		{"1.0", "1.0a", -1},   // mirror
		{"10", "9", 1},        // multi-digit run length
		{"1.2", "1.2a", -1},   // left exhausts, right has letter remainder
		{"1.a", "1.0", -1},    // same position: numeric (right) outranks letter (left)
		{"1.0", "1.a", 1},     // mirror of the type-mismatch branch
		{"01.0", "1.0", 0},    // leading zeros ignored
		{"1.2.3", "1.2.3", 0}, // equal
	}
	for _, tc := range tests {
		if got := CompareVersions(tc.left, tc.right); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
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
		// AND within a group: both bounds of a range must hold.
		{"range inside", []string{">= 1.0.0, < 2.0.0"}, "1.5.0", true},
		{"range above fixed", []string{">= 1.0.0, < 2.0.0"}, "2.0.0", false},
		{"range below introduced", []string{">= 1.0.0, < 2.0.0"}, "0.9.0", false},
		// OR across groups: any group may match.
		{"two groups second matches", []string{">= 1.0.0, < 2.0.0", ">= 3.0.0, < 4.0.0"}, "3.1.0", true},
		{"two groups none match", []string{">= 1.0.0, < 2.0.0", ">= 3.0.0, < 4.0.0"}, "2.5.0", false},
		// Sentinels.
		{"none matches nothing", []string{"none"}, "1.0.0", false},
		{"star matches", []string{"*"}, "1.0.0", true},
		// Empty sub-constraint (trailing comma) is skipped, not failed.
		{"trailing comma", []string{">= 1.0.0, "}, "1.5.0", true},
		// Exact version that does not equal -> no match (default branch).
		{"exact mismatch", []string{"2.0.0"}, "1.0.0", false},
		// Regression: a single range must NOT be satisfied by its lower bound
		// alone. curl 8.14.1 vs CVE-2014-0138 (affected >= 7, fixed in 7.36).
		{"curl over-match regression", []string{">= 7.0.0, < 7.36.0"}, "8.14.1", false},
	}
	for _, tc := range tests {
		got := VersionMatches(tc.affected, tc.version)
		if got != tc.wantMatch {
			t.Fatalf("%s: VersionMatches(%v, %q) = %v, want %v", tc.name, tc.affected, tc.version, got, tc.wantMatch)
		}
	}
}

func TestVersionedPURL(t *testing.T) {
	if got := VersionedPURL("pkg:apk/busybox", "1.36"); got != "pkg:apk/busybox@1.36" {
		t.Fatalf("VersionedPURL with version = %q, want pkg:apk/busybox@1.36", got)
	}
	if got := VersionedPURL("pkg:apk/busybox", ""); got != "pkg:apk/busybox" {
		t.Fatalf("VersionedPURL empty version = %q, want pkg:apk/busybox", got)
	}
	// Idempotent: a purl that already carries a version (real Syft/Trivy form,
	// with qualifiers) must not be double-versioned.
	already := "pkg:apk/alpine/curl@8.14.1-r2?arch=x86_64&distro=3.20.2"
	if got := VersionedPURL(already, "8.14.1-r2"); got != already {
		t.Fatalf("VersionedPURL already-versioned = %q, want unchanged %q", got, already)
	}
	// Scoped npm namespaces encode @ as %40, so a versionless scoped purl still
	// gets its version appended.
	if got := VersionedPURL("pkg:npm/%40babel/core", "7.0.0"); got != "pkg:npm/%40babel/core@7.0.0" {
		t.Fatalf("VersionedPURL scoped npm = %q, want pkg:npm/%%40babel/core@7.0.0", got)
	}
}

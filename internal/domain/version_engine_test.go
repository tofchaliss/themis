package domain

import "testing"

func TestClassifyEcosystem(t *testing.T) {
	tests := map[string]VersionClass{
		"apk":          VersionClassAPK,
		"Alpine":       VersionClassAPK,
		"alpine":       VersionClassAPK,
		"rpm":          VersionClassRPM,
		"redhat":       VersionClassRPM,
		"RHEL":         VersionClassRPM,
		"Rocky Linux":  VersionClassRPM,
		"almalinux":    VersionClassRPM,
		"fedora":       VersionClassRPM,
		"Rocky Linux 9": VersionClassRPM,
		"wolfi":         VersionClassAPK,
		"Wolfi":         VersionClassAPK,
		"npm":          VersionClassGeneric,
		"maven":        VersionClassGeneric,
		"":             VersionClassGeneric,
		"some-distro-alpine-edge": VersionClassAPK,
	}
	for in, want := range tests {
		if got := ClassifyEcosystem(in); got != want {
			t.Errorf("ClassifyEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersionsEcoGeneric(t *testing.T) {
	if CompareVersionsEco("", "1.0", "1.0.1") >= 0 {
		t.Fatal("generic: expected lower")
	}
	if CompareVersionsEco("npm", "2.0.0", "1.9.9") <= 0 {
		t.Fatal("generic: expected higher")
	}
}

func TestCompareVersionsEcoAPK(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.36.1-r2", "1.36.1-r5", -1},
		{"1.36.1-r5", "1.36.1-r2", 1},
		{"1.36.1-r2", "1.36.1-r2", 0},
		{"1.2.3-r0", "1.2.3", 1},  // an explicit build revision is newer than none
		{"1.2.3", "1.2.3-r0", -1}, // mirror: left shorter
		{"3.20.2", "3.9.0", 1},    // multi-digit minor compares numerically
		{"3.9.0", "3.20.2", -1},   // numeric ai<bi branch
		{"01", "1", 0},            // numeric-equal via different strings
		{"abc", "abd", -1},        // pure alpha strings.Compare fallback
	}
	for _, tc := range tests {
		if got := CompareVersionsEco("apk", tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersionsEco(apk, %q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareVersionsEcoRPM(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1:2.0-1", "0:3.0-1", 1},  // higher epoch wins (else branch)
		{"0:2.0-1", "1:3.0-1", -1}, // lower epoch loses (return -1 branch)
		{"0:1.0-1", "1.0-1", 0},    // explicit epoch 0 == no epoch
		{"x:1.0", "1.0", -1},       // non-numeric epoch falls back (Atoi error); leading alpha loses to numeric
		{"1.0-2", "1.0-1", 1},      // release compare
		{"1.0-10", "1.0-2", 1},     // numeric release: a more digits
		{"1.0-2", "1.0-10", -1},    // numeric release: b more digits
		{"1.0", "1_0", 0},          // segment-equal but not byte-equal → both exhausted
		{"1.0", "1.0", 0},          // identical short-circuit
		{"1.0~rc1", "1.0", -1},     // tilde pre-release sorts before release
		{"1.0~rc1", "1.0~rc2", -1}, // both tilde
		{"1.0", "1.0~rc1", 1},      // mirror
		{"1.a", "1.0", -1},         // alpha vs numeric type mismatch (numeric newer)
		{"1.0", "1.a", 1},          // mirror type mismatch
		{"1.0.1", "1.0", 1},        // left has extra segment
		{"1.0", "1.0.1", -1},       // right has extra segment
		{"2.4.37-43.el8", "2.4.37-30.el8", 1},
	}
	for _, tc := range tests {
		if got := CompareVersionsEco("rpm", tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersionsEco(rpm, %q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestStripPURLVersionQualifiers(t *testing.T) {
	tests := map[string]string{
		"8.14.1-r2?arch=x86_64&distro=3.20.2": "8.14.1-r2",
		"1.2.3#subpath":                       "1.2.3",
		"1.2.3":                               "1.2.3",
		"":                                    "",
	}
	for in, want := range tests {
		if got := StripPURLVersionQualifiers(in); got != want {
			t.Errorf("StripPURLVersionQualifiers(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildConstraintGroup(t *testing.T) {
	tests := []struct {
		name                               string
		lowerIncl, lowerExcl, upIncl, upEx string
		want                               string
	}{
		{"full range incl/excl", "2.0", "", "", "2.5", ">= 2.0, < 2.5"},
		{"exclusive lower", "", "1.0", "", "2.0", "> 1.0, < 2.0"},
		{"inclusive upper", "1.0", "", "2.0", "", ">= 1.0, <= 2.0"},
		{"zero lower dropped", "0", "", "", "2.5", "< 2.5"},
		{"empty all", "", "", "", "", ""},
		{"only lower", "1.0", "", "", "", ">= 1.0"},
	}
	for _, tc := range tests {
		if got := BuildConstraintGroup(tc.lowerIncl, tc.lowerExcl, tc.upIncl, tc.upEx); got != tc.want {
			t.Errorf("%s: BuildConstraintGroup = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestNVDOverMatchRegression is the exact D-NVD-1 counterexample: a CPE range
// [2.0, 2.5) built via BuildConstraintGroup must match only versions in that
// interval — never a 1.x. Mirrors the OSV over-match regression.
func TestNVDOverMatchRegression(t *testing.T) {
	group := BuildConstraintGroup("2.0", "", "", "2.5")
	set := VersionConstraintSet{Ecosystem: "npm", Groups: []string{group}}
	if set.Matches("1.0") {
		t.Fatal("1.0 must NOT match [2.0, 2.5)")
	}
	if set.Matches("0.9") {
		t.Fatal("0.9 must NOT match [2.0, 2.5)")
	}
	if !set.Matches("2.3") {
		t.Fatal("2.3 must match [2.0, 2.5)")
	}
	if set.Matches("2.5") {
		t.Fatal("2.5 must NOT match (upper exclusive)")
	}
}

func TestVersionConstraintSetMatches(t *testing.T) {
	set := VersionConstraintSet{Ecosystem: "apk", Groups: []string{">= 1.36.1-r0, < 1.36.1-r5"}}
	if !set.Matches("1.36.1-r2") {
		t.Fatal("apk r2 should be inside [r0, r5)")
	}
	if set.Matches("1.36.1-r5") {
		t.Fatal("apk r5 should be excluded (upper exclusive)")
	}
}

func TestVersionMatchesEcoFallback(t *testing.T) {
	// Empty ecosystem must behave exactly like VersionMatches.
	if VersionMatchesEco("", []string{">= 1.0.0, < 2.0.0"}, "1.5.0") != VersionMatches([]string{">= 1.0.0, < 2.0.0"}, "1.5.0") {
		t.Fatal("eco fallback diverges from VersionMatches")
	}
	if !VersionMatchesEco("", nil, "9.9.9") {
		t.Fatal("empty affected matches all")
	}
}

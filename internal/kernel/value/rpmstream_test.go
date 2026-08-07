package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestRPMReleaseMajor(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.0.2k-16.el8_10", "8"},
		{"openssl-1:1.0.2k-16.el8_10.x86_64", "8"},
		{"0:3.0.1-47.el9_3", "9"},
		{"1.0-1.el10_0", "10"},                    // two-digit major
		{"8.14.1-r2?arch=x86_64&distro=3.20", ""}, // apk-style, no .el marker
		{"1.2.3-4", ""},                           // no release stream marker
		{"", ""},
	}
	for _, tc := range cases {
		if got := value.RPMReleaseMajor(tc.in); got != tc.want {
			t.Errorf("RPMReleaseMajor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRPMFixedByStream(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		installed string
		fixes     []string
		want      bool
	}{
		{
			name:      "installed above same-stream fix is fixed",
			ecosystem: "rhel", installed: "1.0.2k-17.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: true,
		},
		{
			name:      "installed equal to same-stream fix is fixed",
			ecosystem: "rocky", installed: "1.0.2k-16.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10.x86_64"}, want: true,
		},
		{
			name:      "installed below same-stream fix stays affected",
			ecosystem: "rhel", installed: "1.0.2k-15.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: false,
		},
		{
			name:      "cross-major fix is never compared (no false fixed)",
			ecosystem: "rhel", installed: "1.0.2k-99.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el9_2"}, want: false,
		},
		{
			name:      "picks the matching-major fix among several",
			ecosystem: "almalinux", installed: "1.0.2k-20.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el9_2", "openssl-1.0.2k-16.el8_10"}, want: true,
		},
		{
			name:      "install without an el marker is undecidable → not fixed",
			ecosystem: "rhel", installed: "1.0.2k-16",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: false,
		},
		{
			name:      "non-rpm ecosystem is never stream-fixed here",
			ecosystem: "npm", installed: "1.0.2k-17.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: false,
		},
		{
			name:      "no fixes → not fixed",
			ecosystem: "rhel", installed: "1.0.2k-17.el8_10",
			fixes: nil, want: false,
		},
		{
			name:      "epoch-only fix outranks an epoch-less install → conservative not fixed",
			ecosystem: "rhel", installed: "1.0.2k-16.el8_10",
			fixes: []string{"openssl-1:1.0.2k-16.el8_10"}, want: false,
		},
		{
			// Defensive: a hyphenless (malformed) version must normalize without panicking.
			name:      "hyphenless install/fix normalize without a name split",
			ecosystem: "rhel", installed: "5.el8",
			fixes: []string{"3-1.el8"}, want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := value.RPMFixedByStream(tc.ecosystem, tc.installed, tc.fixes); got != tc.want {
				t.Errorf("RPMFixedByStream(%q, %q, %v) = %v, want %v", tc.ecosystem, tc.installed, tc.fixes, got, tc.want)
			}
		})
	}
}

// RPMPackageName is what lets a vendor fix stated as a NEVRA be ATTRIBUTED to its package. A fix
// whose package cannot be recovered must return "" rather than a guess: an unattributed fix is
// excluded from per-component verdicts, and a wrong attribution would reintroduce KN-FIX-1.
func TestRPMPackageName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"openssl-1:1.0.2k-16.el8", "openssl"},
		{"python3-ply-3.9-9.el8", "python3-ply"},      // a name containing hyphens
		{"openssl-1:1.0.2k-16.el8.x86_64", "openssl"}, // arch suffix stripped
		{"1:1.0.2k-16.el8", ""},                       // bare EVR names nothing
		{"1.0.2k-16.el8", ""},                         // bare VR names nothing
		{"", ""},                                      // nothing at all
		{"nohyphens", ""},                             // unparseable
	} {
		if got := value.RPMPackageName(tc.in); got != tc.want {
			t.Errorf("RPMPackageName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// KN-MODULE-1: a modular advisory lists every RPM rebuilt in the stream, so a fix attributed to a
// package may be a stream rebuild rather than a fix to that package. Labelling it is what lets a
// consumer prefer a direct fix without discarding the module one (which IS valid remediation).
func TestIsRPMModuleStream(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"0:3.11-10.module+el8.10.0+1582+bc278001", true},
		{"0:5.4.1-1.module+el8.9.0+1418+f0d66789", true},
		{"0:4.19.4-16.el8_10", false}, // a normal package fix
		{"0:2.28-251.el8_10.38", false},
		{"3.11", false}, // a bare upstream version
		{"", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if got := value.IsRPMModuleStream(tc.version); got != tc.want {
				t.Errorf("IsRPMModuleStream(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

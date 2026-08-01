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
		{"1.0-1.el10_0", "10"},                       // two-digit major
		{"8.14.1-r2?arch=x86_64&distro=3.20", ""},     // apk-style, no .el marker
		{"1.2.3-4", ""},                               // no release stream marker
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
			name: "installed above same-stream fix is fixed",
			ecosystem: "rhel", installed: "1.0.2k-17.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: true,
		},
		{
			name: "installed equal to same-stream fix is fixed",
			ecosystem: "rocky", installed: "1.0.2k-16.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10.x86_64"}, want: true,
		},
		{
			name: "installed below same-stream fix stays affected",
			ecosystem: "rhel", installed: "1.0.2k-15.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: false,
		},
		{
			name: "cross-major fix is never compared (no false fixed)",
			ecosystem: "rhel", installed: "1.0.2k-99.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el9_2"}, want: false,
		},
		{
			name: "picks the matching-major fix among several",
			ecosystem: "almalinux", installed: "1.0.2k-20.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el9_2", "openssl-1.0.2k-16.el8_10"}, want: true,
		},
		{
			name: "install without an el marker is undecidable → not fixed",
			ecosystem: "rhel", installed: "1.0.2k-16",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: false,
		},
		{
			name: "non-rpm ecosystem is never stream-fixed here",
			ecosystem: "npm", installed: "1.0.2k-17.el8_10",
			fixes: []string{"openssl-1.0.2k-16.el8_10"}, want: false,
		},
		{
			name: "no fixes → not fixed",
			ecosystem: "rhel", installed: "1.0.2k-17.el8_10",
			fixes: nil, want: false,
		},
		{
			name: "epoch-only fix outranks an epoch-less install → conservative not fixed",
			ecosystem: "rhel", installed: "1.0.2k-16.el8_10",
			fixes: []string{"openssl-1:1.0.2k-16.el8_10"}, want: false,
		},
		{
			// Defensive: a hyphenless (malformed) version must normalize without panicking.
			name: "hyphenless install/fix normalize without a name split",
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

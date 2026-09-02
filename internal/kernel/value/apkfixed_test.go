package value

import (
	"strconv"
	"testing"

	"pgregory.net/rapid"
)

func TestAPKFixedByBounds(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		installed string
		bounds    []string
		want      bool
	}{
		// The D9 busybox scenario: two branches' bounds on one card. Installed between them
		// must stay affected — "≥ any bound" would be the cross-branch false-"fixed".
		{"between two branch bounds stays affected", "apk", "1.36.0-r2", []string{"1.35.0-r10", "1.36.1-r0"}, false},
		{"at or above every bound is fixed", "apk", "1.36.1-r0", []string{"1.35.0-r10", "1.36.1-r0"}, true},
		{"above every bound is fixed", "apk", "1.36.1-r1", []string{"1.35.0-r10", "1.36.1-r0"}, true},
		{"single bound, installed below", "apk", "5.30.2-r0", []string{"5.30.3-r0"}, false},
		{"single bound, installed at", "apk", "5.30.3-r0", []string{"5.30.3-r0"}, true},
		{"revision ordering decides", "apk", "1.2.4-r0", []string{"1.2.4-r1"}, false},
		{"suffix orders below release", "apk", "1.2.4_rc1", []string{"1.2.4"}, false},

		// The version-class guard: only apk-family ecosystems ever decide.
		{"rpm ecosystem never decides", "rpm", "1.36.1-r0", []string{"1.35.0-r10"}, false},
		{"generic ecosystem never decides", "npm", "2.0.0", []string{"1.0.0"}, false},
		{"alpine ecosystem name classifies as apk", "alpine", "1.36.1-r0", []string{"1.36.1-r0"}, true},
		{"wolfi classifies as apk", "wolfi", "1.36.1-r0", []string{"1.36.1-r0"}, true},

		// No evidence is never a verdict.
		{"empty bound set decides nothing", "apk", "1.36.1-r0", nil, false},
		{"all-blank bounds decide nothing", "apk", "1.36.1-r0", []string{"", "  "}, false},
		{"blank installed decides nothing", "apk", "  ", []string{"1.36.1-r0"}, false},
		{"blank bound skipped, real bound still decides", "apk", "1.36.1-r0", []string{"", "1.36.1-r0"}, true},

		// PURL qualifier debris strips before comparison.
		{"qualifier stripped from installed", "apk", "1.36.1-r0?arch=x86_64", []string{"1.36.1-r0"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := APKFixedByBounds(tc.ecosystem, tc.installed, tc.bounds); got != tc.want {
				t.Fatalf("APKFixedByBounds(%q, %q, %v) = %v, want %v",
					tc.ecosystem, tc.installed, tc.bounds, got, tc.want)
			}
		})
	}
}

// The two safety invariants of the max-bound rule (EDR-VEX-01 D9), as executable
// properties over arbitrary apk-shaped versions.
func TestAPKFixedByBoundsProperty(t *testing.T) {
	apkVersion := rapid.Custom(func(t *rapid.T) string {
		major := rapid.IntRange(0, 20).Draw(t, "major")
		minor := rapid.IntRange(0, 40).Draw(t, "minor")
		patch := rapid.IntRange(0, 40).Draw(t, "patch")
		rev := rapid.IntRange(0, 15).Draw(t, "rev")
		return strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(patch) +
			"-r" + strconv.Itoa(rev)
	})

	// Fixed implies at-or-above each bound INDIVIDUALLY — the verdict never rests on a
	// bound the installed version is below.
	t.Run("fixed implies >= every bound", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			installed := apkVersion.Draw(t, "installed")
			bounds := rapid.SliceOfN(apkVersion, 1, 5).Draw(t, "bounds")
			if !APKFixedByBounds("apk", installed, bounds) {
				return
			}
			for _, b := range bounds {
				if compareAPKVersion(installed, b) < 0 {
					t.Fatalf("verdict fixed but installed %q < bound %q", installed, b)
				}
			}
		})
	})

	// Adding a bound can only flip fixed→affected, never affected→fixed: new evidence
	// never makes the verdict LESS cautious (the safe direction of the max rule).
	t.Run("adding a bound never flips affected to fixed", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			installed := apkVersion.Draw(t, "installed")
			bounds := rapid.SliceOfN(apkVersion, 1, 5).Draw(t, "bounds")
			extra := apkVersion.Draw(t, "extra")
			if !APKFixedByBounds("apk", installed, bounds) &&
				APKFixedByBounds("apk", installed, append(append([]string(nil), bounds...), extra)) {
				t.Fatalf("affected at %v flipped to fixed by adding bound %q", bounds, extra)
			}
		})
	})
}

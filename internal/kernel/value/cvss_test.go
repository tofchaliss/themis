package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestNewCVSS_Valid(t *testing.T) {
	c, err := value.NewCVSS(9.8, "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ")
	if err != nil {
		t.Fatalf("valid cvss: %v", err)
	}
	if c.Score() != 9.8 {
		t.Errorf("Score = %v, want 9.8", c.Score())
	}
	if c.Vector() != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("Vector not trimmed: %q", c.Vector())
	}
	if c.Severity() != value.SeverityCritical {
		t.Errorf("Severity = %q, want critical", c.Severity())
	}
	if c.IsZero() {
		t.Error("constructed cvss reports IsZero")
	}
}

func TestNewCVSS_Invalid(t *testing.T) {
	for name, score := range map[string]float64{
		"negative": -0.1,
		"tooHigh":  10.1,
	} {
		if _, err := value.NewCVSS(score, ""); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestCVSS_Zero(t *testing.T) {
	var zero value.CVSS
	if !zero.IsZero() {
		t.Error("zero cvss should report IsZero")
	}
	// A score of 0 with no vector is treated as unset.
	empty, err := value.NewCVSS(0, "")
	if err != nil {
		t.Fatalf("cvss(0): %v", err)
	}
	if !empty.IsZero() {
		t.Error("cvss(0, \"\") should report IsZero")
	}
	if empty.Severity() != value.SeverityNone {
		t.Errorf("Severity for score 0 = %q, want none", empty.Severity())
	}
}

// Scores checked against the CVSS 3.1 specification's own worked examples and the FIRST
// calculator. A derived score is only trustworthy if it matches the published formula exactly —
// an approximation here would silently mis-band vulnerabilities across the whole estate.
func TestBaseScoreFromVector(t *testing.T) {
	for _, tc := range []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // critical, unchanged scope
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5}, // high, confidentiality only
		// 3.8, hand-verified against the spec: ISC_base = 1-(1-0.22)^3 = 0.5254;
		// impact = 6.42*0.5254 = 3.3734; exploitability = 8.22*0.55*0.44*0.27*0.62 = 0.3330;
		// sum 3.7064, rounded UP to one decimal = 3.8. (The fixture first said 3.9 — the
		// implementation was right and the expectation was not.)
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0}, // changed scope, capped at 10
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},  // 3.0 uses the same base formula
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},    // no impact scores zero

		// Privileges-Required is weighted DIFFERENTLY when the scope changes: crossing a security
		// boundary makes the privileges the attacker started with matter less. Every PR × scope
		// combination is exercised, because a mis-weighted PR shifts a score by a whole band.
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8}, // PR:L, scope unchanged (0.62)
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9}, // PR:L, scope changed   (0.68)
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2}, // PR:H, scope unchanged (0.27)
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1}, // PR:H, scope changed   (0.50)
	} {
		if got := value.BaseScoreFromVector(tc.vector); got != tc.want {
			t.Errorf("value.BaseScoreFromVector(%q) = %v, want %v", tc.vector, got, tc.want)
		}
	}
}

// Anything the formula does not cover returns 0 — DEFER, never a wrong number. A fabricated score
// would band a vulnerability confidently and wrongly, which is worse than admitting ignorance.
func TestBaseScoreFromVector_UncomputableIsZero(t *testing.T) {
	for _, v := range []string{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", // v4 uses a different formula
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",                       // v2
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N",                     // missing the impact metrics
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // an unrecognised attack vector
		"CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H",     // an unrecognised privileges-required
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",     // an unrecognised scope
		"garbage", "",
	} {
		if got := value.BaseScoreFromVector(v); got != 0 {
			t.Errorf("value.BaseScoreFromVector(%q) = %v, want 0 (defer)", v, got)
		}
	}
}

// A feed publishing several vectors must not have the FIRST one decide the enterprise's severity.
// OSV lists CVSS_V2, CVSS_V3 and CVSS_V4 side by side, and the OSV ACL took index 0 — so a v2
// vector could silently outrank a v3.1 one.
func TestPreferredCVSSVector(t *testing.T) {
	v2 := "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	v30 := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v31 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v40 := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"

	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"v3.1 beats everything we can score", []string{v2, v40, v30, v31}, v31},
		{"v3.0 beats v4.0 and v2", []string{v2, v40, v30}, v30},
		{"v4.0 beats v2", []string{v2, v40}, v40},
		{"v2 alone is still better than nothing", []string{v2}, v2},
		{"unrecognised vectors are ignored", []string{"garbage", v31}, v31},
		{"nothing usable yields nothing", []string{"garbage", ""}, ""},
		{"no vectors at all", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := value.PreferredCVSSVector(tc.in); got != tc.want {
				t.Errorf("value.PreferredCVSSVector = %q, want %q", got, tc.want)
			}
		})
	}
}

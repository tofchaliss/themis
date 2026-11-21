package value_test

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/kernel/value"
)

func mustCVSS3(t *testing.T, s string) value.CVSS3Vector {
	t.Helper()
	v, err := value.ParseCVSS3(s)
	if err != nil {
		t.Fatalf("ParseCVSS3(%q): %v", s, err)
	}
	return v
}

// The EDR-SCORING-01 section 11 candidate vectors and well-known published scores.
func TestCVSS3ScoresKnownVectors(t *testing.T) {
	cases := []struct {
		vector         string
		base, tmp, env float64
	}{
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:U/RL:O/RC:C", 6.8, 5.9, 5.9},
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:U/RL:O/RC:C/CR:H/IR:M/AR:H", 6.8, 5.9, 6.5},
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:U/RL:O/RC:C/CR:L/IR:L/AR:L", 6.8, 5.9, 4.2},
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/RL:O/CR:H/IR:M/AR:H", 6.8, 6.5, 7.2},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, 9.8, 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10, 10, 10},
		{"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, 6.4, 6.4},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, 0, 0},
		// 3.0 and 3.1 differ in the changed-scope modified impact.
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MS:C", 7.8, 7.2, 9.3},
		{"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MS:C", 7.8, 7.2, 9.2},
	}
	for _, c := range cases {
		got := mustCVSS3(t, c.vector).Scores()
		if got.Base != c.base || got.Temporal != c.tmp || got.Environmental != c.env {
			t.Errorf("%s: got %+v, want %.1f/%.1f/%.1f", c.vector, got, c.base, c.tmp, c.env)
		}
	}
}

// Differential test against an independent implementation (testdata header names it). The file is
// generated outside the repository; Themis is never validated only against itself.
func TestCVSS3ScoresMatchOracle(t *testing.T) {
	f, err := os.Open("testdata/cvss3_oracle.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 4 {
			t.Fatalf("bad oracle line %q", line)
		}
		want := make([]float64, 3)
		for i := range want {
			if want[i], err = strconv.ParseFloat(cols[i+1], 64); err != nil {
				t.Fatalf("bad oracle number in %q", line)
			}
		}
		got := mustCVSS3(t, cols[0]).Scores()
		if got.Base != want[0] || got.Temporal != want[1] || got.Environmental != want[2] {
			t.Errorf("%s: got %+v, oracle %v", cols[0], got, want)
		}
		n++
	}
	if n < 500 {
		t.Fatalf("oracle has only %d vectors", n)
	}
}

func TestParseCVSS3Refusals(t *testing.T) {
	for _, s := range []string{
		"",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",          // A missing
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Z",  // bad value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:N", // unknown metric
		"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // duplicate
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",     // empty component
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A",        // no value
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      // X not allowed on base
	} {
		if _, err := value.ParseCVSS3(s); !errors.Is(err, value.ErrCVSS3Vector) {
			t.Errorf("ParseCVSS3(%q) err = %v, want ErrCVSS3Vector", s, err)
		}
	}
}

func TestCVSS3VectorAccessorsAndCanonical(t *testing.T) {
	v := mustCVSS3(t, "  CVSS:3.0/A:H/I:N/C:H/S:U/UI:N/PR:L/AC:H/AV:N/E:X/CR:H  ")
	if v.Version() != value.CVSS30 {
		t.Errorf("version %q", v.Version())
	}
	if v.Metric("E") != "X" || v.Metric("RL") != "X" || v.Metric("CR") != "H" || v.Metric("nope") != "" {
		t.Errorf("metrics: E=%q RL=%q CR=%q", v.Metric("E"), v.Metric("RL"), v.Metric("CR"))
	}
	if got, want := v.String(), "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/CR:H"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if mustCVSS3(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").Version() != value.CVSS31 {
		t.Error("3.1 version")
	}
}

// Properties: canonical form is stable and scores-preserving; Temporal never exceeds Base;
// with S:U and every Environmental metric X, Environmental equals Temporal; scores stay in range.
func TestCVSS3Property(t *testing.T) {
	pick := func(t *rapid.T, key string, vals ...string) string {
		return key + ":" + rapid.SampledFrom(vals).Draw(t, key)
	}
	rapid.Check(t, func(t *rapid.T) {
		ver := rapid.SampledFrom([]string{"3.0", "3.1"}).Draw(t, "ver")
		parts := []string{"CVSS:" + ver,
			pick(t, "AV", "N", "A", "L", "P"), pick(t, "AC", "L", "H"), pick(t, "PR", "N", "L", "H"),
			pick(t, "UI", "N", "R"), "S:U", pick(t, "C", "H", "L", "N"), pick(t, "I", "H", "L", "N"),
			pick(t, "A", "H", "L", "N"), pick(t, "E", "X", "H", "F", "P", "U"),
			pick(t, "RL", "X", "U", "W", "T", "O"), pick(t, "RC", "X", "C", "R", "U")}
		v, err := value.ParseCVSS3(strings.Join(parts, "/"))
		if err != nil {
			t.Fatal(err)
		}
		s := v.Scores()
		if s.Temporal > s.Base || s.Base < 0 || s.Base > 10 {
			t.Fatalf("out of order or range: %+v", s)
		}
		if s.Environmental != s.Temporal {
			t.Fatalf("S:U, env all X: environmental %.1f != temporal %.1f", s.Environmental, s.Temporal)
		}
		again, err := value.ParseCVSS3(v.String())
		if err != nil || again.String() != v.String() || again.Scores() != s {
			t.Fatalf("canonical round trip changed %q", v.String())
		}
	})
}

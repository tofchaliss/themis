package report

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// GUI-15: the Grype dialect, born tested. There is no earlier implementation to be
// byte-equal with, so the committed golden freezes THIS converter's bytes — the
// fingerprint contract from the day the dialect exists.
func TestGrypeConvertMatchesGolden(t *testing.T) {
	body := readFixture(t, "grype", "sample.input.json")
	got, stats, err := Convert(body, time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if stats.FindingsTotal != 6 || stats.FindingsSkipped != 2 {
		t.Errorf("stats = %+v, want total=6 skipped=2", stats)
	}
	if want := readFixture(t, "grype", goldenName("sample.input.json")); string(got) != string(want) {
		g, w := firstDiff(string(got), string(want))
		t.Errorf("output differs from the committed golden:\n got: %q\nwant: %q", g, w)
	}
}

// The identity judgements byte-equality cannot see.
func TestGrypeSemanticInvariants(t *testing.T) {
	findings := convertAndDecode(t, "grype", "sample.input.json", "")
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4 kept of 6 considered", len(findings))
	}
	// A GHSA-keyed match takes its related CVE; the score is the 3.x one, not the 2.0 one.
	if f := findings[0]; f.CVE != "CVE-2020-14343" || f.CVSSScore != 9.8 || !strings.HasPrefix(f.CVSSVector, "CVSS:3.1") ||
		f.Component.Ecosystem != "pypi" || f.Component.PURL != "pkg:pypi/pyyaml@5.3" || f.Fixed[0] != "5.4" || f.Scanner != "grype" {
		t.Errorf("first = %+v", f)
	}
	if f := findings[0]; f.ObservedAt != "2026-10-19T09:30:00.500Z" {
		t.Errorf("observed_at = %q, want the descriptor timestamp with three fractional digits", f.ObservedAt)
	}
	// Two fix versions are both kept; a CVE id stays as it is.
	if f := findings[1]; f.CVE != "CVE-2023-45803" || len(f.Fixed) != 2 || f.CVSSScore != 4.2 {
		t.Errorf("second = %+v", f)
	}
	// No purl stays no purl (never invented); an unmapped type passes through; no fix is none.
	if f := findings[2]; f.Component.PURL != "" || f.Component.Ecosystem != "rpm" || len(f.Fixed) != 0 || f.CVSSScore != 0 {
		t.Errorf("third = %+v", f)
	}
	// A GHSA with no related CVE keeps the GHSA id; a zero 3.x score is no score.
	if f := findings[3]; f.CVE != "GHSA-zzzz-zzzz-zzzz" || f.CVSSScore != 0 || f.CVSSVector != "" {
		t.Errorf("fourth = %+v", f)
	}
}

func TestGrypeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"not utf-8", "{\"matches\":[],\"descriptor\":{\"name\":\"grype\"},\"x\":\"\xff\"}", ErrMalformedBody},
		{"not an object", `[]`, ErrMalformedBody},
		{"does not parse", `{"matches":[`, ErrMalformedBody},
		{"a match of the wrong shape", `{"matches":[{"vulnerability":"CVE-1","artifact":{"name":"x"}}],"descriptor":{"name":"grype","timestamp":"2026-01-01T00:00:00Z"}}`, ErrSourceInvalid},
		{"no timestamp and none supplied", `{"matches":[],"descriptor":{"name":"grype"}}`, ErrObservedAtUnderivable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := grypeJSON{}.Convert([]byte(tc.body), time.Time{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// A supplied observed_at rescues a report with no timestamp (D3).
	out, stats, err := grypeJSON{}.Convert([]byte(`{"matches":[],"descriptor":{"name":"grype"}}`), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil || stats.FindingsTotal != 0 || string(out) != `{"findings":[]}` {
		t.Fatalf("supplied: %q %+v %v", out, stats, err)
	}
	if (grypeJSON{}).Version() != "grype@1" {
		t.Error("version")
	}
}

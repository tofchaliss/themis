package report

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// curatedSample is a well-formed curated report: the shape the pipeline reads and
// the only vulnerability-report shape Evidence files.
const curatedSample = `{"findings":[
  {"cve":"CVE-2024-2961","observed_at":"2025-09-29T07:23:22Z","scanner":"cortex","severity":"High",
   "cvss_score":8.1,"cvss_vector":"","affected":[],"fixed":["2.28-251.el8_10.2"],
   "component":{"purl":"pkg:rpm/redhat/glibc@2.28-251.el8_10.1","name":"glibc",
     "version":"2.28-251.el8_10.1","ecosystem":"rpm","source":"glibc"}},
  {"cve":"CVE-2023-45853","observed_at":"2025-09-30T07:20:00Z","scanner":"cortex","severity":"",
   "cvss_score":0,"cvss_vector":"","affected":[],"fixed":[],
   "component":{"purl":"","name":"zlib","version":"1.2.11-25.el8","ecosystem":"rpm","source":"zlib"}}
]}`

// TestCuratedPassesThroughUNCHANGED is the property the dialect exists for: for an
// already-curated document the source IS the evidence document, so re-serializing it
// would change its fingerprint and file a duplicate of something Evidence holds.
func TestCuratedPassesThroughUnchanged(t *testing.T) {
	body := []byte(curatedSample)
	out, stats, err := Convert(body, time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if string(out) != curatedSample {
		t.Errorf("the bytes were rewritten:\n%s", out)
	}
	if stats != (Stats{FindingsTotal: 2}) {
		t.Errorf("stats = %+v, want 2 considered and none skipped", stats)
	}
	if conv, _ := ConverterFor(DialectCurated); conv.Version() != "" {
		t.Errorf("pass-through must record no converter identity, got %q", conv.Version())
	}
}

// TestCuratedDerivesObservedAtWithoutStampingIt: the timestamp decides whether the
// document is admissible, and the document is still filed byte-for-byte as submitted.
func TestCuratedObservedAt(t *testing.T) {
	// Derivation: max(observed_at) across the findings.
	if _, _, err := Convert([]byte(curatedSample), time.Time{}); err != nil {
		t.Fatalf("a document carrying its own observed_at must convert: %v", err)
	}
	// Nothing derivable and nothing supplied.
	none := `{"findings":[{"cve":"CVE-1","component":{"name":"a"}}]}`
	if _, _, err := Convert([]byte(none), time.Time{}); !errors.Is(err, ErrObservedAtUnderivable) {
		t.Fatalf("err = %v, want ErrObservedAtUnderivable", err)
	}
	// ...and the supplied value rescues it without touching the bytes.
	out, stats, err := Convert([]byte(none), time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("with a supplied observed_at: %v", err)
	}
	if string(out) != none {
		t.Error("the bytes were rewritten")
	}
	// The finding has no usable observed_at of its own, so the ACL would skip it —
	// which is counted here, before the write, not discovered in a log line after.
	if stats != (Stats{FindingsTotal: 1, FindingsSkipped: 1}) {
		t.Errorf("stats = %+v, want 1 considered and 1 skipped", stats)
	}
	// An empty report is admissible only in the sense that it is well-formed; the
	// cardinality refusal belongs to the intake border, which knows whether an empty
	// report was asked for.
	if _, stats, err := Convert([]byte(`{"findings":[]}`), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil || stats.FindingsTotal != 0 {
		t.Errorf("empty curated report: err = %v, stats = %+v", err, stats)
	}
}

// TestParseRFC3339AcceptsFractionalSeconds pins the parse every dialect's timestamp
// goes through. Trivy stamps 7-digit fractional seconds and Cortex stamps none, and a
// reader of the single `time.RFC3339` layout would reasonably expect the fractional
// forms to fail — they do not, because Go's parser takes an optional fraction after
// the seconds field whatever the layout says. Asserted here so the behaviour is a
// guarded property rather than something two fixtures happen to exercise.
func TestParseRFC3339AcceptsFractionalSeconds(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"2026-08-17T10:11:12Z", "2026-08-17T10:11:12.000000000Z"},
		{"2026-08-17T10:11:12.1Z", "2026-08-17T10:11:12.100000000Z"},
		{"2026-08-17T10:11:12.123Z", "2026-08-17T10:11:12.123000000Z"},
		{"2026-08-17T10:11:12.1234567Z", "2026-08-17T10:11:12.123456700Z"},
		{"2026-08-17T10:11:12.123456789Z", "2026-08-17T10:11:12.123456789Z"},
		// An offset is normalized to UTC, so the same instant has one representation.
		{"2026-08-17T12:11:12.5+02:00", "2026-08-17T10:11:12.500000000Z"},
		{"2026-08-17T12:11:12+02:00", "2026-08-17T10:11:12.000000000Z"},
	} {
		got, ok := parseRFC3339(tc.in)
		if !ok {
			t.Errorf("parseRFC3339(%q) refused a valid RFC 3339 timestamp", tc.in)
			continue
		}
		if formatted := got.Format("2006-01-02T15:04:05.000000000Z"); formatted != tc.want {
			t.Errorf("parseRFC3339(%q) = %s, want %s", tc.in, formatted, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "last tuesday", "2026-08-17", "2026-08-17T10:11:12", "1759130602123"} {
		if _, ok := parseRFC3339(bad); ok {
			t.Errorf("parseRFC3339(%q) accepted a timestamp the pipeline would reject", bad)
		}
	}
}

func TestCuratedStructuralRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		want   error
		detail string
	}{
		{
			// THE incident body's shape. "curated" must mean exactly one shape.
			name: "a bare JSON array is never a curated report",
			body: `[{"cve":"CVE-1"}]`,
			want: ErrMalformedBody,
		},
		{
			name: "an object with no findings key",
			body: `{"results":[]}`,
			want: ErrMalformedBody,
		},
		{
			name: "findings is not an array",
			body: `{"findings":{"cve":"CVE-1"}}`,
			want: ErrMalformedBody,
		},
		{
			name: "not JSON at all",
			body: `nope`,
			want: ErrMalformedBody,
		},
		{
			name:   "a finding is not an object",
			body:   `{"findings":["CVE-1"]}`,
			want:   ErrSourceInvalid,
			detail: "findings[0] is not an object",
		},
		{
			name:   "a finding is not an object at a later index",
			body:   `{"findings":[{"cve":"CVE-1","observed_at":"2026-01-01T00:00:00Z","component":{"name":"a"}},7]}`,
			want:   ErrSourceInvalid,
			detail: "findings[1] is not an object",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := (passThrough{}).Convert([]byte(tc.body), time.Now())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("refusal does not name where: %v", err)
			}
		})
	}
}

// TestCuratedWrongFieldTypesAreCountedNotFatal is the border held at PARITY with the
// consumer rather than stricter than it. A field of the wrong type is where the
// scanner ACL's own unmarshal into the record contract fails, and it skips and counts
// (scanner_source.go) — so a document carrying one of those has always been readable,
// and refusing the whole thing here would reject reports the pipeline reads today.
// E1 is for a document NO consumer can read; this is not one.
func TestCuratedWrongFieldTypesAreCountedNotFatal(t *testing.T) {
	good := `{"cve":"CVE-0","observed_at":"2026-01-01T00:00:00Z","component":{"name":"a"}}`
	for _, tc := range []struct {
		name string
		bad  string
	}{
		{"cve is a number", `{"cve":7}`},
		{"cvss_score is a string", `{"cve":"CVE-1","cvss_score":"8.1"}`},
		{"component is a string", `{"cve":"CVE-1","component":"glibc"}`},
		{"fixed is not a list of strings", `{"cve":"CVE-1","fixed":[1,2]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"findings":[` + good + `,` + tc.bad + `]}`
			out, stats, err := (passThrough{}).Convert([]byte(body), time.Time{})
			if err != nil {
				t.Fatalf("a readable report with one unusable finding must not be refused: %v", err)
			}
			if string(out) != body {
				t.Error("the bytes were rewritten")
			}
			if stats != (Stats{FindingsTotal: 2, FindingsSkipped: 1}) {
				t.Errorf("stats = %+v, want 2 considered and 1 skipped — counted, never hidden", stats)
			}
		})
	}
}

// TestCuratedUnusableFindingsAreCountedNotFatal: one unusable finding must not void
// a 400-finding report (TESTING.md), and it must not vanish either.
func TestCuratedUnusableFindingsAreCountedNotFatal(t *testing.T) {
	at := `"observed_at":"2026-01-01T00:00:00Z"`
	body := `{"findings":[
	  {"cve":"CVE-1",` + at + `,"component":{"purl":"pkg:rpm/redhat/a@1"}},
	  {"cve":"",` + at + `,"component":{"name":"a"}},
	  {"cve":"CVE-3",` + at + `,"component":{"purl":"","name":""}},
	  {"cve":"CVE-4",` + at + `},
	  {"cve":"CVE-5","observed_at":"not a timestamp","component":{"name":"a"}}
	]}`
	_, stats, err := (passThrough{}).Convert([]byte(body), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if stats != (Stats{FindingsTotal: 5, FindingsSkipped: 4}) {
		t.Fatalf("stats = %+v, want 5 considered and 4 skipped", stats)
	}
}

// TestCuratedCortexOutputIsItselfCurated closes the loop: the Cortex converter's
// output must satisfy the curated contract, because that is the stage-3 check the
// intake border runs on the converted document.
func TestCuratedCortexOutputIsItselfCurated(t *testing.T) {
	for _, fx := range cortexFixtures {
		converted := convert(t, readFixture(t, "cortex", fx.file), suppliedTime(t, fx.supplied))
		stats, _, err := validateCurated(converted)
		if err != nil {
			t.Errorf("%s: the converted document is not curated: %v", fx.file, err)
			continue
		}
		if stats.FindingsSkipped != 0 {
			t.Errorf("%s: the converter emitted %d findings the pipeline cannot use", fx.file, stats.FindingsSkipped)
		}
		if stats.FindingsTotal != fx.total-fx.skipped {
			t.Errorf("%s: converted document holds %d findings, want %d", fx.file, stats.FindingsTotal, fx.total-fx.skipped)
		}
	}
}

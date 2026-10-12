package report

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type trivyFixture struct {
	name      string
	file      string
	effective string
	total     int
	skipped   int
}

var trivyFixtures = []trivyFixture{
	// Two results with different Types (one unmapped, one mapped), a vulnerability with
	// no flaw id, a null element, an empty FixedVersion, a CVSS block with no nvd entry,
	// and 7-digit fractional seconds on CreatedAt.
	{name: "sample", file: "sample.input.json", effective: "2026-08-17T10:11:12.123Z", total: 5, skipped: 2},
	// The mapped ecosystems (jar -> maven, gomod -> golang), a missing Type, a
	// non-UTC CreatedAt, an integer V3Score, a zero V3Score, a package with no
	// PkgIdentifier and one with an empty PkgIdentifier, and a non-ASCII package name.
	{name: "complex", file: "complex.input.json", effective: "2026-09-01T04:00:00.000Z", total: 4},
}

// TestTrivyConvertMatchesJSOracle is the D4 equivalence gate for the dialect that
// lived in the browser (EDR-GUI-01 D16). The oracle is `translateTrivy` itself, moved
// verbatim to `testdata/oracle/translate_trivy.js` when the in-browser translators
// were deleted, and run under node. Committed goldens keep the comparison running
// where node is absent.
func TestTrivyConvertMatchesJSOracle(t *testing.T) {
	for _, fx := range trivyFixtures {
		t.Run(fx.name, func(t *testing.T) {
			body := readFixture(t, "trivy", fx.file)
			got, stats, err := Convert(body, time.Time{})
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if stats.FindingsTotal != fx.total || stats.FindingsSkipped != fx.skipped {
				t.Errorf("stats = %+v, want total=%d skipped=%d", stats, fx.total, fx.skipped)
			}
			if want := readFixture(t, "trivy", goldenName(fx.file)); string(got) != string(want) {
				g, w := firstDiff(string(got), string(want))
				t.Errorf("output differs from the committed golden:\n got: %q\nwant: %q", g, w)
			}
			if oracle, ok := runTrivyTranslator(t, fx.file); ok {
				if string(got) != string(oracle) {
					g, w := firstDiff(string(got), string(oracle))
					t.Errorf("output differs from the live JS oracle:\n got: %q\nwant: %q", g, w)
				}
			}
		})
	}
}

// TestTrivySemanticInvariants: the identity judgement byte-equality cannot see.
func TestTrivySemanticInvariants(t *testing.T) {
	findings := convertAndDecode(t, "trivy", "sample.input.json", "")
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3 kept of 5 considered", len(findings))
	}
	if got := findings[0].Component.Ecosystem; got != "redhat" {
		t.Errorf("an unmapped Trivy Type passes through: %q", got)
	}
	if got := findings[2].Component.Ecosystem; got != "pypi" {
		t.Errorf("python-pkg must map to pypi, got %q", got)
	}
	if got := findings[1].Component.PURL; got != "" {
		t.Errorf("a vulnerability with no PkgIdentifier keeps an EMPTY purl, got %q", got)
	}
	if got := findings[1].Component.Name; got != "zlib" {
		t.Errorf("the package name is still recorded: %q", got)
	}
	for i, f := range findings {
		if f.Component.Source != "" {
			t.Errorf("findings[%d]: a scanner report names no source package, got %q", i, f.Component.Source)
		}
		if f.Scanner != "trivy" {
			t.Errorf("findings[%d]: scanner = %q", i, f.Scanner)
		}
		if f.ObservedAt != "2026-08-17T10:11:12.123Z" {
			t.Errorf("findings[%d]: observed_at = %q, want CreatedAt truncated to milliseconds", i, f.ObservedAt)
		}
	}
	if got := findings[0].Fixed; len(got) != 1 || got[0] != "2.28-251.el8_10.2" {
		t.Errorf("FixedVersion becomes a one-element list, got %q", got)
	}
	if got := len(findings[2].Fixed); got != 0 {
		t.Errorf("an empty FixedVersion becomes [], got %d entries", got)
	}
	if got := findings[1].CVSSScore; got != 0 {
		t.Errorf("a CVSS block with no nvd entry scores 0, got %v", got)
	}

	findings = convertAndDecode(t, "trivy", "complex.input.json", "")
	if got := findings[0].Component.Ecosystem; got != "maven" {
		t.Errorf("jar must map to maven, got %q", got)
	}
	if got := findings[0].Fixed; len(got) != 1 || got[0] != "2.15.0, 2.12.2" {
		t.Errorf("FixedVersion is taken VERBATIM, never split — got %q", got)
	}
	if got := findings[1].Component.PURL; got != "" {
		t.Errorf("an empty PkgIdentifier keeps an empty purl, got %q", got)
	}
	if got := findings[1].Component.Name; got != "paquete-café" {
		t.Errorf("non-ASCII names survive JSON.stringify's raw UTF-8, got %q", got)
	}
	if got := findings[3].Component.Ecosystem; got != "" {
		t.Errorf("a result with no Type has no ecosystem, got %q", got)
	}
}

// TestTrivyObservedAtUnderivable is the one behaviour deliberately NOT ported: the
// browser stamped `new Date()` when a report carried no usable CreatedAt. D3 forbids
// it — a stamped-fresh report re-uploaded tomorrow is a second scan of the same image.
func TestTrivyObservedAtUnderivable(t *testing.T) {
	body := readFixture(t, "trivy", "nocreated.input.json")
	if _, _, err := Convert(body, time.Time{}); !errors.Is(err, ErrObservedAtUnderivable) {
		t.Fatalf("err = %v, want ErrObservedAtUnderivable", err)
	}
	out, stats, err := Convert(body, time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("with a supplied observed_at: %v", err)
	}
	if stats != (Stats{FindingsTotal: 1}) {
		t.Errorf("stats = %+v, want one finding considered and none skipped", stats)
	}
	findings := decodeFindings(t, out)
	if got := findings[0].ObservedAt; got != "2026-10-11T09:30:00.000Z" {
		t.Errorf("observed_at = %q, want the supplied value in the dialect's format", got)
	}
}

func TestTrivyStructuralRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		want   error
		detail string
	}{
		{
			name: "not an object",
			body: `[]`,
			want: ErrMalformedBody,
		},
		{
			name:   "a result is not an object",
			body:   `{"SchemaVersion":2,"Results":["nope"]}`,
			want:   ErrSourceInvalid,
			detail: "Results[0] is not an object",
		},
		{
			name:   "Vulnerabilities is not an array",
			body:   `{"SchemaVersion":2,"Results":[{"Type":"redhat","Vulnerabilities":{}}]}`,
			want:   ErrSourceInvalid,
			detail: "Results[0].Vulnerabilities",
		},
		{
			name:   "a field has the wrong type",
			body:   `{"SchemaVersion":2,"CreatedAt":"2026-01-01T00:00:00Z","Results":[{"Type":"redhat","Vulnerabilities":[{"VulnerabilityID":7,"PkgName":"a"}]}]}`,
			want:   ErrSourceInvalid,
			detail: "Results[0].Vulnerabilities[0]",
		},
		{
			name: "unparseable",
			body: `{"Results":`,
			want: ErrMalformedBody,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := trivyJSON{}.Convert([]byte(tc.body), time.Now())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("refusal does not name where: %v", err)
			}
		})
	}
}

// TestTrivyNonObjectVulnerabilityIsCountedNotFatal preserves the translator's
// tolerance: one malformed finding must not void a 400-finding report.
func TestTrivyNonObjectVulnerabilityIsCountedNotFatal(t *testing.T) {
	body := `{"SchemaVersion":2,"CreatedAt":"2026-01-01T00:00:00Z","Results":[{"Type":"redhat",
	  "Vulnerabilities":[null,"nope",{"VulnerabilityID":"CVE-1","PkgName":"a"}]}]}`
	out, stats, err := trivyJSON{}.Convert([]byte(body), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if stats != (Stats{FindingsTotal: 3, FindingsSkipped: 2}) {
		t.Fatalf("stats = %+v, want 3 considered and 2 skipped", stats)
	}
	if got := len(decodeFindings(t, out)); got != 1 {
		t.Errorf("kept %d findings, want 1", got)
	}
}

func TestTrivyVersion(t *testing.T) {
	conv, ok := ConverterFor(DialectTrivy)
	if !ok || conv.Version() != trivyVersion {
		t.Fatalf("ConverterFor(trivy) = %v, %v", conv, ok)
	}
}

// --- the oracle ---

// runTrivyTranslator runs the frozen oracle — the browser translator this package
// replaced, moved verbatim to `testdata/oracle/` when EDR-INTAKE-01 D4 deleted the
// D16 in-browser translators (tasks.md 4.3). It reports ok=false (with a skip note)
// where `node` is absent, which is why the committed goldens exist.
func runTrivyTranslator(t *testing.T, fixture string) ([]byte, bool) {
	t.Helper()
	oracle := filepath.Join("testdata", "oracle", "translate_trivy.js")
	if _, err := os.Stat(oracle); err != nil {
		t.Skipf("oracle unavailable: %v", err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Logf("skipping the live oracle run: node not on PATH (the committed golden still gates)")
		return nil, false
	}
	out, err := exec.Command("node", oracle, filepath.Join("testdata", "trivy", fixture)).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("JS oracle failed on %s: %v\n%s", fixture, err, exit.Stderr)
		}
		t.Fatalf("JS oracle failed on %s: %v", fixture, err)
	}
	return out, true
}

func goldenName(input string) string {
	return strings.TrimSuffix(input, ".input.json") + ".golden.json"
}

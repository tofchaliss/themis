package report

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cortexFixture names one committed input and everything the converter must say
// about it. The table is explicit rather than globbed so each fixture carries its
// own expected counts and resolved timestamp —
// TestCortexFixtureTableCoversEveryInput keeps the two in step.
type cortexFixture struct {
	name string
	file string
	// supplied is the caller's observed_at (RFC 3339); empty means pass the zero time
	// and force derivation from the body.
	supplied string
	// effective is the observed_at that must land in every finding.
	effective string
	total     int
	skipped   int
}

var cortexFixtures = []cortexFixture{
	// A real-shaped export slice: quoted cve_description fields spanning physical
	// lines (RFC 4180), an "Unknown" severity, an empty cvss_score and an unparseable
	// one. 11 physical lines, 4 logical rows.
	{name: "slice", file: "slice.csv", effective: "2025-09-30T07:20:00Z", total: 4},
	// The KN-SCAN-3b case: an APP row whose purl has no pkg: prefix and whose version
	// carries an RPM release marker.
	{name: "app-el8", file: "app-el8.csv", effective: "2025-09-10T10:26:40Z", total: 3},
	// fix_versions across both separators, with padding and an empty trailing piece.
	{name: "multi-fix", file: "multi-fix.csv", effective: "2025-10-09T08:53:22Z", total: 3},
	// Identity abstention: a row with no purl, a row with no CVE and a row with
	// neither purl nor name (the converter's one skip condition, twice).
	{name: "nopurl", file: "nopurl.csv", effective: "2025-10-20T22:40:00Z", total: 4, skipped: 2},
	// Non-ASCII package names, which json.dumps escapes as \uXXXX (ensure_ascii) —
	// the one serialization rule no amount of ASCII fixtures would have caught.
	{name: "nonascii", file: "nonascii.csv", effective: "2025-11-01T12:26:40Z", total: 2},
	// The CSV projection of the 2026-10-05 array body (see testdata/cortex/README.md):
	// the oracle for the JSON container, since the maintained script reads only CSV.
	{name: "2026-10-05-array-as-csv", file: "2026-10-05-array.csv", effective: "2025-09-30T07:20:00Z", total: 5, skipped: 2},
	// No last_observed column at all — the ordinary Cortex CSV, which is why D3 says
	// the timestamp is "absent in the CSV" and must be supplied.
	{name: "no-observed", file: "no-observed.csv", supplied: "2026-10-11T00:00:00Z", effective: "2026-10-11T00:00:00Z", total: 2},
}

// TestCortexConvertMatchesScriptOracle is the D4 equivalence gate: the Go converter
// must reproduce the Python conversion `scripts/cortex-csv-to-scan-report.sh` carried
// BYTE FOR BYTE on every committed fixture (now frozen at
// `testdata/oracle/cortex_csv_to_scan_report.py`, the script itself having become a
// thin intake wrapper). It is the whole reason the port is safe to make, and it is not
// cosmetic — Evidence's dedup key is the SHA-256 of the filed bytes, so a converter
// that re-serializes the same findings differently turns every post-cutover
// re-submission into a duplicate scan.
//
// The comparison runs twice over: against committed golden files, which always run,
// and against the frozen oracle executed live, which runs wherever `python3` exists
// (`testdata/oracle/` — the Python the script carried until D4 moved the one converter
// server-side). The goldens are what keep the gate from silently disappearing on a
// host without an interpreter; the live run is what keeps the goldens honest.
func TestCortexConvertMatchesScriptOracle(t *testing.T) {
	for _, fx := range cortexFixtures {
		t.Run(fx.name, func(t *testing.T) {
			body := readFixture(t, "cortex", fx.file)
			got, stats, err := Convert(body, suppliedTime(t, fx.supplied))
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if stats.FindingsTotal != fx.total || stats.FindingsSkipped != fx.skipped {
				t.Errorf("stats = %+v, want total=%d skipped=%d", stats, fx.total, fx.skipped)
			}
			if want := readFixture(t, "cortex", fx.file+".golden.json"); string(got) != string(want) {
				g, w := firstDiff(string(got), string(want))
				t.Errorf("output differs from the committed golden:\n got: %q\nwant: %q", g, w)
			}
			if oracle, ok := runCortexScript(t, fx.file, fx.effective); ok {
				if string(got) != string(oracle) {
					g, w := firstDiff(string(got), string(oracle))
					t.Errorf("output differs from the live script oracle:\n got: %q\nwant: %q", g, w)
				}
			}
		})
	}
}

// TestCortexFixtureTableCoversEveryInput fails when a fixture is added to testdata
// without expected counts beside it — an uncovered fixture is a fixture that proves
// nothing.
func TestCortexFixtureTableCoversEveryInput(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "cortex", "*.csv"))
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool, len(cortexFixtures))
	for _, fx := range cortexFixtures {
		listed[fx.file] = true
	}
	for _, f := range files {
		if base := filepath.Base(f); !listed[base] {
			t.Errorf("testdata/cortex/%s is not in cortexFixtures", base)
		}
	}
}

// TestCortexJSONEqualsCSVProjection is D3 determinism across containers and the
// unit-level form of the live check in tasks.md 5.2: the CSV and the JSON array are
// two request encodings of ONE export, so they must produce one document. Because
// the CSV side is byte-equal to the script oracle, this makes the JSON side
// byte-equal to it too — which is how the array body gets an oracle at all, the
// maintained script reading only CSV.
func TestCortexJSONEqualsCSVProjection(t *testing.T) {
	fromJSON, jsonStats, err := Convert(readFixture(t, "cortex", "2026-10-05-array.json"), time.Time{})
	if err != nil {
		t.Fatalf("Convert(json): %v", err)
	}
	fromCSV, csvStats, err := Convert(readFixture(t, "cortex", "2026-10-05-array.csv"), time.Time{})
	if err != nil {
		t.Fatalf("Convert(csv): %v", err)
	}
	if string(fromJSON) != string(fromCSV) {
		j, c := firstDiff(string(fromJSON), string(fromCSV))
		t.Errorf("the two containers of one export disagree:\n json: %q\n  csv: %q", j, c)
	}
	if jsonStats != csvStats {
		t.Errorf("stats differ: json %+v, csv %+v", jsonStats, csvStats)
	}
	if jsonStats != (Stats{FindingsTotal: 5, FindingsSkipped: 2}) {
		t.Errorf("stats = %+v, want 5 considered and 2 skipped", jsonStats)
	}
}

// TestCortexSemanticInvariants is the other half of the D4 acceptance gate: byte
// equality on a fixture corpus is necessary and NOT sufficient, because these
// converters carry identity judgement. Each invariant below decides how a component
// is identified and therefore what it correlates to downstream.
func TestCortexSemanticInvariants(t *testing.T) {
	findings := convertAndDecode(t, "cortex", "app-el8.csv", "")
	if got := findings[0].Component.Ecosystem; got != "rpm" {
		t.Errorf("APP row with a +el8 version: ecosystem = %q, want rpm (KN-SCAN-3b)", got)
	}
	if got := findings[2].Component.Ecosystem; got != "" {
		t.Errorf("APP row with no release marker: ecosystem = %q, want empty", got)
	}
	// Identity abstention (EDR-IDENTITY-01 D6): the purl stays EMPTY. A plausible
	// identity correlates and an abstention does not.
	if got := findings[1].Component.PURL; got != "" {
		t.Errorf("row with no package_purl: purl = %q, want empty — never invented", got)
	}
	if got := findings[1].Component.Ecosystem; got != "rpm" {
		t.Errorf("row with no purl but an .el8 version: ecosystem = %q, want rpm", got)
	}

	findings = convertAndDecode(t, "cortex", "slice.csv", "")
	if got := findings[0].Component.Ecosystem; got != "rpm" {
		t.Errorf("ecosystem from the purl: %q, want rpm", got)
	}
	if got := findings[3].Component.Ecosystem; got != "pypi" {
		t.Errorf("ecosystem from a pypi purl: %q, want pypi", got)
	}
	for i, f := range findings {
		if f.Component.Source != f.Component.Name {
			t.Errorf("findings[%d]: source = %q, want the package's own name %q", i, f.Component.Source, f.Component.Name)
		}
		if f.Scanner != "cortex" {
			t.Errorf("findings[%d]: scanner = %q", i, f.Scanner)
		}
		if f.ObservedAt != "2025-09-30T07:20:00Z" {
			t.Errorf("findings[%d]: observed_at = %q, want the derived max(last_observed)", i, f.ObservedAt)
		}
	}
	if got := findings[1].Severity; got != "" {
		t.Errorf(`severity "Unknown" must coerce to empty, got %q`, got)
	}
	if got := findings[1].CVSSScore; got != 0 {
		t.Errorf("an empty cvss_score must coerce to 0, got %v", got)
	}
	if got := findings[3].CVSSScore; got != 0 {
		t.Errorf("an unparseable cvss_score must coerce to 0, got %v", got)
	}
	if got := len(findings[1].Fixed); got != 0 {
		t.Errorf("an absent fix_versions must coerce to [], got %d entries", got)
	}
	if got := findings[2].Fixed; len(got) != 2 || got[0] != "8.0p1-25.el8_10" || got[1] != "8.0p1-26.el8_10" {
		t.Errorf("fix_versions split on [;,] = %q", got)
	}

	findings = convertAndDecode(t, "cortex", "multi-fix.csv", "")
	if got := findings[0].Fixed; len(got) != 3 {
		t.Errorf("three fix versions across both separators, got %q", got)
	}
	if got := findings[1].Fixed; len(got) != 2 || got[0] != "4.17.21" || got[1] != "4.17.22" {
		t.Errorf("fix versions must be trimmed and empty pieces dropped, got %q", got)
	}
}

// TestCortexSkipsAreCountedNeverHidden: the converter's one skip condition is the
// oracle's `if not cve or not (purl or name)`, and a skipped row must be COUNTED.
// "427 of 427" and "427 of 500"
// must not look alike.
func TestCortexSkipsAreCountedNeverHidden(t *testing.T) {
	body := readFixture(t, "cortex", "nopurl.csv")
	out, stats, err := Convert(body, time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if stats.FindingsTotal != 4 || stats.FindingsSkipped != 2 {
		t.Fatalf("stats = %+v, want 4 considered and 2 skipped", stats)
	}
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != stats.FindingsTotal-stats.FindingsSkipped {
		t.Errorf("document carries %d findings, stats say %d kept", len(doc.Findings), stats.FindingsTotal-stats.FindingsSkipped)
	}
}

func TestCortexObservedAtUnderivable(t *testing.T) {
	body := readFixture(t, "cortex", "no-observed.csv")
	if _, _, err := Convert(body, time.Time{}); !errors.Is(err, ErrObservedAtUnderivable) {
		t.Fatalf("err = %v, want ErrObservedAtUnderivable — a report is never stamped with the upload time", err)
	}
	if _, _, err := Convert(body, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("with a supplied observed_at: %v", err)
	}
}

// TestCortexSuppliedObservedAtWins is D3's precedence, and tasks.md 7.2's reason for
// it: the same source submitted with a different supplied timestamp is a claim about
// a DIFFERENT observation, so it must not produce the same document.
func TestCortexSuppliedObservedAtWins(t *testing.T) {
	body := readFixture(t, "cortex", "slice.csv")
	derived, _, err := Convert(body, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	supplied, _, err := Convert(body, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if string(derived) == string(supplied) {
		t.Fatal("a supplied observed_at did not reach the output, so two observations would dedup as one")
	}
	if !strings.Contains(string(supplied), `"observed_at": "2026-01-02T03:04:05Z"`) {
		t.Error("the supplied observed_at is not the one in the document")
	}
}

func TestCortexCSVStructuralRefusals(t *testing.T) {
	header := "vulnerability_id,package_purl,origin_package_name\n"
	for _, tc := range []struct {
		name string
		body string
		want error
		// detail is a substring the refusal must name, so the operator learns WHERE.
		detail string
	}{
		{
			// A duplicated header is the document's FRAME being wrong, not one record's
			// shape: there is no row index to name, and every row's value for that column
			// would be a guess. So it is malformed_body, not source_invalid.
			name:   "duplicate header",
			body:   "vulnerability_id,package_purl,origin_package_name,package_purl\nCVE-1,a,b,c\n",
			want:   ErrMalformedBody,
			detail: `duplicate CSV header "package_purl"`,
		},
		{
			name:   "too few columns",
			body:   header + "CVE-1,pkg:rpm/redhat/a@1\n",
			want:   ErrSourceInvalid,
			detail: "CSV row 2 has 2 columns",
		},
		{
			name:   "too many columns",
			body:   header + "CVE-1,pkg:rpm/redhat/a@1,a,extra\n",
			want:   ErrSourceInvalid,
			detail: "CSV row 2 has 4 columns",
		},
		{
			name:   "unterminated quote",
			body:   header + "CVE-1,\"pkg:rpm/redhat/a@1,a\n",
			want:   ErrMalformedBody,
			detail: "unreadable",
		},
		{
			name: "no header row",
			body: "",
			want: ErrMalformedBody,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := cortexCSV{}.Convert([]byte(tc.body), time.Now())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("refusal does not name where: %v", err)
			}
		})
	}
}

func TestCortexCSVRejectsInvalidUTF8(t *testing.T) {
	body := append([]byte("vulnerability_id,package_purl,origin_package_name\nCVE-1,a,"), 0xFF, '\n')
	if _, _, err := (cortexCSV{}).Convert(body, time.Now()); !errors.Is(err, ErrMalformedBody) {
		t.Fatalf("err = %v, want ErrMalformedBody", err)
	}
}

func TestCortexJSONStructuralRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		want   error
		detail string
	}{
		{
			name: "empty array",
			body: `[]`,
			want: ErrEmptyReport,
		},
		{
			name:   "element is not an object",
			body:   `[{"vulnerability_id":"CVE-1","package_purl":"p","origin_package_name":"n"},"nope"]`,
			want:   ErrSourceInvalid,
			detail: "element 1 is not an object",
		},
		{
			// The 2026-10-05 shape in miniature: element 0 is well-formed and a later
			// element is not. Detection looks at element 0; THIS stage looks at every one.
			name:   "a later element carries no Cortex field set",
			body:   `[{"vulnerability_id":"CVE-1","package_purl":"p","origin_package_name":"n"},{"something_else":1}]`,
			want:   ErrSourceInvalid,
			detail: "element 1 carries no recognised Cortex field set",
		},
		{
			name:   "a scalar field is a container",
			body:   `[{"vulnerability_id":{"x":1},"package_purl":"p","origin_package_name":"n"}]`,
			want:   ErrSourceInvalid,
			detail: `element 0 field "vulnerability_id" is a JSON container`,
		},
		{
			name: "unparseable",
			body: `[{"vulnerability_id":`,
			want: ErrMalformedBody,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := cortexJSON{}.Convert([]byte(tc.body), time.Now())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("refusal does not name where: %v", err)
			}
		})
	}
}

// TestCortexJSONFixVersionsTakenAsAList: the JSON container skips the
// serialise-to-text-and-split-again round trip the GUI-16b shim needed, so a fix
// version CONTAINING a separator survives — which the CSV road cannot express.
func TestCortexJSONFixVersionsTakenAsAList(t *testing.T) {
	body := `[{"vulnerability_id":"CVE-1","package_purl":"pkg:rpm/redhat/a@1","origin_package_name":"a",
	  "fix_versions":["1.0,beta","2.0"],"last_observed":1759130602123}]`
	findings := decodeFindings(t, convert(t, []byte(body), time.Time{}))
	if got := findings[0].Fixed; len(got) != 2 || got[0] != "1.0,beta" {
		t.Errorf("fix_versions = %q, want the list verbatim", got)
	}
}

// TestCortexLastObservedForms: `last_observed` is epoch MILLISECONDS (D3), and a
// JSON number can arrive in exponential form. A value that is not a whole number of
// milliseconds contributes no timestamp rather than failing the report — derivation
// is best-effort, and its absence surfaces as ErrObservedAtUnderivable only when
// nothing was supplied either.
func TestCortexLastObservedForms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		observed string
		err      error
	}{
		{name: "integer milliseconds", raw: `1759130602123`, observed: "2025-09-29T07:23:22Z"},
		{name: "exponential", raw: `1.759130602e12`, observed: "2025-09-29T07:23:22Z"},
		{name: "numeric string", raw: `"1759130602123"`, observed: "2025-09-29T07:23:22Z"},
		{name: "fractional milliseconds", raw: `1759130602123.5`, err: ErrObservedAtUnderivable},
		{name: "not a number", raw: `"last tuesday"`, err: ErrObservedAtUnderivable},
		{name: "null", raw: `null`, err: ErrObservedAtUnderivable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `[{"vulnerability_id":"CVE-1","package_purl":"pkg:rpm/redhat/a@1",
			  "origin_package_name":"a","last_observed":` + tc.raw + `}]`
			out, _, err := (cortexJSON{}).Convert([]byte(body), time.Time{})
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if got := decodeFindings(t, out)[0].ObservedAt; got != tc.observed {
				t.Errorf("observed_at = %q, want %q", got, tc.observed)
			}
		})
	}
}

func TestCortexVersionIsSharedAcrossContainers(t *testing.T) {
	csv, _ := ConverterFor(DialectCortexCSV)
	js, _ := ConverterFor(DialectCortexJSON)
	if csv.Version() != js.Version() {
		t.Fatalf("the two containers must share one converter identity: %q vs %q", csv.Version(), js.Version())
	}
	if csv.Version() != cortexVersion {
		t.Errorf("Version() = %q, want %q", csv.Version(), cortexVersion)
	}
}

// --- the oracle ---

// runCortexScript executes the frozen oracle — the Python conversion this package
// replaced, moved verbatim to `testdata/oracle/` when the script was rewired to POST
// to intake (EDR-INTAKE-01 D4, tasks.md 4.2). It reports ok=false (with a skip note)
// when the host has no interpreter, which is why the committed goldens exist: the gate
// must not evaporate on a machine without python3.
func runCortexScript(t *testing.T, fixture, observed string) ([]byte, bool) {
	t.Helper()
	oracle := filepath.Join("testdata", "oracle", "cortex_csv_to_scan_report.py")
	if _, err := os.Stat(oracle); err != nil {
		t.Skipf("oracle unavailable: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Logf("skipping the live oracle run: python3 not on PATH (the committed golden still gates)")
		return nil, false
	}
	cmd := exec.Command("python3", oracle, filepath.Join("testdata", "cortex", fixture), observed)
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("oracle failed on %s: %v\n%s", fixture, err, exit.Stderr)
		}
		t.Fatalf("oracle failed on %s: %v", fixture, err)
	}
	return out, true
}

// --- shared helpers ---

func readFixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", dir, name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

func suppliedTime(t *testing.T, s string) time.Time {
	t.Helper()
	if s == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("fixture timestamp %q: %v", s, err)
	}
	return parsed
}

func convert(t *testing.T, body []byte, observedAt time.Time) []byte {
	t.Helper()
	out, _, err := Convert(body, observedAt)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return out
}

// decodedFinding is the curated record as the pipeline reads it, used to assert the
// SEMANTIC invariants that byte-equality cannot see.
type decodedFinding struct {
	CVE        string   `json:"cve"`
	ObservedAt string   `json:"observed_at"`
	Scanner    string   `json:"scanner"`
	Severity   string   `json:"severity"`
	CVSSScore  float64  `json:"cvss_score"`
	CVSSVector string   `json:"cvss_vector"`
	Affected   []string `json:"affected"`
	Fixed      []string `json:"fixed"`
	Component  struct {
		PURL      string `json:"purl"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		Source    string `json:"source"`
	} `json:"component"`
}

func decodeFindings(t *testing.T, doc []byte) []decodedFinding {
	t.Helper()
	var parsed struct {
		Findings []decodedFinding `json:"findings"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("the curated document does not parse: %v", err)
	}
	return parsed.Findings
}

func convertAndDecode(t *testing.T, dir, file, supplied string) []decodedFinding {
	t.Helper()
	return decodeFindings(t, convert(t, readFixture(t, dir, file), suppliedTime(t, supplied)))
}

// firstDiff reports the two strings from the first byte they differ at, bounded, so
// a byte-equality failure points at the divergence instead of dumping two documents.
func firstDiff(got, want string) (string, string) {
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	start := max(i-40, 0)
	return clip(got[start:]), clip(want[start:])
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

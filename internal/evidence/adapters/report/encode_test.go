package report

import (
	"strings"
	"testing"
)

// bs is one backslash, built from its code point so the expectations below — which
// are ABOUT escaping — can be read as the bytes they assert rather than as escapes
// of escapes.
var bs = string(rune(92))

// TestPythonFloatMatchesCPythonRepr: json.dumps writes a float with CPython's own
// repr, and the Cortex oracle's bytes are the contract. The expectations below are
// CPython's output, including the two switches a Go programmer would not guess — the
// forced ".0" and the fixed/exponential boundary at 1e-4 … 1e16.
func TestPythonFloatMatchesCPythonRepr(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{7.5, "7.5"},
		{8.1, "8.1"},
		{7, "7.0"},
		{10, "10.0"},
		{0, "0.0"},
		{-3.25, "-3.25"},
		{1e15, "1000000000000000.0"},
		{1e16, "1e+16"},
		{0.0001, "0.0001"},
		{0.00001, "1e-05"},
		// float("inf")/float("nan") PARSE in Python, and json.dumps writes them with
		// these names (allow_nan defaults to True) rather than refusing.
		{inf(1), "Infinity"},
		{inf(-1), "-Infinity"},
		{nan(), "NaN"},
	} {
		if got := pythonFloat(tc.in); got != tc.want {
			t.Errorf("pythonFloat(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEncodeMultiValuedLists: the Cortex road reaches a multi-entry `fixed` through
// its fixtures; the Trivy road cannot (a FixedVersion becomes one element), so the
// encoder's list separator is asserted directly for both oracles.
func TestEncodeMultiValuedLists(t *testing.T) {
	findings := []curatedFinding{{
		CVE: "CVE-1", ObservedAt: "2026-01-01T00:00:00Z", Scanner: "trivy",
		Score: floatScore(7.5), Fixed: []string{"1.0", "2.0"},
	}}
	if got := string(encodeDocument(findings, encodingJS)); !strings.Contains(got, `"fixed":["1.0","2.0"]`) {
		t.Errorf("js list encoding: %s", got)
	}
	if got := string(encodeDocument(findings, encodingPython)); !strings.Contains(got, "\"fixed\": [\n        \"1.0\",\n        \"2.0\"\n      ]") {
		t.Errorf("python list encoding: %s", got)
	}
}

// TestPythonScoreKeepsNumCoercionVisible: num() returns a FLOAT on success and the
// INTEGER 0 on failure, and json.dumps renders those differently. Collapsing them
// would be a one-byte divergence on every unscored finding.
func TestPythonScoreKeepsNumCoercionVisible(t *testing.T) {
	if got := pythonScore(zeroScore); got != "0" {
		t.Errorf("a coercion failure must render as the integer 0, got %q", got)
	}
	if got := pythonScore(floatScore(0)); got != "0.0" {
		t.Errorf("a parsed zero must render as a float, got %q", got)
	}
}

func TestPythonNumMatchesTheScriptsNumHelper(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  float64
		float bool
	}{
		{"8.1", 8.1, true},
		{"7", 7, true},
		{"0", 0, true},
		{"-1.5", -1.5, true},
		{"1e2", 100, true},
		{"", 0, false},
		{"not-a-number", 0, false},
		{"8.1.2", 0, false},
		// Go's ParseFloat accepts hexadecimal float literals; Python's float() raises.
		{"0x1p-2", 0, false},
	} {
		got := pythonNum(tc.in)
		if got.isFloat != tc.float || got.value != tc.want {
			t.Errorf("pythonNum(%q) = %+v, want value=%v float=%v", tc.in, got, tc.want, tc.float)
		}
	}
}

// TestJSNumberMatchesECMAScriptToString: JSON.stringify writes a number with
// Number::toString, which differs from CPython in both directions — no forced ".0",
// a far wider fixed range, and an UNPADDED exponent.
func TestJSNumberMatchesECMAScriptToString(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{7.5, "7.5"},
		{10, "10"},
		{0, "0"},
		{-3.25, "-3.25"},
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{0.000001, "0.000001"},
		{0.0000001, "1e-7"},
	} {
		if got := jsNumber(tc.in); got != tc.want {
			t.Errorf("jsNumber(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// JSON.stringify writes non-finite numbers as null. Unreachable through the
	// translator's `|| 0`, asserted so the encoder has no undefined behaviour.
	for _, in := range []float64{inf(1), inf(-1), nan()} {
		if got := jsNumber(in); got != "null" {
			t.Errorf("jsNumber(%v) = %q, want null", in, got)
		}
	}
}

// TestPythonStringEscapesToASCII: json.dumps defaults to ensure_ascii=True, so every
// non-ASCII rune leaves as a four-hex-digit escape and anything beyond the BMP as a
// surrogate pair.
func TestPythonStringEscapesToASCII(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"glibc", `"glibc"`},
		{`a"b\c`, `"a\"b\\c"`},
		{"tab\there", `"tab\there"`},
		{"nl\ncr\r", `"nl\ncr\r"`},
		{"\b\f", `"\b\f"`},
		{"\x00\x1f\x7f", `"` + bs + `u0000` + bs + `u001f` + bs + `u007f"`},
		{"café", `"caf` + bs + `u00e9"`},
		{"\U0001F600", `"` + bs + `ud83d` + bs + `ude00"`},
	} {
		if got := pythonString(tc.in); got != tc.want {
			t.Errorf("pythonString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// TestJSStringKeepsNonASCIIRaw: JSON.stringify escapes only what JSON requires and
// emits everything else as UTF-8 — the opposite of json.dumps's default.
func TestJSStringKeepsNonASCIIRaw(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"glibc", `"glibc"`},
		{`a"b\c`, `"a\"b\\c"`},
		{"tab\there", `"tab\there"`},
		{"\b\f\n\r", `"\b\f\n\r"`},
		{"\x00\x1f", `"` + bs + `u0000` + bs + `u001f"`},
		{"café", "\"café\""},
		{"日本語", "\"日本語\""},
		{"\x7f", "\"\x7f\""},
	} {
		if got := jsString(tc.in); got != tc.want {
			t.Errorf("jsString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// TestEncodeEmptyDocument: a report that converts to nothing is still a document,
// and it must be a document both oracles would have written.
func TestEncodeEmptyDocument(t *testing.T) {
	if got := string(encodeDocument(nil, encodingPython)); got != "{\n  \"findings\": []\n}\n" {
		t.Errorf("python encoding of an empty document = %q", got)
	}
	if got := string(encodeDocument(nil, encodingJS)); got != `{"findings":[]}` {
		t.Errorf("js encoding of an empty document = %q", got)
	}
}

func inf(sign int) float64 {
	if sign < 0 {
		return -1 / zero()
	}
	return 1 / zero()
}

func nan() float64 { return zero() / zero() }

// zero defeats the compiler's constant folding so the non-finite cases above are
// real runtime values rather than a build error.
func zero() float64 { return float64(len("")) }

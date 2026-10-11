package report

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// The curated document, as the pipeline reads it: `{"findings":[…]}` with the
// per-finding fields of the `scannerRecord` contract
// (internal/knowledge/adapters/feed/scanner.go) plus the `component` block the
// scanner source parses (internal/knowledge/adapters/evidence/scanner_source.go).
// Declared as structs, never maps, so field order is a property of the code rather
// than of map iteration — D3 determinism starts here.
type curatedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	Source    string
}

type curatedFinding struct {
	CVE        string
	ObservedAt string
	Scanner    string
	Severity   string
	Score      score
	CVSSVector string
	Affected   []string
	Fixed      []string
	Component  curatedComponent
}

// score carries the one numeric distinction the oracles make visible: the Cortex
// script's num() returns a FLOAT when the field parses and the INTEGER 0 when it
// does not, and json.dumps renders those as "7.0" and "0". Collapsing them to one
// Go float64 would be a one-byte divergence on every unscored finding.
type score struct {
	value   float64
	isFloat bool
}

func floatScore(f float64) score { return score{value: f, isFloat: true} }

// zeroScore is num()'s coercion failure: integer zero, never "0.0" (D5b —
// an unparseable cvss_score is coerced, never skipped).
var zeroScore = score{}

// encoding selects which oracle's bytes to reproduce.
//
// **Two serializations in one package is deliberate, and it is not cosmetic.** The
// Cortex and Trivy converters are ports (D4), and each replaces an implementation
// whose output is already filed across the estate: `json.dump(…, indent=2,
// sort_keys=True)` from the Python script, and `JSON.stringify` from the browser
// translator. Evidence's dedup key is the SHA-256 of the FILED bytes
// (store.go — ON CONFLICT (fingerprint)), so a converter that re-serializes the
// same findings differently makes every post-cutover re-submission a brand-new
// evidence document — a duplicate scan of the same image, with nothing to show it
// was a re-serialization rather than a re-scan. That is KN-SCAN-4's shape arriving
// through the new door, and byte-equality with each oracle is what closes it.
//
// **DO NOT replace the writers below with `encoding/json`.** It is the obvious
// cleanup and it would silently break the gate this package is built around:
// `encoding/json` escapes `<`, `>` and `&` by default, never writes CPython's forced
// ".0" on an integral float, emits non-ASCII raw where `json.dumps` escapes it, and
// orders keys by struct declaration rather than sorted. Each of those is a one-byte
// divergence, and one byte is a new fingerprint. Changing the emitted bytes at all is
// a decision to RE-FINGERPRINT every converted document on the estate: it needs the
// owner's explicit approval, the upstream oracles retired first, and the occurrence
// delta measured afterwards (EDR-INTAKE-01 D3a, tasks.md 8.3) — it is not a
// refactor. The equivalence tests in cortex_test.go and trivy_test.go are the guard;
// if they fail after a change here, the change is the fault.
type encoding int

const (
	// encodingPython reproduces `json.dump(doc, indent=2, sort_keys=True)` plus the
	// script's trailing newline: ASCII-only, every key sorted, two-space indent.
	encodingPython encoding = iota
	// encodingJS reproduces `JSON.stringify({findings})`: compact, insertion order,
	// raw UTF-8, no trailing newline.
	encodingJS
)

// encodeDocument writes the curated document in the requested oracle's bytes.
func encodeDocument(findings []curatedFinding, enc encoding) []byte {
	var b strings.Builder
	switch enc {
	case encodingPython:
		writePython(&b, findings)
	case encodingJS:
		writeJS(&b, findings)
	}
	return []byte(b.String())
}

// --- the Python oracle: indent=2, sort_keys=True, ensure_ascii=True ---

func writePython(b *strings.Builder, findings []curatedFinding) {
	b.WriteString("{\n  \"findings\": ")
	if len(findings) == 0 {
		b.WriteString("[]\n}\n")
		return
	}
	b.WriteString("[\n")
	for i, f := range findings {
		if i > 0 {
			b.WriteString(",\n")
		}
		writePythonFinding(b, f)
	}
	b.WriteString("\n  ]\n}\n")
}

// writePythonFinding emits one finding with its keys in sorted order at indent=2's
// nesting depth: the finding object sits four spaces in, its keys six, the nested
// component's keys eight.
func writePythonFinding(b *strings.Builder, f curatedFinding) {
	b.WriteString("    {\n")
	writePythonList(b, "affected", f.Affected, 6)
	b.WriteString(",\n      \"component\": {\n")
	c := f.Component
	// sorted: ecosystem, name, purl, source, version
	for i, kv := range [][2]string{
		{"ecosystem", c.Ecosystem}, {"name", c.Name}, {"purl", c.PURL},
		{"source", c.Source}, {"version", c.Version},
	} {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("        \"" + kv[0] + "\": ")
		b.WriteString(pythonString(kv[1]))
	}
	b.WriteString("\n      },\n")
	// sorted remainder: cve, cvss_score, cvss_vector, fixed, observed_at, scanner, severity
	b.WriteString("      \"cve\": " + pythonString(f.CVE) + ",\n")
	b.WriteString("      \"cvss_score\": " + pythonScore(f.Score) + ",\n")
	b.WriteString("      \"cvss_vector\": " + pythonString(f.CVSSVector) + ",\n")
	writePythonList(b, "fixed", f.Fixed, 6)
	b.WriteString(",\n")
	b.WriteString("      \"observed_at\": " + pythonString(f.ObservedAt) + ",\n")
	b.WriteString("      \"scanner\": " + pythonString(f.Scanner) + ",\n")
	b.WriteString("      \"severity\": " + pythonString(f.Severity) + "\n")
	b.WriteString("    }")
}

func writePythonList(b *strings.Builder, key string, items []string, indent int) {
	pad := strings.Repeat(" ", indent)
	b.WriteString(pad + "\"" + key + "\": ")
	if len(items) == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteString("[\n")
	for i, it := range items {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString(pad + "  " + pythonString(it))
	}
	b.WriteString("\n" + pad + "]")
}

func pythonScore(s score) string {
	if !s.isFloat {
		return "0"
	}
	return pythonFloat(s.value)
}

// pythonFloat reproduces CPython's float repr, which json.dumps uses verbatim:
// shortest round-trip digits, a forced ".0" on an integral value, and the switch to
// exponential notation only outside 1e-4 … 1e16.
func pythonFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	if decpt := decimalPoint(f); decpt <= -4 || decpt > 16 {
		// Go's 'e' with shortest precision already matches CPython's exponent form
		// (two-digit, signed): 1e+16, 1e-05.
		return strconv.FormatFloat(f, 'e', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') {
		s += ".0"
	}
	return s
}

// pythonString reproduces json.dumps's ensure_ascii=True escaping: the short escapes,
// \u00xx for the remaining control characters, and \uXXXX (surrogate pairs beyond the
// BMP) for everything outside printable ASCII.
func pythonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r >= 0x20 && r <= 0x7E:
			b.WriteRune(r)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			b.WriteString(uEscape(hi) + uEscape(lo))
		default:
			b.WriteString(uEscape(r))
		}
	}
	b.WriteByte('"')
	return b.String()
}

// --- the JS oracle: JSON.stringify ---

func writeJS(b *strings.Builder, findings []curatedFinding) {
	b.WriteString(`{"findings":[`)
	for i, f := range findings {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"cve":` + jsString(f.CVE))
		b.WriteString(`,"observed_at":` + jsString(f.ObservedAt))
		b.WriteString(`,"scanner":` + jsString(f.Scanner))
		b.WriteString(`,"severity":` + jsString(f.Severity))
		b.WriteString(`,"cvss_score":` + jsNumber(f.Score.value))
		b.WriteString(`,"cvss_vector":` + jsString(f.CVSSVector))
		b.WriteString(`,"affected":` + jsList(f.Affected))
		b.WriteString(`,"fixed":` + jsList(f.Fixed))
		c := f.Component
		b.WriteString(`,"component":{"purl":` + jsString(c.PURL))
		b.WriteString(`,"name":` + jsString(c.Name))
		b.WriteString(`,"version":` + jsString(c.Version))
		b.WriteString(`,"ecosystem":` + jsString(c.Ecosystem))
		b.WriteString(`,"source":` + jsString(c.Source) + `}}`)
	}
	b.WriteString(`]}`)
}

func jsList(items []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsString(it))
	}
	b.WriteByte(']')
	return b.String()
}

// jsNumber reproduces ECMAScript Number::toString as JSON.stringify emits it:
// shortest round-trip, NO forced ".0", fixed notation across 1e-6 … 1e21, and an
// unpadded exponent outside it. A non-finite value stringifies to null.
func jsNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	decpt := decimalPoint(f)
	if decpt > -6 && decpt <= 21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	// Go pads the exponent to two digits ("1e-07"); JS does not ("1e-7").
	s := strconv.FormatFloat(f, 'e', -1, 64)
	if i := strings.IndexByte(s, 'e'); i >= 0 && i+2 < len(s) {
		mant, sign, digits := s[:i], s[i+1], strings.TrimLeft(s[i+2:], "0")
		if digits == "" {
			digits = "0"
		}
		s = mant + "e" + string(sign) + digits
	}
	return s
}

// jsString reproduces JSON.stringify's string escaping: the short escapes, \u00xx for
// the remaining C0 controls, and non-ASCII passed through as raw UTF-8.
func jsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(uEscape(r))
		default:
			// Everything else leaves as raw UTF-8, including the replacement character
			// encoding/json substitutes for an undecodable byte.
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func uEscape(r rune) string {
	const hex = "0123456789abcdef"
	return string([]byte{'\\', 'u', hex[(r>>12)&0xF], hex[(r>>8)&0xF], hex[(r>>4)&0xF], hex[r&0xF]})
}

// decimalPoint returns the position of the decimal point in the shortest decimal
// representation of f — the `decpt` both CPython's and ECMAScript's number
// formatters branch on. Zero has no exponent; report 1 so it formats fixed. f is
// finite: both callers test for NaN and infinity first.
func decimalPoint(f float64) int {
	if f == 0 {
		return 1
	}
	// 'e' with shortest precision always yields "<mantissa>e<signed exponent>".
	s := strconv.FormatFloat(f, 'e', -1, 64)
	exp, err := strconv.Atoi(s[strings.IndexByte(s, 'e')+1:])
	if err != nil {
		return 1
	}
	return exp + 1
}

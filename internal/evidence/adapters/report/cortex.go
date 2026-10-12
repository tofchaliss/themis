package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// cortexVersion is the converter identity recorded in provenance and echoed as
// `converted_by` (D3). **Both containers carry the SAME version**: the CSV and the
// JSON array are two request encodings of one export, read by one set of rules, so
// the same scan must produce one curated document and one evidence id whichever road
// it arrives by (tasks.md 5.2). A per-container version would make the container a
// converter, and then the two roads would dedup separately.
const cortexVersion = "cortex@1"

// The two regexes are the 2026-09-10 case's judgement, carried over verbatim from the
// Python that `scripts/cortex-csv-to-scan-report.sh` used to carry (frozen as an
// oracle at `testdata/oracle/cortex_csv_to_scan_report.py`).
var (
	// purlEcosystem: the ecosystem comes from the purl itself (pkg:rpm/… -> rpm), never
	// from `package_type`, which is a single constant and carries no ecosystem.
	purlEcosystem = regexp.MustCompile(`^pkg:([^/]+)/`)

	// rpmBuild: Cortex calls a binary it fingerprints on disk `package_type: APP` with
	// an application-scoped purl that has no `pkg:` prefix and therefore no ecosystem —
	// and a blank ecosystem closes the verdict path outright (StrictFixesFor returns nil
	// without a positive ecosystem), so NO vendor-fix verdict can ever fire for that
	// component. Measured 2026-09-10: 87 httpd findings in exactly this state, every one
	// un-clearable. An RPM release marker in the version means the distro built it, so
	// claiming rpm is a statement about the version's SHAPE, not a guess at the
	// scanner's intent (KN-SCAN-3b).
	rpmBuild = regexp.MustCompile(`(\.|\+)el[0-9]`)

	// fixVersionSep: `fix_versions` is comma-or-semicolon separated in the CSV. These
	// stay UNATTRIBUTED by contract (KN-FIX-1).
	fixVersionSep = regexp.MustCompile(`[;,]`)
)

// cortexRow is one Cortex record, already reduced to the seven fields the maintained
// converter reads plus the observation time. Both containers parse into this, so the
// judgement below runs once.
type cortexRow struct {
	cve         string
	purl        string
	name        string
	version     string
	severity    string
	score       score
	fixed       []string
	observedMS  int64
	hasObserved bool
}

type cortexCSV struct{}

func (cortexCSV) Version() string { return cortexVersion }

// Convert reads the CSV container. The CSV is parsed by a real RFC 4180 reader, not
// by splitting on newlines: Cortex quotes `cve_description`/`remediation` and those
// fields CONTAIN newlines — the 20.1.0.0-125 export is 1264 physical lines carrying
// 557 logical rows, and the previous line-splitting implementation shredded every
// such row (measured 2026-09-10).
func (c cortexCSV) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	rows, err := parseCortexCSV(body)
	if err != nil {
		return nil, Stats{}, err
	}
	return cortexDocument(rows, observedAt, "no CSV row carried a numeric last_observed (the ordinary Cortex CSV export has no such column)")
}

type cortexJSON struct{}

func (cortexJSON) Version() string { return cortexVersion }

// Convert reads the JSON-array container — the body that halted the evidence stream
// for 31 hours on 2026-10-05 because no JSON road existed (GUI-16b). It is the same
// export in a different encoding, so it runs the same rules and emits the same bytes.
func (c cortexJSON) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	rows, err := parseCortexJSON(body)
	if err != nil {
		return nil, Stats{}, err
	}
	return cortexDocument(rows, observedAt, "no element carried a numeric last_observed")
}

// cortexDocument applies the row-level rules and serializes. It is the one place the
// Cortex judgement lives, shared by both containers.
func cortexDocument(rows []cortexRow, observedAt time.Time, hint string) ([]byte, Stats, error) {
	var derived time.Time
	for _, r := range rows {
		if !r.hasObserved {
			continue
		}
		if at := time.UnixMilli(r.observedMS).UTC(); at.After(derived) {
			derived = at
		}
	}
	resolved, err := resolveObservedAt(observedAt, derived, hint)
	if err != nil {
		return nil, Stats{}, err
	}
	// The script's `%Y-%m-%dT%H:%M:%SZ`: UTC, whole seconds.
	observed := resolved.Format("2006-01-02T15:04:05Z")

	stats := Stats{FindingsTotal: len(rows)}
	findings := make([]curatedFinding, 0, len(rows))
	for _, r := range rows {
		// The oracle's ONE skip condition (`if not cve or not (purl or name)`): no flaw
		// id, or no component to attach the flaw to. Structurally fine, semantically
		// unusable — counted, never hidden, and never fatal. Everything else the oracle
		// coerces, and so does this.
		if r.cve == "" || (r.purl == "" && r.name == "") {
			stats.FindingsSkipped++
			continue
		}
		severity := r.severity
		if severity == "Unknown" {
			// `value.ParseSeverity` then yields SeverityUnknown and the CVSS band decides.
			severity = ""
		}
		eco := ""
		if m := purlEcosystem.FindStringSubmatch(r.purl); m != nil {
			eco = m[1]
		}
		if eco == "" && rpmBuild.MatchString(r.version) {
			eco = "rpm"
		}
		findings = append(findings, curatedFinding{
			CVE:        r.cve,
			ObservedAt: observed,
			Scanner:    "cortex",
			Severity:   severity,
			Score:      r.score,
			CVSSVector: "",
			Affected:   nil,
			Fixed:      r.fixed,
			Component: curatedComponent{
				PURL:      r.purl,
				Name:      r.name,
				Version:   r.version,
				Ecosystem: eco,
				// `source` is the SOURCE-PACKAGE name, not a path: a feed is asked "what fixes
				// THIS package?" by source package (kernel-core -> kernel, perl-Errno -> perl).
				// Cortex carries no source-RPM field, so the honest value is the package's own
				// name. Measured 2026-09-10: mapping `file_path` here wrote the literal "Managed
				// by the Package Manager" into component_source for 144+ findings, and every fix
				// lookup for them then asked the feeds about a package of that name, forever.
				Source: r.name,
			},
		})
	}
	return encodeDocument(findings, encodingPython), stats, nil
}

// --- the CSV container ---

func parseCortexCSV(body []byte) ([]cortexRow, error) {
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%w: the CSV body is not valid UTF-8", ErrMalformedBody)
	}
	r := csv.NewReader(bytes.NewReader(body))
	// -1 so a column-count mismatch is OUR refusal, naming the row, rather than the
	// reader's generic error.
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: the CSV body has no header row", ErrMalformedBody)
		}
		return nil, fmt.Errorf("%w: the CSV header row is unreadable: %v", ErrMalformedBody, err)
	}
	columns := make(map[string]int, len(header))
	for i, name := range header {
		if _, dup := columns[name]; dup {
			// Two `package_purl` columns make every row ambiguous, and picking one invents
			// data. The maintained script's DictReader silently keeps the last; refusing is
			// the deliberate hardening D5b asks for.
			//
			// The REASON is `malformed_body`, not `source_invalid`: a duplicated header
			// means we do not know what we are reading at all — the fault is the document's
			// frame, not one record's shape, and no row index can be named for it. (Note for
			// the next reader: EDR-INTAKE-01's D5b table puts this row under
			// `source_invalid`; the change's implementation contract and the 2026-10-11
			// review both put it under `malformed_body`, and that is the decision of record.
			// Do not flip it back from the table alone.)
			return nil, fmt.Errorf("%w: duplicate CSV header %q — every row's value for it would be a guess", ErrMalformedBody, name)
		}
		columns[name] = i
	}

	var rows []cortexRow
	// Row numbers are LOGICAL and 1-based with the header as row 1, which is how a
	// spreadsheet shows them — a physical line number is useless on an export whose
	// quoted fields span lines.
	line := 1
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("%w: CSV row %d is unreadable: %v", ErrMalformedBody, line, err)
		}
		if len(rec) != len(header) {
			return nil, fmt.Errorf("%w: CSV row %d has %d columns, the header has %d", ErrSourceInvalid, line, len(rec), len(header))
		}
		field := func(name string) string {
			i, ok := columns[name]
			if !ok {
				return ""
			}
			return strings.TrimSpace(rec[i])
		}
		row := cortexRow{
			cve:      field("vulnerability_id"),
			purl:     field("package_purl"),
			name:     field("origin_package_name"),
			version:  field("package_version"),
			severity: field("cvss_severity"),
			score:    pythonNum(field("cvss_score")),
			fixed:    splitFixVersions(field("fix_versions")),
		}
		row.observedMS, row.hasObserved = epochMillis(field("last_observed"))
		rows = append(rows, row)
	}
	return rows, nil
}

// splitFixVersions is the script's `[v.strip() for v in re.split(r"[;,]", …) if
// v.strip()]`: absent or empty coerces to the empty list, never a skip — a finding
// with no published fix is still a finding.
func splitFixVersions(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range fixVersionSep.Split(s, -1) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- the JSON-array container ---

func parseCortexJSON(body []byte) ([]cortexRow, error) {
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%w: the JSON body is not valid UTF-8", ErrMalformedBody)
	}
	items, err := decodeArray(body)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: the body is an empty JSON array — it names no observation", ErrEmptyReport)
	}
	rows := make([]cortexRow, 0, len(items))
	for i, item := range items {
		// EVERY element, not element zero: a body whose element 0 is well-formed and whose
		// element 47 is not was identified, converted and filed by the border this stage
		// exists to replace.
		if !isObject(item) {
			return nil, fmt.Errorf("%w: element %d is not an object", ErrSourceInvalid, i)
		}
		obj, err := decodeObject(item)
		if err != nil {
			return nil, err
		}
		if !hasKeys(obj, requiredCortexFields) {
			return nil, fmt.Errorf("%w: element %d carries no recognised Cortex field set (wanted %s)", ErrSourceInvalid, i, strings.Join(requiredCortexFields, ", "))
		}
		row := cortexRow{}
		for _, f := range []struct {
			key  string
			dest *string
		}{
			{"vulnerability_id", &row.cve},
			{"package_purl", &row.purl},
			{"origin_package_name", &row.name},
			{"package_version", &row.version},
			{"cvss_severity", &row.severity},
		} {
			v, err := cortexScalar(obj[f.key], i, f.key)
			if err != nil {
				return nil, err
			}
			*f.dest = strings.TrimSpace(v)
		}
		rawScore, err := cortexScalar(obj["cvss_score"], i, "cvss_score")
		if err != nil {
			return nil, err
		}
		row.score = pythonNum(strings.TrimSpace(rawScore))
		if row.fixed, err = cortexFixVersions(obj["fix_versions"], i); err != nil {
			return nil, err
		}
		rawObserved, err := cortexScalar(obj["last_observed"], i, "last_observed")
		if err != nil {
			return nil, err
		}
		row.observedMS, row.hasObserved = epochMillis(strings.TrimSpace(rawObserved))
		rows = append(rows, row)
	}
	return rows, nil
}

// cortexScalar renders a JSON scalar as the text the CSV road would have carried:
// a string verbatim, a number/bool as its JSON text, null or absent as "". A
// container where a scalar belongs is a structural fault, because a purl that is an
// object has no honest text form. Projecting scalars to text is what keeps the two
// containers byte-identical for one scan — the CSV road only ever sees text.
func cortexScalar(raw json.RawMessage, index int, key string) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	if s, ok := stringValue(raw); ok {
		return s, nil
	}
	switch jsonOpener(raw) {
	case '{', '[':
		return "", fmt.Errorf("%w: element %d field %q is a JSON container where a scalar belongs", ErrSourceInvalid, index, key)
	}
	return string(raw), nil
}

// cortexFixVersions takes `fix_versions` as the LIST it already is in the JSON
// container — no serialise-to-text-and-split-again round trip, which is the half of
// the GUI-16b shim that argued for doing this properly. A string is still accepted
// and split on `[;,]`, so a shim-projected body converts identically.
func cortexFixVersions(raw json.RawMessage, index int) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if !isArray(raw) {
		s, err := cortexScalar(raw, index, "fix_versions")
		if err != nil {
			return nil, err
		}
		return splitFixVersions(strings.TrimSpace(s)), nil
	}
	items, err := decodeArray(raw)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, item := range items {
		s, err := cortexScalar(item, index, "fix_versions[]")
		if err != nil {
			return nil, err
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// --- shared coercions ---

// epochMillis reads `last_observed`, which the JSON export carries as epoch
// MILLISECONDS (D3). A value that is not numeric contributes no timestamp rather
// than failing the report: derivation is best-effort and its absence is reported as
// ErrObservedAtUnderivable only when nothing was supplied either.
func epochMillis(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ms, true
	}
	// A JSON number may arrive in exponential form (1.7591306e12).
	if f, err := strconv.ParseFloat(s, 64); err == nil && f == float64(int64(f)) {
		return int64(f), true
	}
	return 0, false
}

// pythonNum reproduces the script's num() helper exactly, including the distinction
// json.dumps makes visible: a parsed value is a FLOAT ("7.0") and a coercion failure
// is the INTEGER zero ("0"). An unparseable score is never a skip — a missing score
// is not a missing finding, and severityFrom falls back to the CVSS band.
func pythonNum(s string) score {
	// Go's ParseFloat accepts hexadecimal float literals; Python's float() does not,
	// and the oracle's behaviour is the contract.
	if strings.ContainsAny(s, "xXpP") {
		return zeroScore
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return zeroScore
	}
	return floatScore(f)
}

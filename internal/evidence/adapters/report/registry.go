package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"mime"
	"strings"
	"time"
)

// requiredCortexFields is the field set that identifies a Cortex record, in both
// containers (D5a rows 1 and 6).
//
// It is deliberately the THREE fields the oracle reads for identity
// (`testdata/oracle/cortex_csv_to_scan_report.py`, the `cve`/`purl`/`name` reads) and
// no more. A wider set — demanding `fix_versions`, `cvss_score`, `last_observed` —
// would refuse real exports, because which optional columns Cortex emits varies by
// tenant and by the console's column selection, and the oracle tolerates every one of
// them being absent
// (`row.get(…) or ""`). Narrower than three stops discriminating: an array of
// objects carrying all three of these is a Cortex export by any honest reading.
var requiredCortexFields = []string{"vulnerability_id", "package_purl", "origin_package_name"}

// Detect names a submitted body: D5a's closed, ordered table, first match wins.
//
//	| # | body                                                            | identified as            |
//	| 1 | Content-Type text/csv + a recognised Cortex header row           | vuln-report / cortex-csv |
//	| 2 | JSON object with bomFormat: "CycloneDX"                          | sbom / cyclonedx         |
//	| 3 | JSON object with spdxVersion                                     | sbom / spdx              |
//	| 4 | JSON object with findings: [...]                                 | vuln-report / curated    |
//	| 5 | JSON object with Results: [...] and SchemaVersion/ArtifactName   | vuln-report / trivy      |
//	| 5b| JSON object with matches: [...] and descriptor.name "grype"      | vuln-report / grype      |
//	| 6 | JSON array whose first element carries Cortex's field set        | vuln-report / cortex-json|
//	| 7 | anything else                                                    | ErrUnrecognisedFormat    |
//
// The order is written out as a straight-line sequence rather than a table walked by
// a loop, because precedence IS the contract here and a map-driven version would make
// it depend on iteration order.
//
// Identification is not admission (D5): a recognised body has only earned the right
// to be validated against its dialect's rules. Detect looks at element 0 of a JSON
// array; Convert validates every element. That split is the 2026-10-05 hole.
//
// `Content-Type: text/csv` is decisive: a body declared CSV is never then tried as
// JSON, and one whose header row carries no recognised Cortex column set is refused
// rather than guessed at. Beyond that declaration the HEADER ROW is the real
// discriminator, so a Cortex CSV sent with curl's default content type is still
// identified — provided it does not open as a JSON value, which is what keeps the
// tolerance from shadowing rows 2-6. (A declared kind/format that contradicts what
// was detected is `declared_format_mismatch` at the intake border, not here: the
// caller's assertion is information, and this function's job is to report what the
// body is.)
func Detect(contentType string, body []byte) (Kind, Dialect, error) {
	opener := jsonOpener(body)

	// Row 1 — CSV.
	if isCSVContentType(contentType) {
		if hasCortexHeader(body) {
			return KindReport, DialectCortexCSV, nil
		}
		return "", "", fmt.Errorf("%w: Content-Type is text/csv but the header row carries no recognised Cortex column set", ErrUnrecognisedFormat)
	}
	if opener == 0 && hasCortexHeader(body) {
		return KindReport, DialectCortexCSV, nil
	}

	switch opener {
	case '{':
		obj, err := decodeObject(body)
		if err != nil {
			return "", "", err
		}
		// Row 2 — CycloneDX.
		if raw, ok := obj["bomFormat"]; ok {
			if s, isStr := stringValue(raw); isStr && s == "CycloneDX" {
				return KindSBOM, DialectCycloneDX, nil
			}
		}
		// Row 3 — SPDX.
		if _, ok := obj["spdxVersion"]; ok {
			return KindSBOM, DialectSPDX, nil
		}
		// Row 4 — already curated.
		if raw, ok := obj["findings"]; ok && isArray(raw) {
			return KindReport, DialectCurated, nil
		}
		// Row 5 — Trivy.
		if raw, ok := obj["Results"]; ok && isArray(raw) {
			_, hasSchema := obj["SchemaVersion"]
			_, hasArtifact := obj["ArtifactName"]
			if hasSchema || hasArtifact {
				return KindReport, DialectTrivy, nil
			}
		}
		// Row 5b — Grype (GUI-15): `matches` plus a descriptor naming the tool. The
		// descriptor is required because `matches` alone is too common a key to claim.
		if raw, ok := obj["matches"]; ok && isArray(raw) {
			if d, ok := obj["descriptor"]; ok && isObject(d) {
				desc, err := decodeObject(d)
				if err != nil {
					return "", "", err
				}
				if name, isStr := stringValue(desc["name"]); isStr && strings.EqualFold(name, "grype") {
					return KindReport, DialectGrype, nil
				}
			}
		}
	case '[':
		arr, err := decodeArray(body)
		if err != nil {
			return "", "", err
		}
		// A zero-length array is refused HERE, before anything indexes element 0 —
		// 0, 1 and >1 are three cardinalities and 0 is the one that panics.
		if len(arr) == 0 {
			return "", "", fmt.Errorf("%w: the body is an empty JSON array — it names no observation", ErrEmptyReport)
		}
		// Row 6 — Cortex JSON. Element 0 only: every element is checked in Convert.
		if isObject(arr[0]) {
			first, err := decodeObject(arr[0])
			if err != nil {
				return "", "", err
			}
			if hasKeys(first, requiredCortexFields) {
				return KindReport, DialectCortexJSON, nil
			}
		}
	}

	// Row 7.
	return "", "", fmt.Errorf("%w: the body matches no known SBOM or vulnerability-report dialect", ErrUnrecognisedFormat)
}

// Convert identifies the body and converts it with the dialect's own converter. It
// is the package-level form of the [Converter] port: pure in (body, observedAt),
// with no content type available, so it leans on Detect's row-1 tolerance for CSV.
//
// An SBOM is identified, not converted: it is already a standards document and
// Evidence's parser ACL owns it. Asking this package to convert one is a caller
// error, reported as such rather than as a silent empty report.
func Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	kind, dialect, err := Detect("", body)
	if err != nil {
		return nil, Stats{}, err
	}
	if kind == KindSBOM {
		return nil, Stats{}, fmt.Errorf("%w: the body is a %s SBOM, not a vulnerability report", ErrUnrecognisedFormat, dialect)
	}
	conv, ok := ConverterFor(dialect)
	if !ok {
		return nil, Stats{}, fmt.Errorf("%w: no converter for dialect %q", ErrUnrecognisedFormat, dialect)
	}
	return conv.Convert(body, observedAt)
}

// ConverterFor returns the one converter for a report dialect (D4: one converter per
// dialect, server-side, and the duplicates are retired). The registry is a switch,
// not a mutable map: a second converter for a dialect is a defect, not a
// convenience, and a registration hook is how one gets added by accident.
func ConverterFor(d Dialect) (Converter, bool) {
	switch d {
	case DialectCurated:
		return passThrough{}, true
	case DialectCortexCSV:
		return cortexCSV{}, true
	case DialectCortexJSON:
		return cortexJSON{}, true
	case DialectTrivy:
		return trivyJSON{}, true
	case DialectGrype:
		return grypeJSON{}, true
	default:
		return nil, false
	}
}

// resolveObservedAt applies D3's precedence, and the absence of `now` is the whole
// point of it:
//
//   - a caller-SUPPLIED timestamp wins, because supplying one is an assertion about
//     WHICH observation this is. The same source submitted with a different supplied
//     timestamp must therefore NOT dedup (tasks.md 7.2), which is only possible if the
//     supplied value reaches the output.
//   - a DERIVED timestamp is the fallback. Derivation is a pure function of the bytes,
//     so the idempotency triple (source_digest, release_id, observed_at) collapses to
//     (source_digest, release_id) with no special case.
//   - neither is [ErrObservedAtUnderivable]. Never the clock: a report stamped fresh
//     and re-uploaded tomorrow is a second scan of the same image, and no operator can
//     tell it from a real one.
func resolveObservedAt(supplied, derived time.Time, hint string) (time.Time, error) {
	if !supplied.IsZero() {
		return supplied.UTC(), nil
	}
	if !derived.IsZero() {
		return derived.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%w: %s, and none was supplied — a report cannot be stamped with the time it was uploaded", ErrObservedAtUnderivable, hint)
}

// isCSVContentType reports whether the header names CSV, ignoring parameters such as
// `; charset=utf-8`.
func isCSVContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.TrimSpace(strings.ToLower(strings.SplitN(contentType, ";", 2)[0]))
	}
	return mt == "text/csv"
}

// hasCortexHeader reads ONLY the header row and reports whether it carries the
// required Cortex columns. It never errors: an unreadable header row is simply not a
// Cortex header, which keeps identification from reporting a validation fault.
// Duplicate or conflicting headers likewise do not prevent identification — they are
// a stage-2 refusal (D5b), because knowing which rules apply is what lets us say the
// headers are wrong.
func hasCortexHeader(body []byte) bool {
	header, err := readCSVHeader(body)
	if err != nil {
		return false
	}
	present := make(map[string]struct{}, len(header))
	for _, h := range header {
		present[h] = struct{}{}
	}
	for _, want := range requiredCortexFields {
		if _, ok := present[want]; !ok {
			return false
		}
	}
	return true
}

func readCSVHeader(body []byte) ([]string, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	return r.Read()
}

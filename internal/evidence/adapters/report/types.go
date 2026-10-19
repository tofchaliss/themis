// Package report is Evidence's vulnerability-report intake ACL: it identifies the
// dialect of a submitted document (EDR-INTAKE-01 D5a) and converts the vendor
// dialects into the one curated `{"findings":[…]}` document Themis files
// (D2/D4) — so the server owns exactly ONE converter per dialect and no vendor
// shape ever reaches the domain.
//
// Three rules shape everything here, and each is a defect already paid for:
//
//   - **Identification is not admission** (D5). Detect names a body; it does not
//     decide the body is good. Validation of every element and the conversion are
//     separate stages with their own refusals, because a Cortex array whose element 0
//     looks right and whose element 47 is broken is exactly how the 2026-10-05
//     incident got past a border that only checked `json.Valid`.
//   - **Conversion is pure in (bytes, observedAt)** (D3). `observed_at` is derived
//     from the submitted data or supplied by the caller and is **never** `now`: a
//     stamped-fresh report re-uploaded tomorrow is a second scan of the same image
//     that nobody can tell apart. No derivation and nothing supplied is
//     [ErrObservedAtUnderivable], not a guess.
//   - **Identity is never invented** (D4, EDR-IDENTITY-01 D6). A missing purl stays
//     missing. A plausible identity correlates and an abstention does not, which is
//     the 2026-09-10 false-positive class in one sentence.
//
// The converters are **ports of the implementations they replaced**, not rewrites:
// Cortex from the Python in `scripts/cortex-csv-to-scan-report.sh` and Trivy from the
// browser's `translateTrivy` (EDR-GUI-01 D16). Their output is byte-compared against
// those oracles on a committed fixture corpus (`testdata/`), which is what made
// retiring them safe — and both are now frozen under `testdata/oracle/`, so the
// comparison outlives the roads they used to be.
//
// That is also why the documents are written by hand-rolled encoders in encode.go
// rather than by `encoding/json`. **Read the comment on the `encoding` type before
// touching them**: the emitted bytes are a dedup contract, not a formatting choice,
// and changing them re-fingerprints every converted document on the estate.
//
// Where this package's refusals sit relative to the pipeline's tolerance is a rule in
// itself: the border refuses a document NO consumer can read, and COUNTS the records a
// consumer would skip. It is never stricter than the consumer — a border that rejects
// reports the pipeline has always read is its own outage.
package report

import (
	"errors"
	"time"
)

// Kind is what a submitted document IS, as echoed to the client in
// `detected_kind` (EDR-INTAKE-01 D5a).
type Kind string

// The two kinds the intake door admits. An SBOM is identified here so the caller
// learns what Themis decided; converting it is the parser ACL's job, not this
// package's.
const (
	KindReport Kind = "vuln-report"
	KindSBOM   Kind = "sbom"
)

// Dialect is the concrete format inside a Kind, echoed as `detected_format`.
type Dialect string

// The closed dialect set. The valid matrix is `sbom × {cyclonedx, spdx}` and
// `vuln-report × {curated, trivy, grype, cortex-json, cortex-csv}`, and nothing else (D5a;
// grype added by GUI-15, 2026-10-19).
const (
	DialectCurated    Dialect = "curated"
	DialectCortexCSV  Dialect = "cortex-csv"
	DialectCortexJSON Dialect = "cortex-json"
	DialectTrivy      Dialect = "trivy"
	DialectGrype      Dialect = "grype"
	DialectCycloneDX  Dialect = "cyclonedx"
	DialectSPDX       Dialect = "spdx"
)

// Stats counts what a conversion saw. FindingsTotal is the number of source
// records **considered**; FindingsSkipped is those refused by a row-level skip
// rule (structurally fine, semantically unusable — the maintained converter's one
// skip condition). The curated document therefore carries exactly
// FindingsTotal-FindingsSkipped findings.
//
// Both are reported, never just the kept count: "427 of 427" and "427 of 500" must
// not look alike, which is the whole of the silent-skip class (KN-SCAN-OBS-1).
type Stats struct {
	FindingsTotal   int
	FindingsSkipped int
}

// The refusal taxonomy (EDR-INTAKE-01 D5/D11). Each sentinel is one reason the
// intake door reports by name; callers match with errors.Is and surface the wrapped
// text as the refusal's `detail` — the reason and its elaboration stay TWO fields
// and are never concatenated (the 2026-09-22 lesson).
var (
	// ErrUnrecognisedFormat is D5a row 7: a body Themis cannot name. It gets no
	// further, because every later rule needs to know which rules apply.
	ErrUnrecognisedFormat = errors.New("unrecognised_format")

	// ErrEmptyReport is a report that names zero observations. For a JSON array this
	// is decided WITHOUT indexing element zero — 0, 1 and >1 are three cardinalities
	// and 0 is the one that panics (CONVENTIONS R5).
	ErrEmptyReport = errors.New("empty_report")

	// ErrMalformedBody is D5b row 1: we do not know what we are reading — unparseable
	// JSON, CSV with no header, broken quoting.
	ErrMalformedBody = errors.New("malformed_body")

	// ErrSourceInvalid is D5b rows 2-3: the body parses but a record's SHAPE is
	// unknown, so every field's meaning would be a guess. Always wrapped with the
	// element index or row number that failed.
	ErrSourceInvalid = errors.New("source_invalid")

	// ErrObservedAtUnderivable is D3's refusal: no timestamp could be derived from
	// the submitted data and none was supplied. Never `now` — see the package doc.
	ErrObservedAtUnderivable = errors.New("observed_at_underivable")
)

// Converter turns one vendor dialect into the curated document. Implementations are
// pure functions of (body, observedAt) — no clock, no filesystem, no map iteration
// in the output — which is what makes Evidence's content addressing able to dedup a
// re-submission instead of filing a second scan (D3).
type Converter interface {
	// Version identifies the converter in provenance and in the intake response's
	// `converted_by` (D3: the output depends on the converter's own rules, so the
	// rules have to be nameable). Empty for pass-through, which converts nothing.
	Version() string

	// Convert produces the curated document. observedAt, when non-zero, is the
	// caller's assertion about WHICH observation this is and wins over derivation;
	// when zero the timestamp is derived from the body per dialect (D3).
	Convert(body []byte, observedAt time.Time) (curated []byte, stats Stats, err error)
}

package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// passThrough is the curated dialect's converter, and it converts nothing: for an
// already-curated `{"findings":[…]}` document the source IS the evidence document,
// so it keeps the existing content-fingerprint identity (D3) and has no converter
// identity to record.
//
// What it does do is the E1 half: validate the shape BEFORE the immutable write.
// The document that halted Knowledge's evidence stream for 31 hours on 2026-10-05
// passed the old border because `json.Valid` was the whole of it.
type passThrough struct{}

func (passThrough) Version() string { return "" }

// Convert validates and returns the submitted bytes UNCHANGED — the same backing
// array, not a re-serialization. Re-encoding a pass-through document would change
// its fingerprint and file a duplicate of a document Evidence already holds.
func (passThrough) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	stats, derived, err := validateCurated(body)
	if err != nil {
		return nil, Stats{}, err
	}
	if _, err := resolveObservedAt(observedAt, derived, "no finding carried a parseable observed_at"); err != nil {
		return nil, Stats{}, err
	}
	return body, stats, nil
}

// curatedRecord is the `scannerRecord` contract
// (internal/knowledge/adapters/feed/scanner.go) plus the `component` block the
// scanner source parses, restated here because a context may not import another's
// packages. Fields are POINTERS so that absent and empty stay distinguishable
// without the zero value standing in for both.
type curatedRecord struct {
	CVE        *string            `json:"cve"`
	ObservedAt *string            `json:"observed_at"`
	Scanner    *string            `json:"scanner"`
	Severity   *string            `json:"severity"`
	CVSSScore  *float64           `json:"cvss_score"`
	CVSSVector *string            `json:"cvss_vector"`
	Affected   []string           `json:"affected"`
	Fixed      []string           `json:"fixed"`
	Component  *curatedRecordComp `json:"component"`
}

type curatedRecordComp struct {
	PURL      *string `json:"purl"`
	Name      *string `json:"name"`
	Version   *string `json:"version"`
	Ecosystem *string `json:"ecosystem"`
	Source    *string `json:"source"`
}

// validateCurated applies the curated dialect's stage-2 rules and reports what it
// counted plus the timestamp the document itself carries.
//
// The line between refuse and count is D5b's, read onto this dialect — and it is
// drawn at PARITY WITH THE CONSUMER, never stricter:
//
//   - not a JSON object, or no `findings` array → ErrMalformedBody. A BARE ARRAY is
//     refused here by construction: that is the incident body, and accepting one
//     would make "curated" mean two shapes.
//   - an element that is not an object → ErrSourceInvalid naming the index. The
//     record's shape is unknown, so every field's meaning would be a guess.
//   - an element the consuming ACL could not use — one that does not decode into the
//     record contract, or that carries no CVE id, no usable `observed_at`, or no
//     component to attach the flaw to → SKIPPED and COUNTED.
//
// That third rule is deliberately the ACL's own condition rather than a tighter one.
// `ScannerSource.ScannerProposals` skips and counts a record it cannot decode
// (scanner_source.go), and one malformed finding must not void a 400-finding report
// (TESTING.md). A border that refused the whole document for a single field of the
// wrong type would reject reports the pipeline has always read — which is not what
// E1 is for. E1 exists to refuse a document NO consumer can read; a document with one
// unreadable finding is still readable, and the counted skip is what keeps the gap
// visible before the immutable write instead of in a log line after it.
func validateCurated(body []byte) (Stats, time.Time, error) {
	var derived time.Time
	if jsonOpener(body) != '{' {
		return Stats{}, derived, fmt.Errorf("%w: a curated scanner report is a JSON object {\"findings\":[…]}, not a bare array or scalar", ErrMalformedBody)
	}
	obj, err := decodeObject(body)
	if err != nil {
		return Stats{}, derived, err
	}
	raw, ok := obj["findings"]
	if !ok || !isArray(raw) {
		return Stats{}, derived, fmt.Errorf("%w: a curated scanner report needs a \"findings\" array", ErrMalformedBody)
	}
	items, err := decodeArray(raw)
	if err != nil {
		return Stats{}, derived, err
	}

	stats := Stats{FindingsTotal: len(items)}
	for i, item := range items {
		if !isObject(item) {
			return Stats{}, time.Time{}, fmt.Errorf("%w: findings[%d] is not an object", ErrSourceInvalid, i)
		}
		var rec curatedRecord
		if err := json.Unmarshal(item, &rec); err != nil {
			// A field of the wrong type is where the consuming ACL's own
			// `json.Unmarshal` into the record contract fails, and it skips and counts.
			// Matching that exactly is the point: the border must not refuse a report the
			// pipeline would have read.
			stats.FindingsSkipped++
			continue
		}
		at, parsed := parseRFC3339(deref(rec.ObservedAt))
		if parsed && at.After(derived) {
			derived = at
		}
		if !usableCuratedRecord(rec, parsed) {
			stats.FindingsSkipped++
		}
	}
	return stats, derived, nil
}

// usableCuratedRecord is the downstream ACL's own acceptance condition, restated:
// a canonical CVE id, a parseable observation time, and a component to attach the
// flaw to. A record failing any of them is skipped there (scanner_source.go), so
// counting it here is what makes the gap visible before the write rather than in a
// log line afterwards.
func usableCuratedRecord(rec curatedRecord, observedParsed bool) bool {
	if strings.TrimSpace(deref(rec.CVE)) == "" || !observedParsed {
		return false
	}
	if rec.Component == nil {
		return false
	}
	return deref(rec.Component.PURL) != "" || deref(rec.Component.Name) != ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseRFC3339 mirrors the ACL's parseObserved (feed.go): RFC 3339 or nothing. The
// converters must not accept a timestamp the pipeline will reject, and mirroring the
// consumer's exact parse is how that stays true.
//
// The single layout is sufficient and `time.RFC3339Nano` is NOT needed beside it:
// Go's parser accepts an optional fractional second after the seconds field
// regardless of whether the layout spells one out, so this reads Trivy's 7-digit
// `CreatedAt` as happily as a whole-second one. That is a property of
// `time.Parse`, not of these fixtures, and it is pinned by
// TestParseRFC3339AcceptsFractionalSeconds across 0-9 digits and both offset forms —
// adding a second layout would be an unreachable branch, not robustness.
func parseRFC3339(s string) (time.Time, bool) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

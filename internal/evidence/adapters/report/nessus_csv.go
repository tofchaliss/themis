package report

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// nessusCSVVersion is the CSV converter's identity in provenance (`converted_by`).
const nessusCSVVersion = "nessus-csv@1"

// nessusCSV converts a Tenable Nessus CSV export into the curated document
// (EDR-INTAKE-01, 2026-10-26 amendment C1–C6).
//
// It applies the `.nessus` report road's rules (N3–N5) row by row. A row is one
// (plugin, host, port, CVE); a row with no CVE is not a vulnerability record and is not
// counted. A row whose `Plugin Output` carries `Remote package installed` lines is a
// vendor advisory check — only local checks print them, and the CSV has no plugin-family
// column to say so another way — and gives one finding per package line. Every other row
// with a CVE is counted as skipped, never filed.
//
// The CSV names no scan date, so `observed_at` must be supplied (C3); `Host`, `Port`,
// `Protocol` and the free text are read and dropped (C5).
type nessusCSV struct{}

func (nessusCSV) Version() string { return nessusCSVVersion }

func (nessusCSV) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	if !utf8.Valid(body) {
		return nil, Stats{}, fmt.Errorf("%w: the CSV body is not valid UTF-8", ErrMalformedBody)
	}
	// Before reading any row: the answer does not depend on the rows, and refusing a
	// 2 MB export after parsing it would report the cheap fault last.
	resolved, err := resolveObservedAt(observedAt, time.Time{}, "a Nessus CSV export carries no scan date (its date columns are the plugin's)")
	if err != nil {
		return nil, Stats{}, err
	}
	observed := resolved.Format("2006-01-02T15:04:05.000Z")

	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, Stats{}, fmt.Errorf("%w: the CSV body has no header row", ErrMalformedBody)
		}
		return nil, Stats{}, fmt.Errorf("%w: the CSV header row is unreadable: %v", ErrMalformedBody, err)
	}
	columns := make(map[string]int, len(header))
	for i, name := range header {
		if _, dup := columns[name]; dup {
			return nil, Stats{}, fmt.Errorf("%w: duplicate CSV header %q — every row's value for it would be a guess", ErrMalformedBody, name)
		}
		columns[name] = i
	}

	var (
		stats    Stats
		findings []curatedFinding
	)
	// Logical, 1-based row numbers with the header as row 1, as a spreadsheet shows
	// them: `Plugin Output` and `Description` span lines.
	line := 1
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		if err != nil {
			return nil, Stats{}, fmt.Errorf("%w: CSV row %d is unreadable: %v", ErrMalformedBody, line, err)
		}
		if len(rec) != len(header) {
			return nil, Stats{}, fmt.Errorf("%w: CSV row %d has %d columns, the header has %d", ErrSourceInvalid, line, len(rec), len(header))
		}
		field := func(name string) string {
			i, ok := columns[name]
			if !ok {
				return ""
			}
			return strings.TrimSpace(rec[i])
		}
		cve := field("CVE")
		if cve == "" {
			continue
		}
		pkgs, bad := nessusPackages(field("Plugin Output"))
		if len(pkgs) == 0 {
			// No package line: an upstream version check or a remote check — counted,
			// never filed. Unsplittable package lines are each a skip, not a guess (N4).
			n := bad
			if n == 0 {
				n = 1
			}
			stats.FindingsTotal += n
			stats.FindingsSkipped += n
			continue
		}
		stats.FindingsTotal += len(pkgs) + bad
		stats.FindingsSkipped += bad
		sc := nessusCSVScore(field("CVSS v3.0 Base Score"))
		for _, p := range pkgs {
			var fixed []string
			if p.fixed != "" {
				fixed = []string{p.fixed}
			}
			findings = append(findings, curatedFinding{
				CVE:        cve,
				ObservedAt: observed,
				Scanner:    "nessus",
				Severity:   nessusSeverity(field("Risk")),
				Score:      sc,
				Fixed:      fixed,
				Component: curatedComponent{
					Name:      p.name,
					Version:   p.version,
					Ecosystem: "rpm",
				},
			})
		}
	}
	return encodeDocument(findings, encodingJS), stats, nil
}

// nessusCSVScore reads `CVSS v3.0 Base Score`; absent or out of range is the integer
// zero, as every other converter writes it. The CSV carries no vector (C4).
func nessusCSVScore(s string) score {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 || f > 10 {
		return zeroScore
	}
	return floatScore(f)
}

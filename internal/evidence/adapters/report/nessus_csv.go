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
const nessusCSVVersion = "nessus-csv@2"

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
		rows     [][]string
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
		rows = append(rows, rec)
	}
	field := func(rec []string, name string) string {
		i, ok := columns[name]
		if !ok {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	// The hand-install rule (H1) reads a host's detection rows — the rows with no CVE —
	// against its package-list row, so it needs every row before the first finding is
	// judged. The rows are grouped by the `Host` column and the value is used for nothing
	// else (C5): it is read and dropped.
	installs := map[string]nessusInstallIndex{}
	{
		byHost := map[string][]nessusDetection{}
		rpms := map[string]map[string]struct{}{}
		for _, rec := range rows {
			host := field(rec, "Host")
			if field(rec, "Plugin ID") == nessusSoftwarePlugin {
				rpms[host] = nessusRPMNames(field(rec, "Plugin Output"))
			}
			var cves []string
			if cve := field(rec, "CVE"); cve != "" {
				cves = []string{cve}
			}
			byHost[host] = append(byHost[host], nessusDetection{
				pluginID: field(rec, "Plugin ID"), pluginName: field(rec, "Name"),
				output: field(rec, "Plugin Output"), cves: cves,
			})
		}
		for host, items := range byHost {
			installs[host] = nessusInstalls(items, rpms[host])
		}
	}
	for _, rec := range rows {
		field := func(name string) string { return field(rec, name) }
		cve := field("CVE")
		if cve == "" {
			continue
		}
		pkgs, bad := nessusPackages(field("Plugin Output"))
		if len(pkgs) == 0 && bad == 0 {
			// No package line: an upstream version check or a remote check. A block naming
			// a hand-installed component of this host is filed (H3); the rest is counted,
			// never filed.
			sc := nessusCSVScore(field("CVSS v3.0 Base Score"))
			kept, total := nessusClassC(field("Plugin Output"), installs[field("Host")], []string{cve},
				func(cve string, inst nessusInstall, fixed []string) {
					findings = append(findings, curatedFinding{
						CVE: cve, ObservedAt: observed, Scanner: "nessus",
						Severity: nessusSeverity(field("Risk")), Score: sc, Fixed: fixed,
						Component: curatedComponent{Name: inst.product, Version: inst.version},
					})
				})
			stats.FindingsTotal += total
			stats.FindingsSkipped += total - kept
			continue
		}
		if len(pkgs) == 0 {
			// Unsplittable package lines are each a skip, not a guess (N4).
			stats.FindingsTotal += bad
			stats.FindingsSkipped += bad
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

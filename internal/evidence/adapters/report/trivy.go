package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// trivyVersion is this converter's identity in provenance (`converted_by`).
const trivyVersion = "trivy@1"

// trivyEcosystems is the browser translator's map, carried over unchanged: Trivy
// speaks its own ecosystem vocabulary where the pipeline speaks purl types. An
// unmapped value passes through — `value.NormalizeEcosystem` is the server-side net
// (KN-SCAN-3) and an unknown ecosystem filters nothing (KN-FIX-3).
var trivyEcosystems = map[string]string{
	"python-pkg": "pypi", "node-pkg": "npm", "gobinary": "golang",
	"gomod": "golang", "jar": "maven", "pom": "maven", "gemspec": "gem",
}

type trivyReport struct {
	CreatedAt *string           `json:"CreatedAt"`
	Results   []json.RawMessage `json:"Results"`
}

type trivyResult struct {
	Type            *string           `json:"Type"`
	Vulnerabilities []json.RawMessage `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  *string `json:"VulnerabilityID"`
	PkgName          *string `json:"PkgName"`
	InstalledVersion *string `json:"InstalledVersion"`
	FixedVersion     *string `json:"FixedVersion"`
	Severity         *string `json:"Severity"`
	PkgIdentifier    *struct {
		PURL *string `json:"PURL"`
	} `json:"PkgIdentifier"`
	// Keyed by scoring source ("nvd", "redhat", …). Only `nvd` is read, so the map is
	// never iterated and the output stays deterministic.
	CVSS map[string]struct {
		V3Score  *float64 `json:"V3Score"`
		V3Vector *string  `json:"V3Vector"`
	} `json:"CVSS"`
}

// trivyJSON is the port of the browser's `translateTrivy` (EDR-GUI-01 D16), which it
// replaces: the dialect is translated once, server-side, and the GUI keeps its
// file-note UX by reading the counts out of the intake response instead of computing
// them (D4).
//
// One behaviour is deliberately NOT carried over. The browser fell back to
// `new Date().toISOString()` when a report carried no usable `CreatedAt`, and said so
// in the file note. Server-side that fallback is forbidden (D3): a stamped-fresh
// report re-uploaded tomorrow is a second scan of the same image and nobody can tell.
// No derivable timestamp and none supplied is [ErrObservedAtUnderivable].
type trivyJSON struct{}

func (trivyJSON) Version() string { return trivyVersion }

func (trivyJSON) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	if !utf8.Valid(body) {
		return nil, Stats{}, fmt.Errorf("%w: the JSON body is not valid UTF-8", ErrMalformedBody)
	}
	if jsonOpener(body) != '{' {
		return nil, Stats{}, fmt.Errorf("%w: a Trivy report is a JSON object", ErrMalformedBody)
	}
	var rep trivyReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, Stats{}, fmt.Errorf("%w: the Trivy report does not parse: %v", ErrMalformedBody, err)
	}

	derived, _ := parseRFC3339(deref(rep.CreatedAt))
	resolved, err := resolveObservedAt(observedAt, derived, "the report carries no parseable CreatedAt")
	if err != nil {
		return nil, Stats{}, err
	}
	// `Date.prototype.toISOString` always writes three fractional digits, so the oracle's
	// bytes carry them whether the source had them or not.
	observed := resolved.Format("2006-01-02T15:04:05.000Z")

	var (
		stats    Stats
		findings []curatedFinding
	)
	for ri, rawResult := range rep.Results {
		if !isObject(rawResult) {
			return nil, Stats{}, fmt.Errorf("%w: Results[%d] is not an object", ErrSourceInvalid, ri)
		}
		var res trivyResult
		if err := json.Unmarshal(rawResult, &res); err != nil {
			return nil, Stats{}, trivyShapeError(err, fmt.Sprintf("Results[%d]", ri))
		}
		ecosystem := trivyEcosystems[deref(res.Type)]
		if ecosystem == "" {
			ecosystem = deref(res.Type)
		}
		for vi, rawVuln := range res.Vulnerabilities {
			stats.FindingsTotal++
			// The translator's skip: no flaw id or no package name. Counted, never fatal —
			// one malformed finding must not void a 400-finding report. A non-object element
			// lands here too, exactly as the `!v` guard did.
			if !isObject(rawVuln) {
				stats.FindingsSkipped++
				continue
			}
			var v trivyVuln
			if err := json.Unmarshal(rawVuln, &v); err != nil {
				return nil, Stats{}, trivyShapeError(err, fmt.Sprintf("Results[%d].Vulnerabilities[%d]", ri, vi))
			}
			if deref(v.VulnerabilityID) == "" || deref(v.PkgName) == "" {
				stats.FindingsSkipped++
				continue
			}
			nvd := v.CVSS["nvd"]
			purl := ""
			if v.PkgIdentifier != nil {
				// EDR-IDENTITY-01 D6: a vulnerability with no PkgIdentifier keeps an EMPTY
				// purl. The name and version are recorded, and resolving the observation onto
				// a release component is the inventory's call — exactly one match or abstain.
				// Synthesising a purl here would make an abstention correlate.
				purl = deref(v.PkgIdentifier.PURL)
			}
			fixed := []string(nil)
			if fv := deref(v.FixedVersion); fv != "" {
				fixed = []string{fv}
			}
			findings = append(findings, curatedFinding{
				CVE:        deref(v.VulnerabilityID),
				ObservedAt: observed,
				Scanner:    "trivy",
				Severity:   deref(v.Severity),
				Score:      trivyScore(nvd.V3Score),
				CVSSVector: deref(nvd.V3Vector),
				Affected:   nil,
				Fixed:      fixed,
				Component: curatedComponent{
					PURL:      purl,
					Name:      deref(v.PkgName),
					Version:   deref(v.InstalledVersion),
					Ecosystem: ecosystem,
					// A scanner report names no source package; the translator left it empty and
					// so does this. Inventing one is the 2026-09-10 mis-attribution.
					Source: "",
				},
			})
		}
	}
	return encodeDocument(findings, encodingJS), stats, nil
}

// trivyScore reproduces `(v.CVSS && v.CVSS.nvd && v.CVSS.nvd.V3Score) || 0`: absent
// and zero are the same output, because `||` cannot tell them apart.
func trivyScore(v *float64) score {
	if v == nil || *v == 0 {
		return zeroScore
	}
	return floatScore(*v)
}

// trivyShapeError reports a field whose TYPE is wrong as a structural fault. The
// browser would have passed a number through where a string belongs and written it
// into the curated document as a number; refusing is the deliberate hardening D5b
// asks for — the record's shape is unknown, so every field's meaning is a guess.
func trivyShapeError(err error, where string) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("%w: %s.%s is %s, not %s", ErrSourceInvalid, where, typeErr.Field, typeErr.Value, typeErr.Type)
	}
	return fmt.Errorf("%w: %s does not parse: %v", ErrSourceInvalid, where, err)
}

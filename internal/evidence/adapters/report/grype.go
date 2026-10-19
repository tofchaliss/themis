package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// grypeVersion is this converter's identity in provenance (`converted_by`).
const grypeVersion = "grype@1"

// grypeEcosystems maps Grype's `artifact.type` vocabulary to purl types where they
// differ. An unmapped value passes through, like Trivy's: `value.NormalizeEcosystem`
// is the server-side net and an unknown ecosystem filters nothing.
var grypeEcosystems = map[string]string{
	"python": "pypi", "java-archive": "maven", "go-module": "golang",
	"gem": "gem", "npm": "npm", "rust-crate": "cargo", "dotnet": "nuget", "php-composer": "composer",
}

type grypeReport struct {
	Matches    []json.RawMessage `json:"matches"`
	Descriptor *struct {
		Name      *string `json:"name"`
		Timestamp *string `json:"timestamp"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability *struct {
		ID       *string `json:"id"`
		Severity *string `json:"severity"`
		Fix      *struct {
			Versions []string `json:"versions"`
			State    *string  `json:"state"`
		} `json:"fix"`
		CVSS []struct {
			Version *string `json:"version"`
			Vector  *string `json:"vector"`
			Metrics *struct {
				BaseScore *float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID *string `json:"id"`
	} `json:"relatedVulnerabilities"`
	Artifact *struct {
		Name    *string `json:"name"`
		Version *string `json:"version"`
		Type    *string `json:"type"`
		PURL    *string `json:"purl"`
	} `json:"artifact"`
}

// grypeJSON converts Grype's JSON output (`grype … -o json`) into the curated document
// (GUI-15: the second scanner dialect, server-side per EDR-INTAKE-01 D4). It follows the
// Trivy converter's rules exactly: identity is never invented (a match with no purl keeps an
// empty purl, the name and version are recorded), the observation time is the report's own
// `descriptor.timestamp` or the caller's and never the clock (D3), a match with no flaw id or
// no package name is counted and skipped, and a record whose SHAPE is wrong refuses the body.
//
// One rule is Grype's own: it keys a match by whatever its source named the flaw, often a
// GHSA id, and lists the CVE under `relatedVulnerabilities`. The curated document is keyed by
// CVE, so a non-CVE id is replaced by the first related CVE when there is one; otherwise the
// source id is kept as-is, exactly as Trivy's is, and it is the correlation that abstains.
type grypeJSON struct{}

func (grypeJSON) Version() string { return grypeVersion }

func (grypeJSON) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	if !utf8.Valid(body) {
		return nil, Stats{}, fmt.Errorf("%w: the JSON body is not valid UTF-8", ErrMalformedBody)
	}
	if jsonOpener(body) != '{' {
		return nil, Stats{}, fmt.Errorf("%w: a Grype report is a JSON object", ErrMalformedBody)
	}
	var rep grypeReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, Stats{}, fmt.Errorf("%w: the Grype report does not parse: %v", ErrMalformedBody, err)
	}
	var derived time.Time
	if rep.Descriptor != nil {
		derived, _ = parseRFC3339(deref(rep.Descriptor.Timestamp))
	}
	resolved, err := resolveObservedAt(observedAt, derived, "the report carries no parseable descriptor.timestamp")
	if err != nil {
		return nil, Stats{}, err
	}
	observed := resolved.Format("2006-01-02T15:04:05.000Z")

	var (
		stats    Stats
		findings []curatedFinding
	)
	for mi, raw := range rep.Matches {
		stats.FindingsTotal++
		if !isObject(raw) {
			stats.FindingsSkipped++
			continue
		}
		var m grypeMatch
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, Stats{}, grypeShapeError(err, fmt.Sprintf("matches[%d]", mi))
		}
		if m.Vulnerability == nil || m.Artifact == nil || deref(m.Vulnerability.ID) == "" || deref(m.Artifact.Name) == "" {
			stats.FindingsSkipped++
			continue
		}
		id := deref(m.Vulnerability.ID)
		if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			for _, r := range m.RelatedVulnerabilities {
				if rid := deref(r.ID); strings.HasPrefix(strings.ToUpper(rid), "CVE-") {
					id = rid
					break
				}
			}
		}
		sc, vector := zeroScore, ""
		for _, c := range m.Vulnerability.CVSS {
			if !strings.HasPrefix(deref(c.Version), "3") || c.Metrics == nil || c.Metrics.BaseScore == nil || *c.Metrics.BaseScore == 0 {
				continue
			}
			sc, vector = floatScore(*c.Metrics.BaseScore), deref(c.Vector)
			break
		}
		var fixed []string
		if m.Vulnerability.Fix != nil {
			for _, v := range m.Vulnerability.Fix.Versions {
				if strings.TrimSpace(v) != "" {
					fixed = append(fixed, v)
				}
			}
		}
		ecosystem := grypeEcosystems[deref(m.Artifact.Type)]
		if ecosystem == "" {
			ecosystem = deref(m.Artifact.Type)
		}
		findings = append(findings, curatedFinding{
			CVE:        id,
			ObservedAt: observed,
			Scanner:    "grype",
			Severity:   deref(m.Vulnerability.Severity),
			Score:      sc,
			CVSSVector: vector,
			Affected:   nil,
			Fixed:      fixed,
			Component: curatedComponent{
				PURL:      deref(m.Artifact.PURL),
				Name:      deref(m.Artifact.Name),
				Version:   deref(m.Artifact.Version),
				Ecosystem: ecosystem,
				Source:    "",
			},
		})
	}
	return encodeDocument(findings, encodingJS), stats, nil
}

// grypeShapeError mirrors trivyShapeError: a field of the wrong TYPE is a structural
// fault of the whole body, named by path.
func grypeShapeError(err error, where string) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("%w: %s.%s is %s, not %s", ErrSourceInvalid, where, typeErr.Field, typeErr.Value, typeErr.Type)
	}
	return fmt.Errorf("%w: %s does not parse: %v", ErrSourceInvalid, where, err)
}

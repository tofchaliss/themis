package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

type trivyDocument struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string              `json:"Target"`
	Type            string              `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string         `json:"VulnerabilityID"`
	Severity         string         `json:"Severity"`
	FixedVersion     string         `json:"FixedVersion"`
	PkgName          string         `json:"PkgName"`
	InstalledVersion string         `json:"InstalledVersion"`
	CVSS             trivyCVSSBlock `json:"CVSS"`
}

type trivyCVSSBlock struct {
	NVD trivyCVSSScore `json:"nvd"`
}

type trivyCVSSScore struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

// TrivyAdapter parses Trivy JSON scan output.
type TrivyAdapter struct{}

func (TrivyAdapter) Format() string { return domain.SBOMFormatTrivy }

func (TrivyAdapter) Parse(_ context.Context, raw []byte, _ string) (domain.CanonicalSBOM, error) {
	var doc trivyDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid trivy json: %w", err)
	}

	sbom := domain.CanonicalSBOM{
		Format:      domain.SBOMFormatTrivy,
		SpecVersion: "1",
	}
	seenComponents := map[string]struct{}{}

	for _, result := range doc.Results {
		componentPURL := trivyComponentPURL(result)
		if componentPURL != "" {
			if _, ok := seenComponents[componentPURL]; !ok {
				seenComponents[componentPURL] = struct{}{}
				ecosystem, _ := ecosystemFromPURL(componentPURL)
				name, version := nameVersionFromPURL(componentPURL)
				sbom.Components = append(sbom.Components, domain.CanonicalComponent{
					PURL:      componentPURL,
					Name:      name,
					Version:   version,
					Ecosystem: ecosystem,
				})
			}
		}

		for _, vuln := range result.Vulnerabilities {
			affected := componentPURL
			if affected == "" {
				affected = buildPURL(result.Type, vuln.PkgName, vuln.InstalledVersion)
			}
			severity := strings.ToLower(vuln.Severity)
			if severity == "" {
				severity = "unknown"
				sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
					"unknown severity for vulnerability %s", vuln.VulnerabilityID,
				))
			}
			fixVersions := []string{}
			if vuln.FixedVersion != "" {
				fixVersions = []string{vuln.FixedVersion}
			}
			sbom.Vulnerabilities = append(sbom.Vulnerabilities, domain.CanonicalVulnerability{
				CVEID:         vuln.VulnerabilityID,
				Severity:      severity,
				CVSSScore:     vuln.CVSS.NVD.V3Score,
				CVSSVector:    vuln.CVSS.NVD.V3Vector,
				AffectedPURLs: []string{affected},
				FixVersions:   fixVersions,
			})
		}
	}

	return sbom, nil
}

func trivyComponentPURL(result trivyResult) string {
	if result.Type == "" {
		return ""
	}
	for _, vuln := range result.Vulnerabilities {
		if vuln.PkgName != "" {
			return buildPURL(result.Type, vuln.PkgName, vuln.InstalledVersion)
		}
	}
	target := strings.TrimSpace(result.Target)
	if target == "" {
		return buildPURL(result.Type, result.Type, "")
	}
	name := target
	if idx := strings.Index(target, " ("); idx >= 0 {
		name = target[:idx]
	}
	return buildPURL(result.Type, name, "")
}

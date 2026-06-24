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
	Target          string               `json:"Target"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

// trivyVulnerability carries only the package identity Themis needs to build the
// component inventory. Trivy's scanner-reported CVE / severity / fix fields are
// intentionally NOT ingested as findings — Themis re-correlates each component
// against its own feeds (CR-9: pure re-correlator).
type trivyVulnerability struct {
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
}

// TrivyAdapter parses Trivy JSON scan output into the component inventory.
type TrivyAdapter struct{}

func (TrivyAdapter) Format() string { return domain.SBOMFormatTrivy }

func (TrivyAdapter) Parse(_ context.Context, raw []byte, _ string) (domain.CanonicalSBOM, error) {
	var doc trivyDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid trivy json: %w", err)
	}

	sbom := domain.CanonicalSBOM{Format: domain.SBOMFormatTrivy, SpecVersion: "1"}
	seen := map[string]struct{}{}
	addComponent := func(purl string) {
		if purl == "" {
			return
		}
		if _, ok := seen[purl]; ok {
			return
		}
		seen[purl] = struct{}{}
		ecosystem, _ := ecosystemFromPURL(purl)
		name, version := nameVersionFromPURL(purl)
		sbom.Components = append(sbom.Components, domain.CanonicalComponent{
			PURL:      purl,
			Name:      name,
			Version:   version,
			Ecosystem: ecosystem,
		})
	}

	for _, result := range doc.Results {
		if result.Type == "" {
			continue
		}
		// One component per DISTINCT package in the result. The previous parser
		// took only the first vulnerability's PkgName and attributed the whole
		// result to it, hiding every other package in a Trivy scan (CR-9).
		pkgFound := false
		for _, vuln := range result.Vulnerabilities {
			purl := buildPURL(result.Type, vuln.PkgName, vuln.InstalledVersion)
			if purl != "" {
				pkgFound = true
			}
			addComponent(purl) // empty (no PkgName) is dropped by addComponent
		}
		if !pkgFound {
			addComponent(trivyTargetPURL(result))
		}
	}

	return sbom, nil
}

// trivyTargetPURL derives an artifact-level component purl from the result Target
// when the result lists no packages.
func trivyTargetPURL(result trivyResult) string {
	if result.Type == "" {
		return ""
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

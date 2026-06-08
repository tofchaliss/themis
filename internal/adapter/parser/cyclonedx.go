package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

type cycloneDXDocument struct {
	BOMFormat   string              `json:"bomFormat"`
	SpecVersion string              `json:"specVersion"`
	Components  []cycloneDXComponent `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies"`
	Vulnerabilities []cycloneDXVulnerability `json:"vulnerabilities"`
}

type cycloneDXComponent struct {
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	PURL     string              `json:"purl"`
	Licenses []cycloneDXLicense  `json:"licenses"`
}

type cycloneDXLicense struct {
	License cycloneDXLicenseChoice `json:"license"`
}

type cycloneDXLicenseChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cycloneDXVulnerability struct {
	ID      string                 `json:"id"`
	Ratings []cycloneDXRating      `json:"ratings"`
	Affects []cycloneDXAffect      `json:"affects"`
}

type cycloneDXRating struct {
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
}

type cycloneDXAffect struct {
	Ref string `json:"ref"`
}

// CycloneDXAdapter parses CycloneDX JSON documents.
type CycloneDXAdapter struct{}

func (CycloneDXAdapter) Format() string { return domain.SBOMFormatCycloneDX }

func (CycloneDXAdapter) Parse(_ context.Context, raw []byte, specVersion string) (domain.CanonicalSBOM, error) {
	var doc cycloneDXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid cyclonedx json: %w", err)
	}
	if doc.BOMFormat != "" && !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid bomFormat %q", doc.BOMFormat)
	}
	version := specVersion
	if version == "" {
		version = doc.SpecVersion
	}
	if err := validateCycloneDXVersion(version); err != nil {
		return domain.CanonicalSBOM{}, err
	}

	sbom := domain.CanonicalSBOM{
		Format:      domain.SBOMFormatCycloneDX,
		SpecVersion: version,
	}

	for _, component := range doc.Components {
		if component.PURL == "" {
			sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
				"skipped component without purl: name=%s version=%s",
				component.Name, component.Version,
			))
			continue
		}
		ecosystem, ok := ecosystemFromPURL(component.PURL)
		if !ok {
			sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
				"skipped component with malformed purl: name=%s version=%s purl=%s",
				component.Name, component.Version, component.PURL,
			))
			continue
		}
		name := component.Name
		versionInfo := component.Version
		if name == "" || versionInfo == "" {
			parsedName, parsedVersion := nameVersionFromPURL(component.PURL)
			if name == "" {
				name = parsedName
			}
			if versionInfo == "" {
				versionInfo = parsedVersion
			}
		}
		sbom.Components = append(sbom.Components, domain.CanonicalComponent{
			PURL:      component.PURL,
			Name:      name,
			Version:   versionInfo,
			Ecosystem: ecosystem,
			Licenses:  cycloneDXLicenses(component.Licenses),
		})
	}

	for _, dep := range doc.Dependencies {
		for _, to := range dep.DependsOn {
			sbom.Dependencies = append(sbom.Dependencies, domain.CanonicalDependencyEdge{
				FromPURL:         dep.Ref,
				ToPURL:           to,
				RelationshipType: "depends_on",
			})
		}
	}

	for _, vuln := range doc.Vulnerabilities {
		severity, score, vector := firstCycloneDXRating(vuln.Ratings)
		affected := make([]string, 0, len(vuln.Affects))
		for _, affect := range vuln.Affects {
			if affect.Ref != "" {
				affected = append(affected, affect.Ref)
			}
		}
		sbom.Vulnerabilities = append(sbom.Vulnerabilities, domain.CanonicalVulnerability{
			CVEID:         vuln.ID,
			Severity:      severity,
			CVSSScore:     score,
			CVSSVector:    vector,
			AffectedPURLs: affected,
		})
	}

	return sbom, nil
}

func validateCycloneDXVersion(version string) error {
	switch version {
	case "1.4", "1.5", "1.6", "":
		return nil
	default:
		return fmt.Errorf("unsupported cyclonedx spec version %q", version)
	}
}

func cycloneDXLicenses(licenses []cycloneDXLicense) []string {
	out := make([]string, 0, len(licenses))
	for _, item := range licenses {
		switch {
		case item.License.ID != "":
			out = append(out, item.License.ID)
		case item.License.Name != "":
			out = append(out, item.License.Name)
		}
	}
	return out
}

func firstCycloneDXRating(ratings []cycloneDXRating) (severity string, score float64, vector string) {
	if len(ratings) == 0 {
		return "", 0, ""
	}
	return ratings[0].Severity, ratings[0].Score, ratings[0].Vector
}

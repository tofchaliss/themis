package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

type spdx23Document struct {
	SPDXVersion   string           `json:"spdxVersion"`
	Packages      []spdx23Package  `json:"packages"`
	Relationships []spdx23Relation `json:"relationships"`
}

type spdx23Package struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdx23Relation struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

type spdx30Document struct {
	SPDXVersion string          `json:"spdxVersion"`
	Elements    []spdx30Element `json:"elements"`
}

type spdx30Element struct {
	Type             string            `json:"type"`
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	From             string            `json:"from"`
	To               []string          `json:"to"`
	RelationshipType string            `json:"relationshipType"`
}

// SPDXAdapter parses SPDX JSON documents.
type SPDXAdapter struct{}

func (SPDXAdapter) Format() string { return domain.SBOMFormatSPDX }

func (SPDXAdapter) Parse(_ context.Context, raw []byte, specVersion string) (domain.CanonicalSBOM, error) {
	version := specVersion
	if version == "" {
		var header struct {
			SPDXVersion string `json:"spdxVersion"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return domain.CanonicalSBOM{}, fmt.Errorf("invalid spdx json: %w", err)
		}
		version = normalizeSPDXVersion(header.SPDXVersion)
	}
	if err := validateSPDXVersion(version); err != nil {
		return domain.CanonicalSBOM{}, err
	}

	switch version {
	case "2.3":
		return parseSPDX23(raw, version)
	case "3.0":
		return parseSPDX30(raw, version)
	default:
		return domain.CanonicalSBOM{}, fmt.Errorf("unsupported spdx spec version %q", version)
	}
}

func parseSPDX23(raw []byte, version string) (domain.CanonicalSBOM, error) {
	var doc spdx23Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid spdx json: %w", err)
	}

	sbom := domain.CanonicalSBOM{
		Format:      domain.SBOMFormatSPDX,
		SpecVersion: version,
	}
	idToPURL := map[string]string{}

	for _, pkg := range doc.Packages {
		purl, ok := purlFromExternalRefs(pkg.ExternalRefs)
		if !ok {
			sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
				"skipped package without package-manager purl: name=%s version=%s",
				pkg.Name, pkg.VersionInfo,
			))
			continue
		}
		ecosystem, valid := ecosystemFromPURL(purl)
		if !valid {
			sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
				"skipped package with malformed purl: name=%s version=%s purl=%s",
				pkg.Name, pkg.VersionInfo, purl,
			))
			continue
		}
		idToPURL[pkg.SPDXID] = purl
		sbom.Components = append(sbom.Components, domain.CanonicalComponent{
			PURL:      purl,
			Name:      pkg.Name,
			Version:   pkg.VersionInfo,
			Ecosystem: ecosystem,
			Licenses:  spdxLicenses(pkg.LicenseConcluded, pkg.LicenseDeclared),
		})
	}

	for _, rel := range doc.Relationships {
		if !strings.EqualFold(rel.RelationshipType, "DEPENDS_ON") {
			continue
		}
		from, okFrom := idToPURL[rel.SPDXElementID]
		to, okTo := idToPURL[rel.RelatedSPDXElement]
		if !okFrom || !okTo {
			continue
		}
		sbom.Dependencies = append(sbom.Dependencies, domain.CanonicalDependencyEdge{
			FromPURL:         from,
			ToPURL:           to,
			RelationshipType: "depends_on",
		})
	}

	return sbom, nil
}

func parseSPDX30(raw []byte, version string) (domain.CanonicalSBOM, error) {
	var doc spdx30Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid spdx json: %w", err)
	}

	sbom := domain.CanonicalSBOM{
		Format:      domain.SBOMFormatSPDX,
		SpecVersion: version,
	}
	idToPURL := map[string]string{}

	for _, element := range doc.Elements {
		if !strings.Contains(strings.ToLower(element.Type), "package") {
			continue
		}
		purl, ok := purlFromExternalRefs(element.ExternalRefs)
		if !ok {
			sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
				"skipped package without package-manager purl: name=%s version=%s",
				element.Name, element.Version,
			))
			continue
		}
		ecosystem, valid := ecosystemFromPURL(purl)
		if !valid {
			sbom.Warnings = append(sbom.Warnings, fmt.Sprintf(
				"skipped package with malformed purl: name=%s version=%s purl=%s",
				element.Name, element.Version, purl,
			))
			continue
		}
		idToPURL[element.SPDXID] = purl
		sbom.Components = append(sbom.Components, domain.CanonicalComponent{
			PURL:      purl,
			Name:      element.Name,
			Version:   element.Version,
			Ecosystem: ecosystem,
			Licenses:  spdxLicenses(element.LicenseConcluded, element.LicenseDeclared),
		})
	}

	for _, element := range doc.Elements {
		if strings.Contains(strings.ToLower(element.Type), "package") {
			continue
		}
		if !strings.EqualFold(element.RelationshipType, "dependsOn") &&
			!strings.EqualFold(element.RelationshipType, "DEPENDS_ON") {
			continue
		}
		from, okFrom := idToPURL[element.From]
		for _, toID := range element.To {
			to, okTo := idToPURL[toID]
			if okFrom && okTo {
				sbom.Dependencies = append(sbom.Dependencies, domain.CanonicalDependencyEdge{
					FromPURL:         from,
					ToPURL:           to,
					RelationshipType: "depends_on",
				})
			}
		}
	}

	return sbom, nil
}

func purlFromExternalRefs(refs []spdxExternalRef) (string, bool) {
	for _, ref := range refs {
		if !strings.EqualFold(ref.ReferenceCategory, "PACKAGE-MANAGER") {
			continue
		}
		locator := strings.TrimSpace(ref.ReferenceLocator)
		if strings.HasPrefix(locator, "pkg:") {
			return locator, true
		}
		if strings.EqualFold(ref.ReferenceType, "purl") && locator != "" {
			return locator, true
		}
	}
	return "", false
}

func spdxLicenses(concluded, declared string) []string {
	licenses := make([]string, 0, 2)
	if concluded != "" && concluded != "NOASSERTION" {
		licenses = append(licenses, concluded)
	}
	if declared != "" && declared != "NOASSERTION" && declared != concluded {
		licenses = append(licenses, declared)
	}
	return licenses
}

func normalizeSPDXVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "SPDX-2.3"):
		return "2.3"
	case strings.HasPrefix(raw, "SPDX-3.0"):
		return "3.0"
	default:
		return raw
	}
}

func validateSPDXVersion(version string) error {
	switch version {
	case "2.3", "3.0", "":
		return nil
	default:
		return fmt.Errorf("unsupported spdx spec version %q", version)
	}
}

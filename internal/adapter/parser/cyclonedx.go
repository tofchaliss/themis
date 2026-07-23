package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

type cycloneDXDocument struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies"`
}

type cycloneDXComponent struct {
	BOMRef   string             `json:"bom-ref"`
	Name     string             `json:"name"`
	Version  string             `json:"version"`
	PURL     string             `json:"purl"`
	Licenses []cycloneDXLicense `json:"licenses"`
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

	// refToPURL resolves a dependency reference (a bom-ref, which is NOT always a
	// purl) to the component's purl. Dependency edges reference bom-refs; mapping
	// them keeps the dependency graph keyed on purl identity (CR-9).
	refToPURL := map[string]string{}

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
		if component.BOMRef != "" {
			refToPURL[component.BOMRef] = component.PURL
		}
		refToPURL[component.PURL] = component.PURL
		sbom.Components = append(sbom.Components, domain.CanonicalComponent{
			PURL:      component.PURL,
			Name:      name,
			Version:   versionInfo,
			Ecosystem: ecosystem,
			Licenses:  cycloneDXLicenses(component.Licenses),
		})
	}

	resolveRef := func(ref string) string {
		if purl, ok := refToPURL[ref]; ok {
			return purl
		}
		if strings.HasPrefix(ref, "pkg:") {
			return ref
		}
		return ""
	}

	for _, dep := range doc.Dependencies {
		from := resolveRef(dep.Ref)
		if from == "" {
			continue
		}
		for _, to := range dep.DependsOn {
			toPURL := resolveRef(to)
			if toPURL == "" {
				continue
			}
			sbom.Dependencies = append(sbom.Dependencies, domain.CanonicalDependencyEdge{
				FromPURL:         from,
				ToPURL:           toPURL,
				RelationshipType: "depends_on",
			})
		}
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

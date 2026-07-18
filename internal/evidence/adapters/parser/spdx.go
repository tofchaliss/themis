package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

type spdxParser struct{}

type spdxDocument struct {
	SPDXVersion   string           `json:"spdxVersion"`
	Packages      []spdxPackage    `json:"packages"`
	Relationships []spdxRelation   `json:"relationships"`
}

type spdxPackage struct {
	SPDXID       string            `json:"SPDXID"`
	Name         string            `json:"name"`
	VersionInfo  string            `json:"versionInfo"`
	ExternalRefs []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelation struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

func (spdxParser) parse(raw []byte, specVersion string) ([]domain.Component, []domain.DependencyEdge, []string, error) {
	var doc spdxDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid spdx json: %w", err)
	}
	version := specVersion
	if version == "" {
		version = normalizeSPDXVersion(doc.SPDXVersion)
	}
	if err := validateSPDXVersion(version); err != nil {
		return nil, nil, nil, err
	}

	var (
		components []domain.Component
		warnings   []string
	)
	idToPURL := map[string]value.PURL{}

	for _, pkg := range doc.Packages {
		locator, ok := purlFromExternalRefs(pkg.ExternalRefs)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("skipped package without package-manager purl: name=%s version=%s", pkg.Name, pkg.VersionInfo))
			continue
		}
		purl, err := value.NewPURL(locator)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped package with invalid purl: name=%s purl=%s", pkg.Name, locator))
			continue
		}
		ecosystem, ok := ecosystemFromPURL(purl.String())
		if !ok {
			warnings = append(warnings, fmt.Sprintf("skipped package with unreadable purl type: purl=%s", purl.String()))
			continue
		}
		idToPURL[pkg.SPDXID] = purl
		components = append(components, domain.Component{PURL: purl, Name: pkg.Name, Version: pkg.VersionInfo, Ecosystem: ecosystem})
	}

	var edges []domain.DependencyEdge
	for _, rel := range doc.Relationships {
		if !strings.EqualFold(rel.RelationshipType, "DEPENDS_ON") {
			continue
		}
		from, okFrom := idToPURL[rel.SPDXElementID]
		to, okTo := idToPURL[rel.RelatedSPDXElement]
		if !okFrom || !okTo {
			continue
		}
		edges = append(edges, domain.DependencyEdge{From: from, To: to, Relationship: "depends_on"})
	}

	return components, edges, warnings, nil
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

func normalizeSPDXVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "SPDX-2.3"):
		return "2.3"
	case strings.HasPrefix(raw, "SPDX-2.2"):
		return "2.2"
	default:
		return raw
	}
}

func validateSPDXVersion(version string) error {
	switch version {
	case "", "2.2", "2.3":
		return nil
	default:
		return fmt.Errorf("unsupported spdx spec version %q", version)
	}
}

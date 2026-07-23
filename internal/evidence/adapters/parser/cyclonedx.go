package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

type cycloneDXParser struct{}

type cycloneDXDocument struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies"`
}

type cycloneDXComponent struct {
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func (cycloneDXParser) parse(raw []byte, specVersion string) ([]domain.Component, []domain.DependencyEdge, []string, error) {
	var doc cycloneDXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid cyclonedx json: %w", err)
	}
	if doc.BOMFormat != "" && !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return nil, nil, nil, fmt.Errorf("invalid bomFormat %q", doc.BOMFormat)
	}
	version := specVersion
	if version == "" {
		version = doc.SpecVersion
	}
	if err := validateCycloneDXVersion(version); err != nil {
		return nil, nil, nil, err
	}

	var (
		components []domain.Component
		warnings   []string
	)
	// refToPURL resolves a dependency reference (a bom-ref, which is not always a
	// purl) to the component's purl, keeping the dependency graph keyed on purl.
	refToPURL := map[string]value.PURL{}

	for _, c := range doc.Components {
		purl, err := value.NewPURL(c.PURL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped component without valid purl: name=%s version=%s purl=%s", c.Name, c.Version, c.PURL))
			continue
		}
		ecosystem, ok := ecosystemFromPURL(purl.String())
		if !ok {
			warnings = append(warnings, fmt.Sprintf("skipped component with unreadable purl type: purl=%s", purl.String()))
			continue
		}
		name, ver := c.Name, c.Version
		if name == "" || ver == "" {
			pn, pv := nameVersionFromPURL(purl.String())
			if name == "" {
				name = pn
			}
			if ver == "" {
				ver = pv
			}
		}
		if c.BOMRef != "" {
			refToPURL[c.BOMRef] = purl
		}
		refToPURL[purl.String()] = purl
		components = append(components, domain.Component{PURL: purl, Name: name, Version: ver, Ecosystem: ecosystem})
	}

	resolve := func(ref string) (value.PURL, bool) {
		if p, ok := refToPURL[ref]; ok {
			return p, true
		}
		if p, err := value.NewPURL(ref); err == nil {
			return p, true
		}
		return value.PURL{}, false
	}

	var edges []domain.DependencyEdge
	for _, dep := range doc.Dependencies {
		from, ok := resolve(dep.Ref)
		if !ok {
			continue
		}
		for _, to := range dep.DependsOn {
			toPURL, ok := resolve(to)
			if !ok {
				continue
			}
			edges = append(edges, domain.DependencyEdge{From: from, To: toPURL, Relationship: "depends_on"})
		}
	}

	return components, edges, warnings, nil
}

func validateCycloneDXVersion(version string) error {
	switch version {
	case "", "1.4", "1.5", "1.6":
		return nil
	default:
		return fmt.Errorf("unsupported cyclonedx spec version %q", version)
	}
}

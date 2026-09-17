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
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	PURL       string              `json:"purl"`
	Properties []cycloneDXProperty `json:"properties"`
}

type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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

	// Entries the document named but did not IDENTIFY — deferred, not dropped, so they can be
	// resolved against what the document did identify (EDR-IDENTITY-01 D2). Same rule as the
	// SPDX door and the scanner door: one rule, three doors.
	var pending []pendingPackage

	for _, c := range doc.Components {
		purl, err := value.NewPURL(c.PURL)
		if err != nil {
			// An absent purl and an unparseable one are the same outcome (D1): neither is an
			// identity. The bom-ref is carried so a resolved entry keeps its dependency edges.
			ref := c.BOMRef
			if ref == "" {
				ref = c.PURL
			}
			pending = append(pending, pendingPackage{ID: ref, Name: c.Name, Version: c.Version, RawPURL: c.PURL})
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
		components = append(components, domain.Component{PURL: purl, Name: name, Version: ver, Ecosystem: ecosystem, Source: srcNameFromProperties(c.Properties)})
	}

	// A resolved entry's bom-ref joins refToPURL, so its dependency edges survive instead of
	// vanishing with the entry.
	resolvedTwins, unresolved := resolveTwins(components, pending)
	for ref, purl := range resolvedTwins {
		if ref != "" {
			refToPURL[ref] = purl
		}
	}
	for _, u := range unresolved {
		warnings = append(warnings, unresolvedWarning(u))
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

// srcNameFromProperties returns the distro source-package name from a CycloneDX property whose
// name ends with ":srcname" (e.g. Trivy's "aquasecurity:trivy:SrcName"), or "" if absent.
func srcNameFromProperties(props []cycloneDXProperty) string {
	for _, p := range props {
		if strings.HasSuffix(strings.ToLower(p.Name), ":srcname") {
			return strings.TrimSpace(p.Value)
		}
	}
	return ""
}

func validateCycloneDXVersion(version string) error {
	switch version {
	case "", "1.4", "1.5", "1.6":
		return nil
	default:
		return fmt.Errorf("unsupported cyclonedx spec version %q", version)
	}
}

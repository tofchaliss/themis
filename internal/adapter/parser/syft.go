package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// syftDocument is the subset of Syft's native JSON SBOM Themis needs: the
// artifacts inventory and the dependency relationships between them.
type syftDocument struct {
	Artifacts     []syftArtifact     `json:"artifacts"`
	Relationships []syftRelationship `json:"artifactRelationships"`
}

type syftArtifact struct {
	ID   string `json:"id"`
	PURL string `json:"purl"`
}

type syftRelationship struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
}

// SyftAdapter parses Syft (Anchore) native JSON SBOMs, including the dependency
// graph carried in artifactRelationships.
type SyftAdapter struct{}

// Format returns the format discriminator handled by this adapter.
func (SyftAdapter) Format() string { return domain.SBOMFormatSyft }

// Parse normalises a Syft JSON SBOM into the canonical model.
func (SyftAdapter) Parse(_ context.Context, raw []byte, _ string) (domain.CanonicalSBOM, error) {
	var doc syftDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid syft json: %w", err)
	}

	sbom := domain.CanonicalSBOM{Format: domain.SBOMFormatSyft, SpecVersion: "1"}
	idToPURL := map[string]string{}
	seen := map[string]struct{}{}
	for _, artifact := range doc.Artifacts {
		purl := strings.TrimSpace(artifact.PURL)
		if purl == "" {
			continue
		}
		if artifact.ID != "" {
			idToPURL[artifact.ID] = purl
		}
		if _, ok := seen[purl]; ok {
			continue
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

	if len(sbom.Components) == 0 {
		return domain.CanonicalSBOM{}, fmt.Errorf("syft document contains no artifacts with a purl")
	}

	for _, rel := range doc.Relationships {
		if rel.Type != "dependency-of" {
			continue
		}
		from, fromOK := idToPURL[rel.Parent]
		to, toOK := idToPURL[rel.Child]
		if !fromOK || !toOK {
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

package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// grypeDocument is the subset of Grype's native JSON output Themis needs: the
// artifacts inventory. Grype's scanner-reported matches/CVEs are intentionally
// NOT ingested as findings — Themis re-correlates each component against its own
// feeds (CR-9: pure re-correlator).
type grypeDocument struct {
	Artifacts []grypeArtifact `json:"artifacts"`
}

type grypeArtifact struct {
	PURL string `json:"purl"`
}

// GrypeAdapter parses Grype native JSON scan output into the component inventory.
type GrypeAdapter struct{}

// Format returns the format discriminator handled by this adapter.
func (GrypeAdapter) Format() string { return domain.SBOMFormatGrype }

// Parse normalises Grype JSON into the canonical component model.
func (GrypeAdapter) Parse(_ context.Context, raw []byte, _ string) (domain.CanonicalSBOM, error) {
	var doc grypeDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.CanonicalSBOM{}, fmt.Errorf("invalid grype json: %w", err)
	}

	sbom := domain.CanonicalSBOM{Format: domain.SBOMFormatGrype, SpecVersion: "1"}
	seen := map[string]struct{}{}
	for _, artifact := range doc.Artifacts {
		purl := strings.TrimSpace(artifact.PURL)
		if purl == "" {
			continue
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
		return domain.CanonicalSBOM{}, fmt.Errorf("grype document contains no artifacts with a purl")
	}
	return sbom, nil
}

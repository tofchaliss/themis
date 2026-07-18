package serializer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/communication/domain"
)

// JSONReport renders an artifact as a structured audit report (JSON) for compliance /
// internal use. Deterministic.
type JSONReport struct{}

// Format returns "json-report".
func (JSONReport) Format() string { return "json-report" }

type auditReport struct {
	Title           string `json:"title"`
	CVE             string `json:"cve"`
	ReleaseID       string `json:"release_id"`
	FindingID       string `json:"finding_id"`
	FaultlineID     string `json:"faultline_id"`
	PositionVersion int    `json:"position_version"`
	Stance          string `json:"stance"`
	Rationale       string `json:"rationale,omitempty"`
}

// Render serializes the artifact as a JSON audit report.
func (JSONReport) Render(art domain.Artifact) ([]byte, error) {
	rep := auditReport{
		Title:           art.Title,
		CVE:             art.Lineage.CVE,
		ReleaseID:       art.Lineage.ReleaseID,
		FindingID:       art.Lineage.FindingID,
		FaultlineID:     art.Lineage.FaultlineID,
		PositionVersion: art.PositionVersion,
		Stance:          string(art.Stance),
		Rationale:       art.Rationale,
	}
	return json.MarshalIndent(rep, "", "  ")
}

// TextNotification renders an artifact as a channel-native plain-text notification (email
// body / Slack message / webhook text). Deterministic.
type TextNotification struct{}

// Format returns "text".
func (TextNotification) Format() string { return "text" }

// Render serializes the artifact as a plain-text notification.
func (TextNotification) Render(art domain.Artifact) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", art.Title)
	fmt.Fprintf(&b, "%s\n", art.Summary)
	if art.Rationale != "" {
		fmt.Fprintf(&b, "\nRationale: %s\n", art.Rationale)
	}
	return []byte(b.String()), nil
}

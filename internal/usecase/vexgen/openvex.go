package vexgen

import (
	"encoding/json"

	"github.com/themis-project/themis/internal/domain"
)

type openVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability openVEXName   `json:"vulnerability"`
	Products      []openVEXName `json:"products"`
	Status        string        `json:"status"`
	Justification string        `json:"justification,omitempty"`
}

type openVEXName struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"@id,omitempty"`
}

// SerializeOpenVEX encodes export entries as OpenVEX 0.2+ JSON.
func SerializeOpenVEX(entries []domain.VEXExportEntry) ([]byte, error) {
	doc := openVEXDocument{
		Context: "https://openvex.dev/ns/v0.2.0",
		ID:      "https://themis.dev/vex/export",
	}
	for _, entry := range entries {
		doc.Statements = append(doc.Statements, openVEXStatement{
			Vulnerability: openVEXName{Name: entry.CVEID},
			Products:      []openVEXName{{ID: entry.BOMRef}},
			Status:        entry.VEXStatus,
			Justification: entry.Justification,
		})
	}
	return json.Marshal(doc)
}

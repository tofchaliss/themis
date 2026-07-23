// Package inbound is the Communication context's anti-corruption layer for the Governance
// seam: it decodes Governance's Position wire events (PositionEstablished / PositionRevised)
// and updates the publishable-positions worklist — Positions only (DOM-0025). It never
// auto-materializes (D4) and never imports Governance — the event JSON is the only contract.
// Unrelated event types are ignored so the same bus can carry events Communication does not
// consume.
package inbound

import (
	"context"
	"encoding/json"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Governance integration-event type identifiers Communication consumes (mirrors
// EDR-GOVERNANCE-01 D8). These are the wire contract, not a shared package.
const (
	eventPositionEstablished = "governance.position_established"
	eventPositionRevised     = "governance.position_revised"
)

// Consumer translates raw Governance Position events into publishable-queue updates.
type Consumer struct {
	svc *app.PublicationService
}

// NewConsumer wires the inbound consumer over the publication service.
func NewConsumer(svc *app.PublicationService) *Consumer { return &Consumer{svc: svc} }

// Handle decodes and dispatches one Governance event by type. A PositionEstablished marks the
// Position ready to publish; a PositionRevised marks it stale (re-publish needed — D5). An
// unrecognized type is ignored (returns nil); a malformed payload for a recognized type is a
// real error (surfaced so the event is retried, not silently dropped).
func (c *Consumer) Handle(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case eventPositionEstablished:
		snap, err := decodeSnapshot(payload)
		if err != nil {
			return err
		}
		return c.svc.RecordPublishable(ctx, snap, false)
	case eventPositionRevised:
		snap, err := decodeSnapshot(payload)
		if err != nil {
			return err
		}
		return c.svc.RecordPublishable(ctx, snap, true)
	default:
		return nil // not a Communication-consumed event — ignore
	}
}

// positionEventDTO mirrors Governance's PositionEstablished / PositionRevised JSON (its
// domain event structs are marshaled without tags, so keys are the exported field names —
// decoding is case-insensitive).
type positionEventDTO struct {
	FindingID   string `json:"FindingID"`
	ReleaseID   string `json:"ReleaseID"`
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
	Version     int    `json:"Version"`
	Stance      string `json:"Stance"`
}

func decodeSnapshot(payload []byte) (domain.PositionSnapshot, error) {
	var dto positionEventDTO
	if err := json.Unmarshal(payload, &dto); err != nil {
		return domain.PositionSnapshot{}, err
	}
	return domain.PositionSnapshot{
		FindingID: dto.FindingID,
		Version:   dto.Version,
		Stance:    domain.Stance(dto.Stance),
		Lineage: domain.Lineage{
			ReleaseID:   dto.ReleaseID,
			FindingID:   dto.FindingID,
			FaultlineID: dto.FaultlineID,
			CVE:         dto.CVE,
		},
	}, nil
}

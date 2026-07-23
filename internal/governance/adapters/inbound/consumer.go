// Package inbound is the Governance context's anti-corruption layer for the Knowledge
// seam: it decodes Knowledge's completed-fact wire events (ComponentMatched /
// FaultlineEnriched / FaultlineSuperseded) into the app's inbound contract and dispatches
// them to the non-owning coordinator. It never imports Knowledge — the event JSON is the
// only contract (D5/D6). Unrelated event types are ignored so the same bus can carry
// events Governance does not consume.
package inbound

import (
	"context"
	"encoding/json"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// Knowledge integration-event type identifiers Governance consumes (mirrors
// EDR-KNOWLEDGE-01 D8). These are the wire contract, not a shared package.
const (
	eventComponentMatched    = "knowledge.component_matched"
	eventFaultlineEnriched   = "knowledge.faultline_enriched"
	eventFaultlineSuperseded = "knowledge.faultline_superseded"
)

// Consumer translates raw Knowledge events into coordinator calls.
type Consumer struct {
	coord *app.Coordinator
}

// NewConsumer wires the inbound consumer over the coordinator.
func NewConsumer(coord *app.Coordinator) *Consumer { return &Consumer{coord: coord} }

// Handle decodes and dispatches one Knowledge event by type. An unrecognized type is
// ignored (returns nil) so the consumer tolerates a shared bus. A malformed payload for a
// recognized type is a real error (surfaced so the event is retried, not silently dropped).
func (c *Consumer) Handle(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case eventComponentMatched:
		var dto componentMatchedDTO
		if err := json.Unmarshal(payload, &dto); err != nil {
			return err
		}
		return c.coord.OnComponentMatched(ctx, dto.toInbound())
	case eventFaultlineEnriched:
		var dto faultlineEnrichedDTO
		if err := json.Unmarshal(payload, &dto); err != nil {
			return err
		}
		return c.coord.OnFaultlineEnriched(ctx, app.InboundFaultlineEnriched{
			FaultlineID: dto.FaultlineID, CVE: dto.CVE, Severity: dto.Severity, KEV: dto.KEV, ExploitPublic: dto.ExploitPublic,
		})
	case eventFaultlineSuperseded:
		var dto faultlineSupersededDTO
		if err := json.Unmarshal(payload, &dto); err != nil {
			return err
		}
		return c.coord.OnFaultlineSuperseded(ctx, app.InboundFaultlineSuperseded{FaultlineID: dto.FaultlineID, CVE: dto.CVE})
	default:
		return nil // not a Governance-consumed event — ignore
	}
}

// The DTOs mirror Knowledge's event JSON (its domain event structs are marshaled without
// tags, so keys are the exported field names — decoding is case-insensitive).

type componentMatchedDTO struct {
	FaultlineID string         `json:"FaultlineID"`
	CVE         string         `json:"CVE"`
	ReleaseID   string         `json:"ReleaseID"`
	Components  []componentDTO `json:"Components"`
}

type componentDTO struct {
	PURL      string `json:"PURL"`
	Name      string `json:"Name"`
	Version   string `json:"Version"`
	Ecosystem string `json:"Ecosystem"`
}

func (d componentMatchedDTO) toInbound() app.InboundComponentMatched {
	comps := make([]domain.MatchedComponent, 0, len(d.Components))
	for _, c := range d.Components {
		comps = append(comps, domain.MatchedComponent{PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem})
	}
	return app.InboundComponentMatched{FaultlineID: d.FaultlineID, CVE: d.CVE, ReleaseID: d.ReleaseID, Components: comps}
}

type faultlineEnrichedDTO struct {
	FaultlineID   string `json:"FaultlineID"`
	CVE           string `json:"CVE"`
	Severity      string `json:"Severity"`
	KEV           bool   `json:"KEV"`
	ExploitPublic bool   `json:"ExploitPublic"`
}

type faultlineSupersededDTO struct {
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
}

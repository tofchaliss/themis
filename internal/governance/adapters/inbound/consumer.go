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
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/platform/eventbus"
)

// Knowledge integration-event type identifiers Governance consumes (mirrors
// EDR-KNOWLEDGE-01 D8). These are the wire contract, not a shared package.
const (
	eventComponentMatched        = "knowledge.component_matched"
	eventComponentVerdictChanged = "knowledge.component_verdict_changed"
	eventFaultlineEnriched       = "knowledge.faultline_enriched"
	eventFaultlineSuperseded     = "knowledge.faultline_superseded"
)

// Subscription declares Governance's bus binding (EB-07 / D7): it consumes the Knowledge
// stream and dispatches on the three Faultline facts below (its interest set — the same
// types Handle switches on). Composition binds this to a platform Reader over the inbox-
// wrapped Consumer; the interest filter drops any other type the stream may carry.
var Subscription = eventbus.Subscription{
	Consumer: "governance",
	Stream:   "knowledge",
	Interest: []string{eventComponentMatched, eventComponentVerdictChanged, eventFaultlineEnriched, eventFaultlineSuperseded},
}

// Consumer translates raw Knowledge events into coordinator calls.
type Consumer struct {
	coord *app.Coordinator
}

// NewConsumer wires the inbound consumer over the coordinator.
func NewConsumer(coord *app.Coordinator) *Consumer { return &Consumer{coord: coord} }

// Handle decodes and dispatches one Knowledge event carried by the kernel Envelope. It
// reads the event type + payload from the Envelope (M5 EB-02); the rest of the envelope
// metadata is transport concern, not the ACL's. An unrecognized type is ignored (returns
// nil) so the consumer tolerates a shared bus. A malformed payload for a recognized type
// is a real error (surfaced so the event is retried, not silently dropped).
func (c *Consumer) Handle(ctx context.Context, env event.Envelope) error {
	switch env.Type {
	case eventComponentMatched:
		var dto componentMatchedDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return err
		}
		return c.coord.OnComponentMatched(ctx, dto.toInbound())
	case eventComponentVerdictChanged:
		var dto componentVerdictChangedDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return err
		}
		return c.coord.OnComponentVerdictChanged(ctx, app.InboundComponentVerdictChanged{
			FaultlineID: dto.FaultlineID, ReleaseID: dto.ReleaseID, Component: dto.Component.toDomain(),
		})
	case eventFaultlineEnriched:
		var dto faultlineEnrichedDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return err
		}
		apps := make([]app.Applicability, 0, len(dto.Applicabilities))
		for _, a := range dto.Applicabilities {
			apps = append(apps, app.Applicability{Package: a.Package, Status: a.Status, Justification: a.Justification})
		}
		return c.coord.OnFaultlineEnriched(ctx, app.InboundFaultlineEnriched{
			FaultlineID: dto.FaultlineID, CVE: dto.CVE, Severity: dto.Severity, KEV: dto.KEV, ExploitPublic: dto.ExploitPublic, Score: dto.Score,
			EPSS:            dto.EPSS,
			Priority:        dto.Priority,
			Fixes:           toAppFixes(dto.Fixes),
			Applicabilities: apps,
			AffectedRanges:  dto.AffectedRanges,
			HeadlineTrust:   value.TrustClass(dto.HeadlineTrust),
			RangeTrust:      value.TrustClass(dto.RangeTrust),
			SignalTrust:     value.TrustClass(dto.SignalTrust),
		})
	case eventFaultlineSuperseded:
		var dto faultlineSupersededDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return err
		}
		return c.coord.OnFaultlineSuperseded(ctx, app.InboundFaultlineSuperseded{
			FaultlineID: dto.FaultlineID, CVE: dto.CVE, Trust: value.TrustClass(dto.Trust),
		})
	default:
		return nil // not a Governance-consumed event — ignore
	}
}

// The DTOs mirror Knowledge's event JSON (its domain event structs are marshaled without
// tags, so keys are the exported field names — decoding is case-insensitive).

type componentMatchedDTO struct {
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
	ReleaseID   string `json:"ReleaseID"`
	Score       int    `json:"Score"` // card's CVE-intrinsic score at match time (C6); 0 when an older payload omits it.
	// Priority and Fixes at MATCH time (BUG-3b). Empty on a payload predating the field, which
	// reads as the old behaviour: the Finding waits for an enrichment event that may never come.
	Priority   string         `json:"Priority"`
	Fixes      []fixDTO       `json:"Fixes"`
	Components []componentDTO `json:"Components"`
}

type componentDTO struct {
	PURL      string `json:"PURL"`
	Name      string `json:"Name"`
	Version   string `json:"Version"`
	Ecosystem string `json:"Ecosystem"`
	// Source is the upstream source-package name for distro components (AI-GROUND-1). Absent
	// on payloads predating the field, which leaves selection to the name/namespace keys.
	Source string `json:"Source"`
	// ClaimClass — carrier | scope | "" (unknown). Absent on payloads predating
	// EDR-CORRELATION-01, which reads as unknown and is therefore treated as carrier: exactly
	// the pre-change behaviour.
	ClaimClass string `json:"ClaimClass"`
	// DetectionOrigin — `discovery` | `scanner/<name>` | "" (unknown, on payloads predating
	// KN-SCAN-2). Display provenance only; carried, never acted on.
	DetectionOrigin string `json:"DetectionOrigin"`
	// The occurrence verdict, mirrored as-is (EDR-VERDICT-01 D5). Absent on payloads predating
	// the field, which decodes to "" and reads as open — the fail-safe direction.
	VerdictState  string `json:"VerdictState"`
	VerdictGrade  string `json:"VerdictGrade"`
	VerdictReason string `json:"VerdictReason"`
}

func (c componentDTO) toDomain() domain.MatchedComponent {
	return domain.MatchedComponent{
		PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, Source: c.Source,
		ClaimClass: c.ClaimClass, DetectionOrigin: c.DetectionOrigin,
		VerdictState: c.VerdictState, VerdictGrade: c.VerdictGrade, VerdictReason: c.VerdictReason,
	}
}

func (d componentMatchedDTO) toInbound() app.InboundComponentMatched {
	comps := make([]domain.MatchedComponent, 0, len(d.Components))
	for _, c := range d.Components {
		comps = append(comps, c.toDomain())
	}
	return app.InboundComponentMatched{
		FaultlineID: d.FaultlineID, CVE: d.CVE, ReleaseID: d.ReleaseID, Score: d.Score,
		Band: d.Priority, Fixes: toAppFixes(d.Fixes), Components: comps,
	}
}

// componentVerdictChangedDTO mirrors Knowledge's ComponentVerdictChanged wire JSON
// (EDR-VERDICT-01 D5/D6): one existing occurrence whose verdict state changed.
type componentVerdictChangedDTO struct {
	FaultlineID string       `json:"FaultlineID"`
	CVE         string       `json:"CVE"`
	ReleaseID   string       `json:"ReleaseID"`
	Component   componentDTO `json:"Component"`
}

type faultlineEnrichedDTO struct {
	FaultlineID     string             `json:"FaultlineID"`
	CVE             string             `json:"CVE"`
	Severity        string             `json:"Severity"`
	KEV             bool               `json:"KEV"`
	ExploitPublic   bool               `json:"ExploitPublic"`
	Score           int                `json:"Score"`           // CVE-intrinsic base priority (C6); 0 when an older payload omits it.
	EPSS            float64            `json:"EPSS"`            // exploitation probability, for disposition-drift detection (GOV-14b).
	Priority        string             `json:"Priority"`        // exploitability band, materialized onto the posture (DASH-2).
	Fixes           []fixDTO           `json:"Fixes"`           // package-attributed fixes, selected per component (PLAN-3).
	Applicabilities []applicabilityDTO `json:"Applicabilities"` // vendor VEX statements (EDR-VEX-01 D5); absent on an older payload.
	// Per-field-group trust from Knowledge's reconciled view (EDR-TRUST-01 T2/T3). Empty
	// on a payload predating the field — which is safe, because value.MaxTrust reads an
	// unset class as Inferred, the most conservative answer.
	// AffectedRanges is Knowledge's reconciled range (D3); absent on an older payload.
	AffectedRanges []string `json:"AffectedRanges"`
	HeadlineTrust  string   `json:"HeadlineTrust"`
	RangeTrust     string   `json:"RangeTrust"`
	SignalTrust    string   `json:"SignalTrust"`
}

type fixDTO struct {
	Package string `json:"Package"`
	Version string `json:"Version"`
	// Ecosystem is additive (KN-FIX-3): absent on a payload predating it, which decodes to ""
	// = "not stated" and filters nothing.
	Ecosystem string `json:"Ecosystem"`
}

type applicabilityDTO struct {
	Package       string `json:"Package"`
	Status        string `json:"Status"`
	Justification string `json:"Justification"`
}

type faultlineSupersededDTO struct {
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
	Trust       string `json:"Trust"`
}

// toAppFixes maps the wire fixes into Governance's own vocabulary (no cross-context import).
func toAppFixes(in []fixDTO) []app.FixedVersion {
	out := make([]app.FixedVersion, 0, len(in))
	for _, f := range in {
		out = append(out, app.FixedVersion{Package: f.Package, Version: f.Version, Ecosystem: f.Ecosystem})
	}
	return out
}

package domain

// ArtifactType is the audience-specific kind of a materialized artifact (D3). The set is
// extensible — a new audience is a new materializer/serializer, not a model change.
type ArtifactType string

const (
	// ArtifactVEX — machine-readable VEX document (CycloneDX VEX / OpenVEX) for tooling.
	ArtifactVEX ArtifactType = "vex"
	// ArtifactAdvisory — human-readable, customer-facing security advisory (CSAF / Markdown).
	ArtifactAdvisory ArtifactType = "advisory"
	// ArtifactNotification — email / Slack / webhook alert.
	ArtifactNotification ArtifactType = "notification"
	// ArtifactAuditReport — compliance / internal report.
	ArtifactAuditReport ArtifactType = "audit_report"
)

// Valid reports whether t is a recognized artifact type.
func (t ArtifactType) Valid() bool {
	switch t {
	case ArtifactVEX, ArtifactAdvisory, ArtifactNotification, ArtifactAuditReport:
		return true
	default:
		return false
	}
}

// Artifact is the abstract, pre-serialization materialized artifact (D3): the deterministic
// content derived from one Position, holding the type, the carried-verbatim stance (the
// stance-equality invariant), the presentation text, and the lineage. Serializers (adapters)
// render an Artifact into concrete bytes for a format; the external format shapes never leak
// into the domain.
type Artifact struct {
	Type            ArtifactType
	Stance          Stance
	Title           string
	Summary         string
	Rationale       string
	PositionVersion int
	Lineage         Lineage
}

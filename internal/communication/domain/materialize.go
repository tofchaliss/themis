package domain

import "fmt"

// Materialize is the pure, deterministic transform of an Enterprise Position (+ lineage)
// into an abstract artifact for a given audience type (D3). Re-running it on the same
// snapshot yields identical content, which is what makes the Publication's payload
// regenerable (D1).
//
// Hard invariant (CON-0010 / DOM-0025): the artifact's stance ALWAYS equals the Position's
// stance — it is carried verbatim, never reinterpreted. Only the presentation (title,
// summary, wording) is derived per audience; the conclusion may not vary.
func Materialize(snap PositionSnapshot, typ ArtifactType) (Artifact, error) {
	if !typ.Valid() {
		return Artifact{}, errUnknownArtifact
	}
	if !snap.Stance.Valid() {
		return Artifact{}, errInvalidStance
	}
	if snap.FindingID == "" {
		return Artifact{}, errEmptyFinding
	}
	return Artifact{
		Type:            typ,
		Stance:          snap.Stance, // verbatim — the stance-equality invariant
		Title:           titleFor(typ, snap.Lineage.CVE),
		Summary:         summaryFor(snap),
		Rationale:       snap.Rationale,
		PositionVersion: snap.Version,
		Lineage:         snap.Lineage,
	}, nil
}

// titleFor renders a deterministic, audience-appropriate title.
func titleFor(typ ArtifactType, cve string) string {
	if cve == "" {
		cve = "unspecified CVE"
	}
	switch typ {
	case ArtifactVEX:
		return "VEX statement for " + cve
	case ArtifactAdvisory:
		return "Security advisory for " + cve
	case ArtifactNotification:
		return "Security notification: " + cve
	default: // ArtifactAuditReport (typ is pre-validated by Materialize)
		return "Audit report for " + cve
	}
}

// summaryFor renders a deterministic one-line summary that states the same conclusion as
// the Position's stance for the affected release.
func summaryFor(snap PositionSnapshot) string {
	cve := snap.Lineage.CVE
	if cve == "" {
		cve = "the referenced vulnerability"
	}
	rel := snap.Lineage.ReleaseID
	if rel == "" {
		rel = "the release"
	}
	return fmt.Sprintf("Release %s is %s with respect to %s.", rel, snap.Stance.Phrase(), cve)
}

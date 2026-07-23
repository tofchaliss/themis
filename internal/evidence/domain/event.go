package domain

import "time"

// EvidenceRegistered is the thin completed-fact event published after an Evidence
// record is atomically persisted (EDR-EVIDENCE-01 D6/D7; DOM-0033). It carries only
// key headers — never the full inventory. Downstream contexts fetch the canonical
// inventory through Evidence's read API, keyed by the Evidence ID.
type EvidenceRegistered struct {
	EvidenceID       EvidenceID
	Kind             Kind
	SubjectReleaseID string
	Fingerprint      string
	OccurredAt       time.Time
}

// NewEvidenceRegistered builds the event from a persisted Evidence aggregate.
func NewEvidenceRegistered(e Evidence, occurredAt time.Time) EvidenceRegistered {
	return EvidenceRegistered{
		EvidenceID:       e.ID(),
		Kind:             e.Kind(),
		SubjectReleaseID: e.Subject().ReleaseID,
		Fingerprint:      e.Fingerprint().String(),
		OccurredAt:       occurredAt,
	}
}

package domain

// PositionSnapshot is the Enterprise Position, as Communication fetches it from Governance's
// read API (GetPosition — D2), together with its lineage handles. It is the sole input to
// materialization (D3): Communication reads it, never Governance's tables, and keeps no copy
// beyond the resulting Publication's lineage reference.
type PositionSnapshot struct {
	FindingID string
	Version   int
	Stance    Stance
	Rationale string
	Lineage   Lineage
}

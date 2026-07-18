package domain

// Lineage is the permanent reference chain a Publication records (CON-0016 / D2):
// Position → Finding → Faultline → Evidence, held as immutable reference handles (ids),
// never copies of upstream state. The deeper chain (e.g. the Evidence record) stays
// reconstructable by traversal; Communication keeps only the handles.
type Lineage struct {
	ReleaseID   string
	FindingID   string
	FaultlineID string
	CVE         string
}

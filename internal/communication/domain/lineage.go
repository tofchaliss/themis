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
	// Components are the affected package PURLs the Position is about, carried from
	// Governance's Finding. They answer "which packages inside that release?", which is the
	// other half of what a lineage identifies — and what a standards-compliant VEX document
	// must name, as OpenVEX `subcomponents`, for a consumer to act on it.
	Components []string
}

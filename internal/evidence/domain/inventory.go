package domain

import "github.com/themis-project/themis/internal/kernel/value"

// Component is one normalized entry in an Evidence SBOM's canonical inventory.
type Component struct {
	PURL      value.PURL
	Name      string
	Version   string
	Ecosystem string
}

// DependencyEdge is a normalized dependency relationship between two components.
type DependencyEdge struct {
	From         value.PURL
	To           value.PURL
	Relationship string
}

// Inventory is the format-neutral component inventory translated from an SBOM at
// the door (EDR-EVIDENCE-01 D4). Scanner-reported vulnerabilities are intentionally
// not carried — Themis re-correlates against its own feeds downstream, so trusting
// the scanner's vuln list is out of scope for Evidence.
type Inventory struct {
	components   []Component
	dependencies []DependencyEdge
}

// NewInventory constructs an inventory, defensively copying its inputs so the
// aggregate can never be mutated through the caller's slices.
func NewInventory(components []Component, dependencies []DependencyEdge) Inventory {
	return Inventory{
		components:   append([]Component(nil), components...),
		dependencies: append([]DependencyEdge(nil), dependencies...),
	}
}

// Components returns a copy of the inventory's components.
func (inv Inventory) Components() []Component {
	return append([]Component(nil), inv.components...)
}

// Dependencies returns a copy of the inventory's dependency edges.
func (inv Inventory) Dependencies() []DependencyEdge {
	return append([]DependencyEdge(nil), inv.dependencies...)
}

// IsEmpty reports whether the inventory has no components.
func (inv Inventory) IsEmpty() bool { return len(inv.components) == 0 }

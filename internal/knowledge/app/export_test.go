package app

// ScannerOnlyComponentsForTest exposes the scanner-only selection for its edge-case test.
func ScannerOnlyComponentsForTest(items []ScannerProposal, siblings []InventoryComponent) []InventoryComponent {
	return scannerOnlyComponents(items, siblings)
}

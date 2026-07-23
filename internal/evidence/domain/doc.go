// Package domain is the Evidence context's pure inner ring: the Evidence
// aggregate, its invariants, the canonical component inventory, and the
// EvidenceRegistered domain event.
//
// Ring rules (EDR-EVIDENCE-01 D9; openspec/changes/phase3-evidence/design.md):
// it depends on nothing but the standard library and the behavior-free shared
// kernel (internal/kernel). It must never import the app or adapters rings, nor
// any other bounded context.
package domain

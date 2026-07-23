// Package domain is the gateway core of the Intelligence supporting context
// (EDR-INTELLIGENCE-01, Revision 2 · Δ1). It holds the pure, I/O-free types and
// rules the AI Gateway is built from: the Capability + its ExecutionPlan, the
// in-code Capability Registry, the structured advisory Proposal envelope, the
// AssembledContext (grounding), the recommendable Stance subset, and the pure
// 3-stage validators (schema -> business -> proposal construction).
//
// Intelligence owns no enterprise truth (D1): these types are advisory transports
// and grounding views, never Faultlines/Findings/Positions. The domain ring
// imports only the standard library, the shared kernel, and the JSON-schema
// validator; it performs no I/O.
package domain

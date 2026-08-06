// Package readapi holds the Intelligence Gateway's read clients: HTTP clients that decode
// wire JSON into the intelligence domain's own view types, never importing another context's
// packages (the JSON contract is the only coupling).
//
// The grounding read is AssessmentClient, which fetches one business-named **Domain
// Projection** (EDR-TRUST-01 T10). It replaced a pair of gathering clients — a Finding from
// Governance plus a Faultline from Knowledge, composed here — which made the runtime a
// participant in business orchestration rather than a reasoning engine.
//
// PrecedentClient remains as the exact-CVE fallback used only when semantic retrieval found
// nothing; it grounds reasoning with our own past decisions rather than assembling the
// subject.
package readapi

// Package domain is the Governance context's domain ring (EDR-GOVERNANCE-01 D13):
// the Finding aggregate — Governance's release-scoped record of how one Faultline
// affects one Release (own identity; keyed by (Release, Faultline)) — carrying its
// matched components, an explicit investigation lifecycle, append-only Governance
// Proposals, append-only immutable Enterprise Position versions, and a materialized
// current position. It also holds the Governance Proposal + lifecycle, the Enterprise
// Position value object + extensible stance set, the pure policy-rule evaluation, and
// the Governance domain events. The ring is pure: it depends only on the standard
// library and the shared kernel.
package domain

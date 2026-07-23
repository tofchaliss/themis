// Package domain is the Knowledge context's domain ring (EDR-KNOWLEDGE-01 D12): the
// Faultline aggregate — the enterprise's single knowledge card per canonical CVE
// (own identity; CVE = alias) — with its append-only source Proposals, a materialized
// enterprise view reconciled by a fixed precedence rule, and a forward-only lifecycle
// ladder. It also holds the Proposal value object + kinds, the pure reconciliation
// rule, and the Knowledge domain events. The ring is pure: it depends only on the
// standard library and the shared kernel.
package domain

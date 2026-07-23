// Package app is the Governance context's application ring (EDR-GOVERNANCE-01 D13):
// the use cases — OpenOrUpdateFinding, RaiseProposal, Accept/RejectProposal,
// Resolve/Reopen/ArchiveFinding, GetFinding/GetPosition, Reconcile — and the ports
// they depend on (the Knowledge event subscription, the outbox, the aggregate
// repository, the projection store, the policy rules, and authorization). It
// orchestrates the domain and depends only on the domain + the shared kernel; never
// on another bounded context (collaboration is via events + read APIs).
package app

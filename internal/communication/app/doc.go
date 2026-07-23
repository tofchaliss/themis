// Package app is the Communication context's application ring (EDR-COMMUNICATION-01 D12):
// the use cases — CreatePublication (human-triggered), Preview (non-recording render),
// GetPublication / ListPublications, Reconcile, Prune, and the inbound handling that marks
// Positions publishable / stale — and the ports they depend on (the Governance read-API
// client, the serializer registry, the delivery channels, the outbox, the aggregate
// repository, the projection store, and routing rules). It orchestrates the domain and
// depends only on the domain; never on another bounded context (collaboration is via
// events + read APIs).
package app

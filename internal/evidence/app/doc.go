// Package app holds the Evidence context's application services (use cases):
// RegisterEvidence, GetEvidence, GetInventory, and List — orchestrating the
// domain through ports (store, parser, trust, outbox, subject-ref).
//
// Ring rules (EDR-EVIDENCE-01 D9): it imports only the domain ring and the shared
// kernel (internal/kernel). It must never import the adapters ring or any other
// bounded context. Collaboration with other contexts happens solely via events
// and read APIs.
package app

// Package adapters is the Knowledge context's outer ring (EDR-KNOWLEDGE-01 D12): the
// feed anti-corruption layers (nvd/osv/redhat/epsskev/exploitdb/vexfeed) that
// translate each source dialect into the common Proposal, the Evidence read-API
// client, the Postgres store (Faultline aggregate + outbox + projections), the HTTP
// read API, and the background workers. Adapters implement the app ports and depend
// inward on app + domain; they never import another bounded context.
package adapters

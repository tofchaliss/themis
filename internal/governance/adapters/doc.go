// Package adapters is the Governance context's outer ring (EDR-GOVERNANCE-01 D13):
// the inbound event consumers (Knowledge's ComponentMatched / FaultlineEnriched), the
// Postgres store (Finding aggregate + outbox + projections), the HTTP triage + read
// API, the background workers, and the policy-rule engine. Adapters implement the app
// ports and depend inward on app + domain; they never import another bounded context.
package adapters

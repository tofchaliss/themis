// Package adapters is the Communication context's outer ring (EDR-COMMUNICATION-01 D12):
// the Governance read-API client (fetch a Position via GetPosition, never its tables), the
// inbound Position-event consumer, the serializer registry (CycloneDX VEX / OpenVEX / CSAF
// / human-readable advisory / audit report / channel-native notification), the delivery
// channels (export / email / Slack / webhook), the Postgres store (Publication aggregate +
// capped payload + outbox + projections), the HTTP publish-trigger + read/preview API, and
// the background workers. Adapters implement the app ports and depend inward on app +
// domain; they never import another bounded context.
package adapters

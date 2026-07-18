// Package event defines the integration-event envelope — the stable, behavior-free
// contract that wraps every domain event crossing a bounded-context boundary
// (EDR-KERNEL-01 D4 · BCK-0046). Only the envelope value shape and its JSON schema
// live here: specific event types are owned by their publishing context, and the
// outbox runner + bus that carry envelopes are Event Infrastructure (M5), not the
// kernel.
package event

// Package adapters holds the Intelligence Gateway's outer ring (EDR-INTELLIGENCE-01,
// Revision 2 · Δ1): the LLM engine and its provider adapters (Ollama over the
// OpenAI-compatible schema, plus a deterministic fake for CI), the Knowledge and
// Governance read-API clients (Knowledge Providers that decode wire JSON into the
// domain's own view types — no cross-context imports), the spec-first reactive
// HTTP API, telemetry, and wiring.
//
// All provider/engine-specific code is confined here behind the app ports (INT-0070);
// a provider swap never touches the domain or app rings.
package adapters

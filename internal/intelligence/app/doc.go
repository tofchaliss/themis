// Package app is the Intelligence Gateway's invoke pipeline (EDR-INTELLIGENCE-01,
// Revision 2 · Δ1). It orchestrates the deterministic chain a reactive capability
// runs through — context construction -> prompt -> route -> execute -> validate ->
// propose — and defines the ports the adapters satisfy (Engine, Provider, Router,
// FindingReader, FaultlineReader, PromptRenderer, Clock).
//
// The pipeline reads enterprise knowledge only through the read-API ports
// (Knowledge Providers, D5), never a truth store, and returns the validated
// advisory Proposal to its caller — it writes nothing to any context (D1). It
// imports only the standard library, the shared kernel, and the intelligence
// domain ring.
package app

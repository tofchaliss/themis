// Package adapters is the Evidence context's outer ring (plumbing). Its
// subpackages implement the app-layer ports: store (Postgres record + outbox +
// read views), parser (CycloneDX/SPDX ACL), trust (the trust gate), and http (the
// REST counter).
//
// Ring rules (EDR-EVIDENCE-01 D9): adapters may import the app and domain rings,
// the shared kernel (internal/kernel), and the registry's public API
// (internal/registry) — but never another bounded context, and they are never
// imported by domain or app.
package adapters

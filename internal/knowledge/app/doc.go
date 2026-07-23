// Package app is the Knowledge context's application ring (EDR-KNOWLEDGE-01 D12):
// the use cases — Fold-Proposal/Enrich, Correlate, Watch, Reconcile, GetFaultline —
// and the ports they depend on (feed clients, the Evidence read-API client, the
// outbox, the aggregate repository, the projection store). It orchestrates the
// domain and depends only on the domain + the shared kernel; never on another
// bounded context (collaboration is via events + read APIs).
package app

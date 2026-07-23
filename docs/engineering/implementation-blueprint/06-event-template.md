# Blueprint 06 — Event & Transactional-Outbox Template

Pattern (realized: `evidence/domain` + `evidence/adapters/store`):

- The domain defines a **thin completed-fact event** carrying key headers only (id, kind, subject ref,
  fingerprint) — never the full payload; downstream fetches detail via the read API (DOM-0033;
  EDR-EVIDENCE-01 D6). Exemplar: `EvidenceRegistered`.
- Persistence writes the aggregate **and** an outbox note in **one local transaction** (BCK-0041): every
  stored aggregate is announced exactly once, and no announcement ever exists for un-stored data. Exemplar:
  `Store.Save` (`INSERT … ON CONFLICT (fingerprint) DO NOTHING` for idempotency, then the outbox note).
- A **Relay** delivers unsent notes via a `Publisher` port, marks them sent, and increments an attempt
  counter + retries on failure without aborting the batch (exactly-once-eventually). Exemplar:
  `Relay.DeliverPending`.
- The `Publisher` is a stand-in (logging) until the **Event Infrastructure (M5)** event bus is available;
  this outbox + relay is the reusable M5 seed.

## Schema

`evidence` + `evidence_outbox` (see `internal/evidence/adapters/store/migrations/`). JSON payloads are
passed to `jsonb` columns as strings (pgx encodes `[]byte` as `bytea`). The outbox note carries the
serialized event payload + `occurred_at`; `sent_at IS NULL` indexes the unsent queue.

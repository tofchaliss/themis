// Package eventbus is the platform-owned event transport — Event Infrastructure (M5,
// EDR-EVENTBUS-01). It owns the channel between each bounded context's transactional
// outbox and the inbound consumers: the `bus` database's event log, the Publisher that
// appends to it (EB-04), and the stream Reader / drain engine that delivers envelopes
// to a consumer's Handle (EB-05).
//
// It is business-agnostic (D10): it moves kernel Envelopes and knows nothing of any
// bounded context. It depends only on the kernel (internal/kernel/event.Envelope) and
// infrastructure drivers (pgx, golang-migrate, OpenTelemetry) — never on a context's
// domain/app/adapters, nor on the registry. Like internal/platform/observability, it
// may be imported only by adapters and composition roots (cmd/*); the depguard rule
// platform-eventbus-infra-only and the architecture test TestPlatformEventbusIsBusinessAgnostic
// enforce both directions.
//
// Topology (D3/D4): one PostgreSQL server, database-per-context plus a dedicated `bus`
// database that holds the single event_log — a Postgres stand-in for a Kafka topic.
// A database boundary is hard (no cross-database joins/transactions), so split-stability
// is structural, not disciplinary: a consumer physically cannot read another context's
// tables.
//
// Governing principle (EDR-EVENTBUS-01): freeze contracts early, evolve implementations
// later. A broker can slot behind the same Envelope + ports (D1/D2) without changing any
// bounded context.
package eventbus

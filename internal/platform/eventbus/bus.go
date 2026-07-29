package eventbus

// event_log schema — the single platform channel, a Postgres stand-in for a Kafka topic
// (EDR-EVENTBUS-01 D4). The Publisher (EB-04) appends one row per outbox note; the stream
// Reader (EB-05) drains rows in Seq order, filtered by SourceContext (the stream, D7),
// and per-Subject order falls out of the single monotonic Seq (D6). EnvelopeID is UNIQUE,
// giving at-most-once append and the dedup key behind exactly-once application (D5).
//
// These names are the one source of truth shared by the Publisher, Reader, and the
// migrations under ./migrations; they exist now so later groups build on a fixed contract.
const (
	TableEventLog = "event_log"

	ColSeq           = "seq"            // monotonic append order (one cursor → per-subject order, D6)
	ColEnvelopeID    = "envelope_id"    // kernel Envelope id; UNIQUE → dedup / exactly-once application (D5)
	ColSourceContext = "source_context" // the stream: routing + ordering unit (D7)
	ColSubject       = "subject"        // per-subject ordering key (D6)
	ColType          = "type"           // event type, e.g. "evidence.registered"
	ColOccurredAt    = "occurred_at"    // source state-transition time
	ColCorrelationID = "correlation_id" // ties events into a workflow across contexts
	ColSchemaRef     = "schema_ref"     // integration-contract id of the payload (D9)
	ColPayload       = "payload"        // opaque producer-owned integration event
	ColInsertXid8    = "insert_xid8"    // inserting transaction id; backs the Reader's gap-free watermark (EB-05, D7)
)

// stream_cursor schema — the per-consumer read position over a stream (EB-05, D5). The
// cursor is a PostgreSQL-era read optimization only: correctness is the consumer's
// processed_events inbox, so a lost cursor rescans from zero as a no-op.
const (
	TableStreamCursor = "stream_cursor"

	ColConsumer  = "consumer"       // the subscribing consumer
	ColStream    = "source_context" // the subscribed stream (shares event_log's source_context)
	ColLastSeq   = "last_seq"       // highest seq whose Handle succeeded for this (consumer, stream)
	ColUpdatedAt = "updated_at"
)

// DefaultMigrationsPath is where the `bus` migrations live, applied against the `bus`
// database by a composition root (mirrors each context's THEMIS_<CTX>_MIGRATIONS default;
// applied with golang-migrate over a file:// source, like every context store).
const DefaultMigrationsPath = "internal/platform/eventbus/migrations"

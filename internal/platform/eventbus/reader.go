package eventbus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Handler applies one delivered envelope. A consuming context's inbound Consumer.Handle
// satisfies it; the Reader is business-agnostic and dispatches nothing itself — the
// interest set (which event types a consumer acts on) lives in the Consumer (EB-07).
type Handler interface {
	Handle(ctx context.Context, env event.Envelope) error
}

// ErrStreamHalted is returned by Drain once a poison event has halted the stream. It is a
// loud, terminal condition (D8, M5 cut): the stream stops rather than silently skipping an
// event, and a human must intervene before the Reader will process anything else.
var ErrStreamHalted = errors.New("eventbus: stream halted (poison event)")

const (
	defaultReaderBatch = 100
	defaultMaxAttempts = 5
	defaultBaseBackoff = 100 * time.Millisecond
	maxBackoff         = 30 * time.Second
)

// ReaderConfig configures a stream Reader. Zero values take sane defaults.
type ReaderConfig struct {
	Consumer    string        // the subscribing consumer id (e.g. "governance")
	Stream      string        // the subscribed stream = event_log.source_context (e.g. "knowledge")
	BatchSize   int           // max envelopes per Drain pass (default 100)
	MaxAttempts int           // retries before an event is declared poison (default 5)
	BaseBackoff time.Duration // first retry backoff; doubles per attempt, capped (default 100ms)
}

// Reader is the drain engine (EB-05): it reads one subscribed stream from bus.event_log in
// seq order — which yields per-subject order for free (D6) — through a per-consumer cursor,
// and calls Handler for each envelope. It is gap-free by observable contract (D7): a
// txid watermark keeps it from stepping over a lower seq whose inserting transaction has not
// yet become visible. Failures follow D8's M5 cut: retry with backoff, then halt the whole
// stream with a loud alert (never silent-skip). The subject-aware scheduler that isolates a
// halt to a single Subject is the documented migration target, not built here.
type Reader struct {
	pool        *pgxpool.Pool
	logger      *observability.Logger
	handler     Handler
	consumer    string
	stream      string
	batchSize   int
	maxAttempts int
	baseBackoff time.Duration
	halted      bool
}

// NewReader builds a Reader over a pool connected to the `bus` database.
func NewReader(pool *pgxpool.Pool, logger *observability.Logger, cfg ReaderConfig, handler Handler) *Reader {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultReaderBatch
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	return &Reader{
		pool:        pool,
		logger:      logger,
		handler:     handler,
		consumer:    cfg.Consumer,
		stream:      cfg.Stream,
		batchSize:   cfg.BatchSize,
		maxAttempts: cfg.MaxAttempts,
		baseBackoff: cfg.BaseBackoff,
	}
}

// Halted reports whether a poison event has stopped the stream (D8). A halted Reader
// applies nothing until the process is restarted after the cause is resolved.
func (r *Reader) Halted() bool { return r.halted }

// stamped pairs a scanned envelope with its event_log seq (the cursor key; the seq is not
// part of the wire Envelope).
type stamped struct {
	seq int64
	env event.Envelope
}

// Drain delivers up to BatchSize envelopes from the subscribed stream in seq order,
// advancing the cursor after each success, and returns the number applied. A transient
// error (handler failure within MaxAttempts, or a cursor/read DB error) leaves the cursor
// where it is and returns the error for the caller to retry next tick — redelivery is safe
// because the consumer inbox makes application idempotent (D5). A poison event (still
// failing after MaxAttempts) halts the stream: Drain alerts loudly and returns
// ErrStreamHalted, and every later call returns ErrStreamHalted without applying anything.
func (r *Reader) Drain(ctx context.Context) (int, error) {
	if r.halted {
		return 0, ErrStreamHalted
	}

	cursor, err := r.loadCursor(ctx)
	if err != nil {
		return 0, fmt.Errorf("eventbus: load cursor for %q/%q: %w", r.consumer, r.stream, err)
	}

	batch, err := r.readBatch(ctx, cursor)
	if err != nil {
		return 0, fmt.Errorf("eventbus: read stream %q: %w", r.stream, err)
	}

	applied := 0
	for _, s := range batch {
		if err := r.deliver(ctx, s.env); err != nil {
			if ctx.Err() != nil {
				return applied, ctx.Err() // graceful shutdown mid-backoff — not a poison halt
			}
			r.halted = true
			r.logger.Error("event stream HALTED on poison event — manual intervention required (D8)",
				observability.String("consumer", r.consumer),
				observability.String("stream", r.stream),
				observability.String("envelope_id", s.env.ID),
				observability.String("event_type", s.env.Type),
				observability.String("subject", s.env.Subject),
				observability.Int("attempts", r.maxAttempts),
				observability.Err(err))
			return applied, fmt.Errorf("eventbus: consumer %q stream %q halted on envelope %s: %w", r.consumer, r.stream, s.env.ID, ErrStreamHalted)
		}
		if err := r.advanceCursor(ctx, s.seq); err != nil {
			// The apply succeeded; only the cursor lagged. Redelivery on the next pass is a
			// no-op via the inbox, so this is transient — surface it and stop the batch.
			return applied, fmt.Errorf("eventbus: advance cursor %q/%q to %d: %w", r.consumer, r.stream, s.seq, err)
		}
		applied++
	}
	return applied, nil
}

// deliver applies one envelope, retrying with exponential backoff up to MaxAttempts. It
// returns nil on success, ctx.Err() if the context is cancelled during a backoff (graceful
// shutdown), or the last handler error once attempts are exhausted (poison).
func (r *Reader) deliver(ctx context.Context, env event.Envelope) error {
	var lastErr error
	for attempt := 1; attempt <= r.maxAttempts; attempt++ {
		if lastErr = r.handler.Handle(ctx, env); lastErr == nil {
			return nil
		}
		if attempt < r.maxAttempts {
			if err := sleepCtx(ctx, r.backoffFor(attempt)); err != nil {
				return err
			}
		}
	}
	return lastErr
}

// backoffFor doubles the base backoff each attempt, capped at maxBackoff (and guarding the
// shift against overflow).
func (r *Reader) backoffFor(attempt int) time.Duration {
	d := r.baseBackoff << (attempt - 1)
	if d <= 0 || d > maxBackoff {
		return maxBackoff
	}
	return d
}

func (r *Reader) loadCursor(ctx context.Context) (int64, error) {
	var last int64
	err := r.pool.QueryRow(ctx,
		`SELECT last_seq FROM stream_cursor WHERE consumer = $1 AND source_context = $2`,
		r.consumer, r.stream).Scan(&last)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil // first read of this stream: start from the beginning
	}
	return last, err
}

// readBatch reads the next envelopes after the cursor in seq order, gap-free (D7): the
// insert_xid8 < pg_snapshot_xmin(...) predicate excludes any row whose inserting transaction
// is not yet settled, so the loop never steps over a lower seq that will still become
// visible. Permanent seq gaps (a rolled-back or ON CONFLICT-skipped nextval) are simply
// absent and harmless — the watermark advances past them without waiting.
func (r *Reader) readBatch(ctx context.Context, cursor int64) ([]stamped, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT seq, envelope_id, source_context, subject, type, occurred_at, correlation_id, schema_ref, payload
		FROM event_log
		WHERE source_context = $1
		  AND seq > $2
		  AND insert_xid8 < pg_snapshot_xmin(pg_current_snapshot())
		ORDER BY seq
		LIMIT $3`, r.stream, cursor, r.batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []stamped
	for rows.Next() {
		var s stamped
		if err := rows.Scan(&s.seq, &s.env.ID, &s.env.SourceContext, &s.env.Subject, &s.env.Type,
			&s.env.OccurredAt, &s.env.CorrelationID, &s.env.SchemaRef, &s.env.Payload); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Reader) advanceCursor(ctx context.Context, seq int64) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO stream_cursor (consumer, source_context, last_seq) VALUES ($1, $2, $3)
		ON CONFLICT (consumer, source_context)
		DO UPDATE SET last_seq = EXCLUDED.last_seq, updated_at = now()`,
		r.consumer, r.stream, seq)
	return err
}

// sleepCtx sleeps for d, returning early with ctx.Err() if the context is cancelled. A
// non-positive d does not sleep.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

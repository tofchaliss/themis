package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// idempotencyConstraint is the UNIQUE constraint on `intake_receipts.idempotency_key`,
// named in the migration so this dispatch can key on it. The name is part of the
// contract, not an implementation detail: dispatching on the constraint NAME rather
// than on "some 23505 happened" is what keeps a future third constraint from being
// silently absorbed into this branch.
const idempotencyConstraint = "intake_receipts_idempotency_key_key"

// ErrIdempotencyKeyTaken reports that a receipt already exists for the asserted
// Idempotency-Key. It is a benign outcome, not a persistence failure: the caller
// reads the winner back and replays it (D12).
var ErrIdempotencyKeyTaken = errors.New("evidence: idempotency key already has a receipt")

// IntakeReceipt is one intake attempt as the database holds it (EDR-INTAKE-01 D9).
//
// It is a flat row rather than the domain's [domain.Receipt] on purpose. The domain
// type owns the forward-only LADDER — which transitions are legal — and that is a
// rule about a live attempt. A stored receipt is the RECORD of an attempt, read back
// long after the goroutine that made it is gone, and reconstructing a domain
// aggregate from a row would mean giving the ladder a back door wide enough to set
// any state. The adapter persists what happened; the domain decides what may happen.
type IntakeReceipt struct {
	IntakeID string
	// IdempotencyKey is empty when the client asserted none. Empty is stored as SQL
	// NULL so the UNIQUE constraint binds only the keys a client actually asserted.
	IdempotencyKey  string
	Status          domain.ReceiptStatus
	Reason          domain.RejectReason
	Detail          string
	EvidenceID      string
	ReleaseID       string
	DetectedKind    string
	DetectedFormat  string
	FindingsTotal   int
	FindingsSkipped int
	Components      int
	// ComponentsSkipped is what a converted SBOM left out for want of an identity
	// (EDR-INTAKE-01, 2026-10-26 P4); zero for anything filed as submitted.
	ComponentsSkipped int
	SourceDigest      string
	ConvertedBy       string
	// BuildID is what THIS attempt submitted (EDR-INTAKE-01 B5). A byte-identical
	// retry dedups and the evidence row keeps the FIRST upload's build id, so this
	// value and the filed document's can differ: a receipt records an attempt, the
	// evidence row records what was filed.
	BuildID   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SaveIntakeReceipt writes a receipt, inserting it the first time and advancing it
// on every later write. `updated_at` is set here rather than by a trigger, so the
// one place that writes receipts is the one place that stamps them.
//
// An insert that collides with an existing Idempotency-Key is reported as
// [ErrIdempotencyKeyTaken] and NOT as a failure: a retry is the thing the key exists
// to make safe, so the caller reads the winner back and replays its receipt.
func (s *Store) SaveIntakeReceipt(ctx context.Context, r IntakeReceipt) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO intake_receipts (intake_id, idempotency_key, status, reason, detail,
			evidence_id, release_id, detected_kind, detected_format, findings_total,
			findings_skipped, components, source_digest, converted_by, build_id,
			components_skipped, created_at, updated_at)
		VALUES ($1, NULLIF($2,''), $3,$4,$5, NULLIF($6,''), $7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)
		ON CONFLICT (intake_id) DO UPDATE SET
			status = EXCLUDED.status,
			reason = EXCLUDED.reason,
			detail = EXCLUDED.detail,
			evidence_id = EXCLUDED.evidence_id,
			release_id = EXCLUDED.release_id,
			detected_kind = EXCLUDED.detected_kind,
			detected_format = EXCLUDED.detected_format,
			findings_total = EXCLUDED.findings_total,
			findings_skipped = EXCLUDED.findings_skipped,
			components = EXCLUDED.components,
			components_skipped = EXCLUDED.components_skipped,
			source_digest = EXCLUDED.source_digest,
			converted_by = EXCLUDED.converted_by,
			build_id = EXCLUDED.build_id,
			updated_at = EXCLUDED.updated_at
	`, r.IntakeID, r.IdempotencyKey, string(r.Status), string(r.Reason), r.Detail,
		r.EvidenceID, r.ReleaseID, r.DetectedKind, r.DetectedFormat, r.FindingsTotal,
		r.FindingsSkipped, r.Components, r.SourceDigest, r.ConvertedBy, r.BuildID,
		r.ComponentsSkipped, now)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.ConstraintName == idempotencyConstraint {
			return ErrIdempotencyKeyTaken
		}
		return fmt.Errorf("evidence: intake receipt save: %w", err)
	}
	return nil
}

// LoadIntakeReceipt reads one receipt by its intake id, returning [ErrNotFound] when
// there is none.
func (s *Store) LoadIntakeReceipt(ctx context.Context, intakeID string) (IntakeReceipt, error) {
	return s.scanReceipt(ctx, `WHERE intake_id = $1`, intakeID)
}

// FindIntakeReceiptByIdempotencyKey reads the receipt an asserted key already owns
// (D12). An empty key matches nothing: a keyless submission asserts no identity, and
// returning "the receipt with no key" would collapse every keyless attempt into one.
func (s *Store) FindIntakeReceiptByIdempotencyKey(ctx context.Context, key string) (IntakeReceipt, error) {
	if key == "" {
		return IntakeReceipt{}, ErrNotFound
	}
	return s.scanReceipt(ctx, `WHERE idempotency_key = $1`, key)
}

func (s *Store) scanReceipt(ctx context.Context, where string, arg string) (IntakeReceipt, error) {
	var (
		r               IntakeReceipt
		key, evidenceID *string
		status, reason  string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT intake_id, idempotency_key, status, reason, detail, evidence_id, release_id,
			detected_kind, detected_format, findings_total, findings_skipped, components,
			source_digest, converted_by, build_id, components_skipped, created_at, updated_at
		FROM intake_receipts `+where, arg).
		Scan(&r.IntakeID, &key, &status, &reason, &r.Detail, &evidenceID, &r.ReleaseID,
			&r.DetectedKind, &r.DetectedFormat, &r.FindingsTotal, &r.FindingsSkipped, &r.Components,
			&r.SourceDigest, &r.ConvertedBy, &r.BuildID, &r.ComponentsSkipped, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IntakeReceipt{}, ErrNotFound
	}
	if err != nil {
		return IntakeReceipt{}, fmt.Errorf("evidence: intake receipt load: %w", err)
	}
	r.Status, r.Reason = domain.ReceiptStatus(status), domain.RejectReason(reason)
	if key != nil {
		r.IdempotencyKey = *key
	}
	if evidenceID != nil {
		r.EvidenceID = *evidenceID
	}
	return r, nil
}

// PurgeExpiredReceipts deletes the receipts older than the cutoff and reports how
// many went. Receipts are operational records of an attempt, not evidence, so this
// is an ordinary retention sweep and not a hole in CON-0007's immutability: no
// evidence document is reachable from here.
func (s *Store) PurgeExpiredReceipts(ctx context.Context, olderThan time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM intake_receipts WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("evidence: intake receipt purge: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// FailStaleNonTerminalReceipts closes out the receipts a restart interrupted, and
// reports how many.
//
// A receipt advances in the process that is doing the work, so a process that dies
// mid-intake leaves its receipt stuck at `accepted` forever — and a client polling
// `status_url` would wait on a goroutine that no longer exists. The honest outcome is
// `failed` (a statement about Themis, not about the document, so it carries no
// reason) with a detail that says what to do. It is applied at startup, to receipts
// older than the inline budget: anything younger could still be in flight.
func (s *Store) FailStaleNonTerminalReceipts(ctx context.Context, olderThan time.Time, detail string) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE intake_receipts
		SET status = $1, detail = $2, updated_at = now()
		WHERE created_at < $3
		  AND status NOT IN ($4, $5, $6)
	`, string(domain.ReceiptFailed), detail, olderThan,
		string(domain.ReceiptFiled), string(domain.ReceiptRejected), string(domain.ReceiptFailed))
	if err != nil {
		return 0, fmt.Errorf("evidence: intake receipt recovery: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// HasInventory answers D6's precondition: does an Evidence document of `kind=sbom`
// exist whose subject release is this one? It satisfies the app's InventoryReader
// port.
//
// A single boolean is the whole answer, and that is verified rather than assumed:
// `Register` parses inline and `Save` writes the row and its canonical inventory in
// ONE transaction, and the domain refuses an SBOM that parsed to zero components. So
// "uploaded but not parsed" and "parsed but empty" do not exist here, and there is no
// window for an `inventory_not_ready` state to describe. The check is release-scoped
// by construction, so another release's inventory can never satisfy it.
func (s *Store) HasInventory(ctx context.Context, releaseID string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM evidence WHERE subject_release_id = $1 AND kind = $2)
	`, releaseID, string(domain.KindSBOM)).Scan(&ok); err != nil {
		return false, fmt.Errorf("evidence: inventory presence: %w", err)
	}
	return ok, nil
}

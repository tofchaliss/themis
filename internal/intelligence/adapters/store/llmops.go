package store

// The Δ4a LLMOps store (EDR-INTELLIGENCE-01 § Δ4a): the invocation log, the human-promoted
// golden set, eval reports, and the prompt-version stamp. It lives beside the Operational
// Semantic Index in the same `intelligence` DB and store package (D-Δ4a-1) but is a distinct
// concern — attribution + a replay harness, never enterprise truth. golden_entries and
// eval_reports are the node's first NON-DISPOSABLE state; the invocation log is capped.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// LoggedInvocation is one captured reactive invocation (redacted on write, D-Δ4a-5). ContextJSON
// and OutputJSON are opaque JSON the harness froze — the store neither interprets nor re-derives
// them.
type LoggedInvocation struct {
	CorrelationID string
	Capability    string
	PromptVersion string
	Model         string
	Tier          string
	ContextJSON   []byte
	OutputJSON    []byte // nil for a non-LLM decision
	Reason        string
	DeclineClass  string
	Tokens        int
}

// AppendInvocation records one invocation. Best-effort by contract (the caller ignores the
// error — a capture failure must never fail the invocation, D-Δ4a-5); idempotent on
// correlation_id so a retry for the same correlation id is a no-op rather than a duplicate.
func (s *Store) AppendInvocation(ctx context.Context, in LoggedInvocation) error {
	var out any
	if in.OutputJSON != nil {
		out = in.OutputJSON
	}
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO invocation_log
		  (correlation_id, capability, prompt_version, model, tier, context_json, output_json, reason, decline_class, tokens)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (correlation_id) DO NOTHING`,
		in.CorrelationID, in.Capability, in.PromptVersion, in.Model, in.Tier,
		in.ContextJSON, out, in.Reason, in.DeclineClass, in.Tokens)
	return err
}

// GetInvocation returns one logged invocation by correlation id (the promote path reads it).
func (s *Store) GetInvocation(ctx context.Context, correlationID string) (LoggedInvocation, bool, error) {
	var in LoggedInvocation
	var output []byte
	err := s.exec(ctx).QueryRow(ctx, `
		SELECT correlation_id, capability, prompt_version, model, tier, context_json, output_json, reason, decline_class, tokens
		FROM invocation_log WHERE correlation_id = $1`, correlationID).
		Scan(&in.CorrelationID, &in.Capability, &in.PromptVersion, &in.Model, &in.Tier,
			&in.ContextJSON, &output, &in.Reason, &in.DeclineClass, &in.Tokens)
	if err == pgx.ErrNoRows {
		return LoggedInvocation{}, false, nil
	}
	if err != nil {
		return LoggedInvocation{}, false, err
	}
	in.OutputJSON = output
	return in, true, nil
}

// PruneInvocations deletes log rows older than the cutoff, returning how many were removed —
// the retention sweep (THEMIS_INTELLIGENCE_LOG_RETENTION). The log is disposable; the golden
// set promoted from it is not, and is untouched here.
func (s *Store) PruneInvocations(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.exec(ctx).Exec(ctx, `DELETE FROM invocation_log WHERE occurred_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GoldenEntry is one durable, human-promoted regression case (D-Δ4a-2/5).
type GoldenEntry struct {
	ID                  string
	Label               string
	Capability          string
	SourceCorrelationID string
	ContextJSON         []byte
	ExpectedJSON        []byte
}

// PromoteGolden inserts a durable golden entry.
func (s *Store) PromoteGolden(ctx context.Context, g GoldenEntry) error {
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO golden_entries
		  (id, label, capability, source_correlation_id, context_json, expected_json)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		g.ID, g.Label, g.Capability, g.SourceCorrelationID, g.ContextJSON, g.ExpectedJSON)
	return err
}

// ListGolden returns every golden entry — the eval's replay set.
func (s *Store) ListGolden(ctx context.Context) ([]GoldenEntry, error) {
	rows, err := s.exec(ctx).Query(ctx, `
		SELECT id, label, capability, source_correlation_id, context_json, expected_json
		FROM golden_entries ORDER BY promoted_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GoldenEntry
	for rows.Next() {
		var g GoldenEntry
		if err := rows.Scan(&g.ID, &g.Label, &g.Capability, &g.SourceCorrelationID, &g.ContextJSON, &g.ExpectedJSON); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// WriteEvalReport records one eval run. resultsJSON is the harness's per-entry + aggregate blob.
func (s *Store) WriteEvalReport(ctx context.Context, id, fingerprint string, entries, passed int, resultsJSON []byte) error {
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO eval_reports (id, fingerprint, entries, passed, results_json)
		VALUES ($1,$2,$3,$4,$5)`, id, fingerprint, entries, passed, resultsJSON)
	return err
}

// UpsertPromptVersion records that a capability's template currently hashes to content_hash
// (D-Δ4a-3). Idempotent: re-seeing the same hash keeps the original first_seen.
func (s *Store) UpsertPromptVersion(ctx context.Context, capability, contentHash string) error {
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO prompt_versions (capability, content_hash)
		VALUES ($1,$2) ON CONFLICT (capability, content_hash) DO NOTHING`, capability, contentHash)
	return err
}

// HasProposed reports whether the autonomous analyst already pushed this (finding, precedent)
// pair (Δ4b D-Δ4b-5) — the idempotence check that keeps the plane quiet-by-default. A
// precedent_key that encodes the precedent's version means a CHANGED precedent reads false and
// re-proposes, which is correct, not spam.
func (s *Store) HasProposed(ctx context.Context, findingID, precedentKey string) (bool, error) {
	var exists bool
	err := s.exec(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM autonomous_proposals WHERE finding_id = $1 AND precedent_key = $2)`,
		findingID, precedentKey).Scan(&exists)
	return exists, err
}

// RecordProposed records that the analyst pushed this pair. Idempotent on the pair.
func (s *Store) RecordProposed(ctx context.Context, findingID, precedentKey string) error {
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO autonomous_proposals (finding_id, precedent_key)
		VALUES ($1,$2) ON CONFLICT (finding_id, precedent_key) DO NOTHING`, findingID, precedentKey)
	return err
}

package store

import (
	"context"
	"errors"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Source ratings store (EDR-SCORING-01 S2). Append-only: every statement here is an INSERT or a
// SELECT. Implements app.RatingStore.

var _ app.RatingStore = (*Store)(nil)

// RecordRevision records one revision in its own transaction, under a per-CVE advisory lock:
// groupings are per CVE, so two revisions of the same CVE never interleave. It does not join an
// ambient inbox transaction: source truth is independent of the fold that carried it, and an
// unchanged revision re-recorded after a rollback is only a seen event (R-S7).
func (s *Store) RecordRevision(ctx context.Context, key app.RatingKey, build func(app.RatingPrior) (app.RatingWrite, error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('source_ratings:' || $1))`, key.CVE); err != nil {
		return err
	}
	prior, err := loadRatingPrior(ctx, tx, key)
	if err != nil {
		return err
	}
	w, err := build(prior)
	if err != nil {
		return err
	}
	if err := writeRatings(ctx, tx, w); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func loadRatingPrior(ctx context.Context, tx pgx.Tx, key app.RatingKey) (app.RatingPrior, error) {
	var prior app.RatingPrior
	err := tx.QueryRow(ctx, `SELECT id, fingerprint FROM rating_observations WHERE source = $1 AND document_ref = $2
		ORDER BY seq DESC LIMIT 1`, key.Source, key.DocumentRef).
		Scan(&prior.LatestObservationID, &prior.LatestFingerprint)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return prior, err
	}
	if prior.LatestObservationID != "" && prior.LatestFingerprint == key.Fingerprint {
		return prior, nil // unchanged revision: nothing else is needed
	}
	all, terminal, err := ratingsOfCVE(ctx, tx, key.CVE)
	if err != nil {
		return prior, err
	}
	for _, r := range all {
		status := domain.RatingActive
		if terminal[r.ID] {
			status = domain.RatingStatusWithdrawn // any terminal kind: not active
		}
		prior.Members = append(prior.Members, domain.MemberOf(r, status))
		if !terminal[r.ID] && r.Source == key.Source && r.DocumentRef == key.DocumentRef {
			prior.Active = append(prior.Active, r)
		}
	}
	prior.Groupings, err = latestGroupings(ctx, tx, key.CVE)
	return prior, err
}

const ratingColumns = `r.id, r.observation_id, r.cve, r.source, r.document_ref, r.feed, r.assessor, r.publisher,
	r.nvd_type, r.cvss_version, r.vector, r.stated_score::float8, r.severity_word, r.asserted_context,
	r.inherited_context, r.recorded_at`

// ratingsOfCVE returns every publication of a CVE in recording order, and which are terminal.
func ratingsOfCVE(ctx context.Context, q rowQuerier, cve string) ([]domain.SourceRating, map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT `+ratingColumns+`, e.rating_id IS NOT NULL
		FROM source_ratings r LEFT JOIN source_rating_events e ON e.rating_id = r.id
		WHERE r.cve = $1 ORDER BY r.seq`, cve)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []domain.SourceRating
	terminal := map[string]bool{}
	for rows.Next() {
		var (
			r      domain.SourceRating
			stated *float64
			term   bool
		)
		if err := rows.Scan(&r.ID, &r.ObservationID, &r.CVE, &r.Source, &r.DocumentRef, &r.Feed, &r.Assessor, &r.Publisher,
			&r.NVDType, &r.Version, &r.Vector, &stated, &r.SeverityWord, &r.AssertedContext, &r.InheritedContext,
			&r.RecordedAt, &term); err != nil {
			return nil, nil, err
		}
		if stated != nil {
			r.StatedScore, r.HasStatedScore = *stated, true
		}
		r.RecordedAt = r.RecordedAt.UTC()
		terminal[r.ID] = term
		out = append(out, r)
	}
	return out, terminal, rows.Err()
}

func latestGroupings(ctx context.Context, q rowQuerier, cve string) (map[string]domain.Grouping, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT ON (set_key) set_key, grouping FROM assessment_links
		WHERE cve = $1 ORDER BY set_key, seq DESC`, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]domain.Grouping{}
	for rows.Next() {
		var (
			k   string
			raw []byte
			g   domain.Grouping
		)
		if err := rows.Scan(&k, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		out[k] = g
	}
	return out, rows.Err()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nullScore(v float64, ok bool) *float64 {
	if !ok {
		return nil
	}
	return &v
}

func writeRatings(ctx context.Context, tx pgx.Tx, w app.RatingWrite) error {
	if o := w.Observation; o != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO rating_observations (id, cve, source, feed, document_ref, revision,
			updated_original, updated_at, updated_interpretation, fingerprint, complete, applicability, severity_word,
			first_observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			o.ID, o.CVE, o.Source, o.Feed, o.DocumentRef, o.Revision, o.UpdatedAt.Original, nullTime(o.UpdatedAt.Instant),
			string(o.UpdatedAt.Interpretation), o.Fingerprint, o.Complete, o.Applicability, o.SeverityWord,
			o.FirstObservedAt); err != nil {
			return err
		}
	}
	sv := w.Seen
	if _, err := tx.Exec(ctx, `INSERT INTO rating_observation_seen (observation_id, source, document_ref, fetched_at,
		outcome, endpoint, http_status, etag, last_modified) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		sv.ObservationID, sv.Source, sv.DocumentRef, sv.FetchedAt, string(sv.Outcome), sv.Fetch.Endpoint,
		sv.Fetch.HTTPStatus, sv.Fetch.ETag, sv.Fetch.LastModified); err != nil {
		return err
	}
	for _, r := range w.Ratings {
		if _, err := tx.Exec(ctx, `INSERT INTO source_ratings (id, observation_id, cve, source, document_ref, feed,
			assessor, publisher, nvd_type, cvss_version, vector, stated_score, severity_word, asserted_context,
			inherited_context, recorded_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			r.ID, r.ObservationID, r.CVE, r.Source, r.DocumentRef, r.Feed, r.Assessor, r.Publisher, r.NVDType,
			r.Version, r.Vector, nullScore(r.StatedScore, r.HasStatedScore), r.SeverityWord, r.AssertedContext,
			r.InheritedContext, r.RecordedAt); err != nil {
			return err
		}
	}
	for _, e := range w.Events {
		var replaced *string
		if e.ReplacedBy != "" {
			replaced = &e.ReplacedBy
		}
		// ON CONFLICT: a publication has at most one terminal event; a second never replaces it.
		if _, err := tx.Exec(ctx, `INSERT INTO source_rating_events (rating_id, kind, caused_by, replaced_by,
			source_time_original, source_time, source_time_interpretation, learned_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (rating_id) DO NOTHING`,
			e.RatingID, string(e.Kind), e.CausedBy, replaced, e.SourceTime.Original, nullTime(e.SourceTime.Instant),
			string(e.SourceTime.Interpretation), e.LearnedAt); err != nil {
			return err
		}
	}
	for _, v := range w.Validations {
		valid := v.Result == domain.ValidationValid
		if _, err := tx.Exec(ctx, `INSERT INTO rating_validations (rating_id, calculator_version, spec_version, result,
			reason, base_score, temporal_score, stated_comparison, validated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (rating_id, calculator_version) DO NOTHING`,
			v.RatingID, v.CalculatorVersion, v.SpecVersion, string(v.Result), v.Reason, nullScore(v.Base, valid),
			nullScore(v.Temporal, v.HasTemporal), string(v.Stated), v.ValidatedAt); err != nil {
			return err
		}
	}
	for _, l := range w.Links {
		g, err := json.Marshal(l.Grouping)
		if err != nil {
			return err
		}
		changes := l.Changes
		if changes == nil {
			changes = []domain.LinkChange{}
		}
		c, err := json.Marshal(changes)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_links (cve, set_key, grouping, changes, policy_version, cause, at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, l.CVE, l.SetKey, string(g), string(c), l.PolicyVersion, l.Cause, l.At); err != nil {
			return err
		}
	}
	return nil
}

// RatingsForCVE reads the stored source truth of one CVE.
func (s *Store) RatingsForCVE(ctx context.Context, cve string) (app.RatingsSnapshot, error) {
	snap := app.RatingsSnapshot{Events: map[string]domain.RatingEvent{}, Validations: map[string]domain.RatingValidation{}}
	rows, err := s.pool.Query(ctx, `SELECT id, cve, source, feed, document_ref, revision, updated_original, updated_at,
		updated_interpretation, fingerprint, complete, applicability, severity_word, first_observed_at
		FROM rating_observations WHERE cve = $1 ORDER BY seq`, cve)
	if err != nil {
		return snap, err
	}
	for rows.Next() {
		var (
			o       domain.SourceObservation
			updated *time.Time
			interp  string
		)
		if err := rows.Scan(&o.ID, &o.CVE, &o.Source, &o.Feed, &o.DocumentRef, &o.Revision, &o.UpdatedAt.Original,
			&updated, &interp, &o.Fingerprint, &o.Complete, &o.Applicability, &o.SeverityWord, &o.FirstObservedAt); err != nil {
			rows.Close()
			return snap, err
		}
		if updated != nil {
			o.UpdatedAt.Instant = updated.UTC()
		}
		o.UpdatedAt.Interpretation = domain.SourceTimeInterpretation(interp)
		o.FirstObservedAt = o.FirstObservedAt.UTC()
		snap.Observations = append(snap.Observations, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snap, err
	}
	if snap.Ratings, _, err = ratingsOfCVE(ctx, s.pool, cve); err != nil {
		return snap, err
	}
	if err := s.readRatingEvents(ctx, cve, snap.Events); err != nil {
		return snap, err
	}
	if err := s.readRatingValidations(ctx, cve, snap.Validations); err != nil {
		return snap, err
	}
	snap.Groupings, err = latestGroupings(ctx, s.pool, cve)
	return snap, err
}

func (s *Store) readRatingEvents(ctx context.Context, cve string, out map[string]domain.RatingEvent) error {
	rows, err := s.pool.Query(ctx, `SELECT e.rating_id, e.kind, e.caused_by, COALESCE(e.replaced_by, ''),
		e.source_time_original, e.source_time, e.source_time_interpretation, e.learned_at
		FROM source_rating_events e JOIN source_ratings r ON r.id = e.rating_id WHERE r.cve = $1`, cve)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			e            domain.RatingEvent
			kind, interp string
			at           *time.Time
		)
		if err := rows.Scan(&e.RatingID, &kind, &e.CausedBy, &e.ReplacedBy, &e.SourceTime.Original, &at, &interp, &e.LearnedAt); err != nil {
			return err
		}
		e.Kind, e.SourceTime.Interpretation, e.LearnedAt = domain.RatingEventKind(kind), domain.SourceTimeInterpretation(interp), e.LearnedAt.UTC()
		if at != nil {
			e.SourceTime.Instant = at.UTC()
		}
		out[e.RatingID] = e
	}
	return rows.Err()
}

// readRatingValidations keeps, per publication, the validation of the current calculator.
func (s *Store) readRatingValidations(ctx context.Context, cve string, out map[string]domain.RatingValidation) error {
	rows, err := s.pool.Query(ctx, `SELECT v.rating_id, v.calculator_version, v.spec_version, v.result, v.reason,
		v.base_score::float8, v.temporal_score::float8, v.stated_comparison, v.validated_at
		FROM rating_validations v JOIN source_ratings r ON r.id = v.rating_id
		WHERE r.cve = $1 AND v.calculator_version = $2`, cve, domain.CalculatorVersion)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			v              domain.RatingValidation
			result, stated string
			base, temporal *float64
		)
		if err := rows.Scan(&v.RatingID, &v.CalculatorVersion, &v.SpecVersion, &result, &v.Reason, &base, &temporal, &stated, &v.ValidatedAt); err != nil {
			return err
		}
		v.Result, v.Stated, v.ValidatedAt = domain.ValidationResult(result), domain.StatedComparison(stated), v.ValidatedAt.UTC()
		if base != nil {
			v.Base = *base
		}
		if temporal != nil {
			v.Temporal, v.HasTemporal = *temporal, true
		}
		out[v.RatingID] = v
	}
	return rows.Err()
}

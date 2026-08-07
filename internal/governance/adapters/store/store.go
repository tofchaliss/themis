// Package store is the Governance context's Postgres persistence adapter: it owns the
// findings / finding_components / finding_proposals / finding_positions /
// governance_outbox tables and implements the application Repository and ProjectionReader
// ports as an aggregate-root store with optimistic concurrency and a transactional outbox
// (D9). jsonb columns receive string(...) because pgx encodes []byte as bytea.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// ErrNotFound is returned by GetByID when no Finding exists.
var ErrNotFound = errors.New("governance: finding not found")

// sourceContext stamps every outbox row's source_context (M5 EB-02). correlation_id is
// the Finding id — the workflow anchor for its lifecycle.
const sourceContext = "governance"

// schemaRefByEventType pins each published Governance event type to its frozen
// integration-contract v1 schema (M5 EB-03 / D9 / BCK-0046). This producer-owned mapping
// stamps the outbox row's schema_ref; the checked-in schemas under schemas/ and the
// contract test guard the wire shape so a domain refactor fails the build rather than
// silently breaking a consumer.
var schemaRefByEventType = map[string]string{
	app.EventFindingOpened:       "governance.finding_opened.v1",
	app.EventFindingResolved:     "governance.finding_resolved.v1",
	app.EventFindingReopened:     "governance.finding_reopened.v1",
	app.EventFindingArchived:     "governance.finding_archived.v1",
	app.EventProposalRaised:      "governance.proposal_raised.v1",
	app.EventProposalAccepted:    "governance.proposal_accepted.v1",
	app.EventProposalRejected:    "governance.proposal_rejected.v1",
	app.EventPositionEstablished: "governance.position_established.v1",
	app.EventPositionRevised:     "governance.position_revised.v1",
	app.EventDispositionStale:    "governance.disposition_stale.v1",
}

// schemaRefFor returns the pinned v1 schema_ref for a published event type. An unmapped
// type falls back to the raw type so the outbox write still succeeds; the contract test
// forbids that gap.
func schemaRefFor(eventType string) string {
	if ref, ok := schemaRefByEventType[eventType]; ok {
		return ref
	}
	return eventType
}

// Store is the Governance Finding aggregate repository.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// GetByKey loads the Finding for a (Release, Faultline) business key; found=false if none.
func (s *Store) GetByKey(ctx context.Context, releaseID, faultlineID string) (domain.Finding, bool, error) {
	f, err := s.load(ctx, "release_id = $1 AND faultline_id = $2", releaseID, faultlineID)
	if errors.Is(err, ErrNotFound) {
		return domain.Finding{}, false, nil
	}
	if err != nil {
		return domain.Finding{}, false, err
	}
	return f, true, nil
}

// GetByID loads the Finding by its own identity (with proposals + position history).
func (s *Store) GetByID(ctx context.Context, id domain.FindingID) (domain.Finding, error) {
	return s.load(ctx, "id = $1", string(id))
}

func (s *Store) load(ctx context.Context, where string, args ...any) (domain.Finding, error) {
	var (
		id, releaseID, faultlineID, cve, stage string
		version                                int
	)
	var sig domain.ExploitSignals
	row := s.querier(ctx).QueryRow(ctx,
		"SELECT id, release_id, faultline_id, cve, stage, version, signal_kev, signal_exploit_public, signal_epss "+
			"FROM findings WHERE "+where, args...)
	if err := row.Scan(&id, &releaseID, &faultlineID, &cve, &stage, &version,
		&sig.KEV, &sig.ExploitPublic, &sig.EPSS); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Finding{}, ErrNotFound
		}
		return domain.Finding{}, err
	}

	components, err := s.loadComponents(ctx, id)
	if err != nil {
		return domain.Finding{}, err
	}
	proposals, err := s.loadProposals(ctx, id)
	if err != nil {
		return domain.Finding{}, err
	}
	positions, err := s.loadPositions(ctx, id)
	if err != nil {
		return domain.Finding{}, err
	}

	return domain.ReconstituteFinding(domain.FindingID(id), releaseID, faultlineID, cve,
		components, domain.Stage(stage), proposals, positions, version, sig), nil
}

func (s *Store) loadComponents(ctx context.Context, id string) ([]domain.MatchedComponent, error) {
	rows, err := s.querier(ctx).Query(ctx,
		`SELECT purl, name, version, ecosystem, source FROM finding_components WHERE finding_id = $1 ORDER BY purl`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.MatchedComponent
	for rows.Next() {
		var c domain.MatchedComponent
		if err := rows.Scan(&c.PURL, &c.Name, &c.Version, &c.Ecosystem, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) loadProposals(ctx context.Context, id string) ([]domain.GovernanceProposal, error) {
	rows, err := s.querier(ctx).Query(ctx, `
		SELECT proposal_id, proposer_kind, proposer_id, stance, rationale, raised_at,
		       status, decided_kind, decided_id, decided_at, evidence_trust
		FROM finding_proposals WHERE finding_id = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.GovernanceProposal
	for rows.Next() {
		var (
			pid, proposerKind, proposerID, stance, rationale, status, decidedKind, decidedID string
			evidenceTrust                                                                    string
			raisedAt                                                                         time.Time
			decidedAt                                                                        *time.Time
		)
		if err := rows.Scan(&pid, &proposerKind, &proposerID, &stance, &rationale, &raisedAt,
			&status, &decidedKind, &decidedID, &decidedAt, &evidenceTrust); err != nil {
			return nil, err
		}
		var dat time.Time
		if decidedAt != nil {
			dat = *decidedAt
		}
		out = append(out, domain.ReconstituteProposal(
			domain.ProposalID(pid),
			domain.Actor{Kind: domain.ActorKind(proposerKind), ID: proposerID},
			domain.Stance(stance), rationale, raisedAt,
			domain.ProposalStatus(status),
			decidedActor(decidedKind, decidedID), dat,
			value.TrustClass(evidenceTrust),
		))
	}
	return out, rows.Err()
}

func (s *Store) loadPositions(ctx context.Context, id string) ([]domain.Position, error) {
	rows, err := s.querier(ctx).Query(ctx, `
		SELECT version, stance, rationale, actor_kind, actor_id, accepted_proposal_id, faultline_ref, established_at,
		       decided_kev, decided_exploit_public, decided_epss
		FROM finding_positions WHERE finding_id = $1 ORDER BY version`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Position
	for rows.Next() {
		var (
			version                                                   int
			stance, rationale, actorKind, actorID, acceptedPID, flRef string
			establishedAt                                             time.Time
			sig                                                       domain.ExploitSignals
		)
		if err := rows.Scan(&version, &stance, &rationale, &actorKind, &actorID, &acceptedPID, &flRef, &establishedAt,
			&sig.KEV, &sig.ExploitPublic, &sig.EPSS); err != nil {
			return nil, err
		}
		out = append(out, domain.ReconstitutePosition(version, domain.Stance(stance), rationale,
			domain.Actor{Kind: domain.ActorKind(actorKind), ID: actorID},
			domain.PositionInputs{
				AcceptedProposalID: domain.ProposalID(acceptedPID), FaultlineRef: flRef, DecidedWith: sig,
			},
			establishedAt))
	}
	return out, rows.Err()
}

// decidedActor rebuilds the deciding actor, or the zero Actor when the proposal is
// still open (no decision recorded).
func decidedActor(kind, id string) domain.Actor {
	if kind == "" && id == "" {
		return domain.Actor{}
	}
	return domain.Actor{Kind: domain.ActorKind(kind), ID: id}
}

// Save persists the aggregate + outbox notes atomically (D9). A new Finding is inserted; an
// existing Finding is updated under optimistic concurrency (WHERE version=prevVersion),
// returning app.ErrConcurrent on a mismatch or a duplicate (Release, Faultline) insert.
// Components/proposals/positions are upserted idempotently; only a proposal's decision
// columns are ever updated (immutable columns never change).
func (s *Store) Save(ctx context.Context, f domain.Finding, created bool, prevVersion int, notes []app.OutboxNote) error {
	// Join the inbox unit of work when one rides the context (EB-06), so the aggregate
	// write commits atomically with the envelope claim; otherwise own a fresh transaction.
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	now := time.Now().UTC()
	curStance, curVersion := materializedPosition(f)

	if created {
		if _, err := tx.Exec(ctx, `
			INSERT INTO findings (id, release_id, faultline_id, cve, stage, version, current_stance, current_position_version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
			string(f.ID()), f.ReleaseID(), f.FaultlineID(), f.CVE(), string(f.Stage()), f.Version(), curStance, curVersion, now); err != nil {
			// A concurrent writer created this (Release, Faultline) first — converge by retry.
			if isUniqueViolation(err) {
				return app.ErrConcurrent
			}
			return err
		}
	} else {
		ct, err := tx.Exec(ctx, `
			UPDATE findings SET stage=$1, version=$2, current_stance=$3, current_position_version=$4, updated_at=$5
			WHERE id=$6 AND version=$7`,
			string(f.Stage()), f.Version(), curStance, curVersion, now, string(f.ID()), prevVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return app.ErrConcurrent
		}
	}

	if err := s.saveComponents(ctx, tx, f); err != nil {
		return err
	}
	if err := s.saveProposals(ctx, tx, f); err != nil {
		return err
	}
	if err := s.savePositions(ctx, tx, f); err != nil {
		return err
	}
	if err := s.saveNotes(ctx, tx, f, notes); err != nil {
		return err
	}

	if own {
		return tx.Commit(ctx)
	}
	return nil // the inbox unit of work owns the commit
}

func (s *Store) saveComponents(ctx context.Context, tx pgx.Tx, f domain.Finding) error {
	for _, c := range f.Components() {
		if _, err := tx.Exec(ctx, `
			INSERT INTO finding_components (finding_id, purl, name, version, ecosystem, source)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (finding_id, purl) DO UPDATE SET source = EXCLUDED.source
			WHERE finding_components.source = '' AND EXCLUDED.source <> ''`,
			string(f.ID()), c.PURL, c.Name, c.Version, c.Ecosystem, c.Source); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) saveProposals(ctx context.Context, tx pgx.Tx, f domain.Finding) error {
	for seq, p := range f.Proposals() {
		var decidedAt *time.Time
		if !p.DecidedAt().IsZero() {
			t := p.DecidedAt()
			decidedAt = &t
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO finding_proposals
			  (finding_id, proposal_id, seq, proposer_kind, proposer_id, stance, rationale, raised_at, status, decided_kind, decided_id, decided_at, evidence_trust)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (finding_id, proposal_id)
			DO UPDATE SET status=EXCLUDED.status, decided_kind=EXCLUDED.decided_kind,
			              decided_id=EXCLUDED.decided_id, decided_at=EXCLUDED.decided_at`,
			string(f.ID()), string(p.ID()), seq, string(p.Proposer().Kind), p.Proposer().ID,
			string(p.Stance()), p.Rationale(), p.RaisedAt(), string(p.Status()),
			string(p.DecidedBy().Kind), p.DecidedBy().ID, decidedAt, string(p.EvidenceTrust())); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) savePositions(ctx context.Context, tx pgx.Tx, f domain.Finding) error {
	for _, pos := range f.Positions() {
		if _, err := tx.Exec(ctx, `
			INSERT INTO finding_positions
			  (finding_id, version, stance, rationale, actor_kind, actor_id, accepted_proposal_id, faultline_ref, established_at,
			   decided_kev, decided_exploit_public, decided_epss)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (finding_id, version) DO NOTHING`,
			string(f.ID()), pos.Version(), string(pos.Stance()), pos.Rationale(),
			string(pos.Actor().Kind), pos.Actor().ID,
			string(pos.Inputs().AcceptedProposalID), pos.Inputs().FaultlineRef, pos.EstablishedAt(),
			pos.Inputs().DecidedWith.KEV, pos.Inputs().DecidedWith.ExploitPublic, pos.Inputs().DecidedWith.EPSS); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) saveNotes(ctx context.Context, tx pgx.Tx, f domain.Finding, notes []app.OutboxNote) error {
	for _, n := range notes {
		payload, err := json.Marshal(n.Event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO governance_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			uuid.NewString(), sourceContext, string(f.ID()), n.EventType, schemaRefFor(n.EventType), string(f.ID()), string(payload), n.OccurredAt); err != nil {
			return err
		}
	}
	return nil
}

// materializedPosition returns the current-position stance + version to denormalize onto
// the Finding row (NULL when the Finding has no Position yet), so the read-side rollups
// (D10) never scan the position history.
func materializedPosition(f domain.Finding) (*string, *int) {
	pos, ok := f.CurrentPosition()
	if !ok {
		return nil, nil
	}
	stance := string(pos.Stance())
	version := pos.Version()
	return &stance, &version
}

// FindingsByFaultline lists the ids of every Finding referencing a Faultline — the
// FaultlineEnriched fan-out (D6).
func (s *Store) FindingsByFaultline(ctx context.Context, faultlineID string) ([]domain.FindingID, error) {
	rows, err := s.querier(ctx).Query(ctx, `SELECT id FROM findings WHERE faultline_id = $1 ORDER BY id`, faultlineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.FindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, domain.FindingID(id))
	}
	return out, rows.Err()
}

// ReleasePosture returns the Release security-posture rollup — every Finding + its current
// stance for a Release (D10), served from the materialized current-position columns.
func (s *Store) ReleasePosture(ctx context.Context, releaseID string) ([]app.PostureEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT f.id, f.faultline_id, f.cve, f.stage, f.current_stance, f.current_position_version,
		       f.base_score, COALESCE(pr.evidence_trust, '')
		FROM findings f
		-- The reservation (EDR-TRUST-01 T12) is DERIVED, never stored: join the current
		-- Position to the proposal it accepted and read that proposal's evidence class. A
		-- stored flag could disagree with the evidence it describes; a join cannot.
		LEFT JOIN finding_positions po
		       ON po.finding_id = f.id AND po.version = f.current_position_version
		LEFT JOIN finding_proposals pr
		       ON pr.finding_id = f.id AND pr.proposal_id = po.accepted_proposal_id
		WHERE f.release_id = $1 ORDER BY f.id`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.PostureEntry
	for rows.Next() {
		var (
			id, faultlineID, cve, stage string
			curStance                   *string
			curVersion                  *int
			baseScore                   int
			evidenceTrust               string
		)
		if err := rows.Scan(&id, &faultlineID, &cve, &stage, &curStance, &curVersion, &baseScore, &evidenceTrust); err != nil {
			return nil, err
		}
		e := app.PostureEntry{
			FindingID:   domain.FindingID(id),
			FaultlineID: faultlineID,
			CVE:         cve,
			Stage:       domain.Stage(stage),
			BaseScore:   baseScore,
		}
		if curStance != nil {
			e.Stance = domain.Stance(*curStance)
			e.HasPosition = true
			// Derived must not mean invisible (T12): a Position resting on anything weaker
			// than Observed carries its class here, beside stance and priority.
			if c := value.MaxTrust(value.TrustClass(evidenceTrust)); c != value.TrustObserved {
				e.Reservation = c
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.attachComponents(ctx, releaseID, out)
}

// attachComponents fills each posture row's components in ONE additional query (AI-GROUND-1 /
// the release-scoped Domain Projection).
//
// One query for the whole release, not one per row: a release carries hundreds of Findings, and
// a per-row read would make the rollup's cost linear in its own length — the N+1 that already
// makes `release-posture.sh` issue ~460 calls to render one table.
func (s *Store) attachComponents(ctx context.Context, releaseID string, entries []app.PostureEntry) ([]app.PostureEntry, error) {
	if len(entries) == 0 {
		return entries, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c.finding_id, c.purl, c.name, c.version, c.ecosystem, c.source
		FROM finding_components c
		JOIN findings f ON f.id = c.finding_id
		WHERE f.release_id = $1
		ORDER BY c.finding_id, c.purl`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byFinding := make(map[string][]domain.MatchedComponent, len(entries))
	for rows.Next() {
		var fid string
		var c domain.MatchedComponent
		if err := rows.Scan(&fid, &c.PURL, &c.Name, &c.Version, &c.Ecosystem, &c.Source); err != nil {
			return nil, err
		}
		byFinding[fid] = append(byFinding[fid], c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].Components = byFinding[string(entries[i].FindingID)]
	}
	return entries, nil
}

// SetBaseScore materializes Knowledge's CVE-intrinsic base score onto every Finding for a
// Faultline (C6). It is a denormalized read-column update, independent of aggregate version.
func (s *Store) SetBaseScore(ctx context.Context, faultlineID string, score int) error {
	_, err := s.exec(ctx).Exec(ctx,
		`UPDATE findings SET base_score = $2 WHERE faultline_id = $1`, faultlineID, score)
	return err
}

// SetSignals materializes the current exploitability picture onto every Finding for a Faultline
// (GOV-14b), beside the base score and for the same reason: a decision must be able to record the
// premise it rested on without a live cross-context read.
func (s *Store) SetSignals(ctx context.Context, faultlineID string, sig domain.ExploitSignals) error {
	_, err := s.exec(ctx).Exec(ctx,
		`UPDATE findings SET signal_kev = $2, signal_exploit_public = $3, signal_epss = $4
		 WHERE faultline_id = $1`, faultlineID, sig.KEV, sig.ExploitPublic, sig.EPSS)
	return err
}

// FaultlineBlastRadius returns the Releases affected by a Faultline (D10).
func (s *Store) FaultlineBlastRadius(ctx context.Context, faultlineID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT release_id FROM findings WHERE faultline_id = $1 ORDER BY release_id`, faultlineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var rel string
		if err := rows.Scan(&rel); err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation
// (SQLSTATE 23505) — e.g. two writers creating the same (Release, Faultline) at once.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Purge removes all Governance rows (dev/test only).
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`TRUNCATE processed_events, governance_outbox, finding_positions, finding_proposals, finding_components, findings RESTART IDENTITY CASCADE`)
	return err
}

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/domain"
)

// harnessEvidenceJSON is the persisted `harness-execution/v1` shape.
// Written once with the proposal, never updated (EDR-HARNESS-01).
type harnessEvidenceJSON struct {
	Schema        string   `json:"schema"`
	CommissionID  string   `json:"commission_id"`
	AnchorHash    string   `json:"anchor_hash"`
	Anchor        string   `json:"anchor"`
	AnchorState   string   `json:"anchor_state_at_intake"`
	TaskID        string   `json:"task_id"`
	ArtifactSeq   int64    `json:"artifact_bound_seq"`
	ArtifactID    string   `json:"artifact_object_id"`
	VerifiedPath  string   `json:"verified_member_path"`
	VerifiedHash  string   `json:"verified_member_sha256"`
	Skill         string   `json:"skill"`
	Composition   string   `json:"skill_composition_sha256"`
	Contract      string   `json:"contract"`
	ContractHash  string   `json:"contract_sha256"`
	ContractState string   `json:"contract_state_at_intake"`
	Reconstructed string   `json:"reconstruction"`
	Witness       string   `json:"production_witness"`
	Constitution  string   `json:"constitution_hash"`
	HarnessModule string   `json:"harness_module"`
	DelegCount    int      `json:"delegation_count"`
	DelegSeqs     []int64  `json:"delegation_seqs"`
	BusinessRefs  []string `json:"business_refs"`
}

const harnessSchema = "harness-execution/v1"

func encodeHarnessEvidence(ev *domain.HarnessExecution) ([]byte, string, error) {
	if ev == nil {
		return nil, "", nil
	}
	j := harnessEvidenceJSON{
		Schema: harnessSchema, CommissionID: string(ev.CommissionID), AnchorHash: ev.AnchorHash, Anchor: ev.Anchor,
		AnchorState: ev.AnchorState, TaskID: ev.TaskID, ArtifactSeq: ev.ArtifactSeq, ArtifactID: ev.ArtifactID,
		VerifiedPath: ev.VerifiedPath, VerifiedHash: ev.VerifiedHash, Skill: ev.Skill, Composition: ev.Composition,
		Contract: ev.Contract, ContractHash: ev.ContractHash, ContractState: ev.ContractState,
		Reconstructed: ev.Reconstructed, Witness: ev.Witness, Constitution: ev.Constitution, HarnessModule: ev.HarnessModule,
		DelegCount: ev.Delegations.Count, DelegSeqs: ev.Delegations.Seqs, BusinessRefs: ev.BusinessRefs,
	}
	if j.DelegSeqs == nil {
		j.DelegSeqs = []int64{}
	}
	b, err := json.Marshal(j)
	if err != nil {
		return nil, "", err
	}
	return b, string(ev.CommissionID), nil
}

func decodeHarnessEvidence(b []byte) (*domain.HarnessExecution, error) {
	var j harnessEvidenceJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if j.Schema != harnessSchema {
		return nil, fmt.Errorf("governance: harness evidence schema %q is not %s", j.Schema, harnessSchema)
	}
	return &domain.HarnessExecution{
		CommissionID: domain.CommissionID(j.CommissionID), AnchorHash: j.AnchorHash, Anchor: j.Anchor, AnchorState: j.AnchorState,
		TaskID: j.TaskID, ArtifactSeq: j.ArtifactSeq, ArtifactID: j.ArtifactID, VerifiedPath: j.VerifiedPath, VerifiedHash: j.VerifiedHash,
		Skill: j.Skill, Composition: j.Composition, Contract: j.Contract, ContractHash: j.ContractHash, ContractState: j.ContractState,
		Reconstructed: j.Reconstructed, Witness: j.Witness, Constitution: j.Constitution, HarnessModule: j.HarnessModule,
		Delegations: domain.HarnessDelegations{Count: j.DelegCount, Seqs: j.DelegSeqs}, BusinessRefs: j.BusinessRefs,
	}, nil
}

func (s *Store) loadCommissions(ctx context.Context, id string) ([]domain.Commission, error) {
	rows, err := s.querier(ctx).Query(ctx, `
		SELECT commission_id, skill, composition_sha256, anchor, artifact_sha256, commissioned_kind, commissioned_id,
		       premise_stage, premise_position, rationale, raised_at, state, withdrawn_kind, withdrawn_id, withdrawn_at, withdrawal_rationale
		FROM finding_commissions WHERE finding_id = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Commission
	for rows.Next() {
		var (
			cid, skill, comp, anchor, artifact, byKind, byID, stage, rationale, state, wKind, wID, wRationale string
			premisePos                                                                                        int
			raisedAt                                                                                          time.Time
			withdrawnAt                                                                                       *time.Time
		)
		if err := rows.Scan(&cid, &skill, &comp, &anchor, &artifact, &byKind, &byID, &stage, &premisePos, &rationale, &raisedAt, &state, &wKind, &wID, &withdrawnAt, &wRationale); err != nil {
			return nil, err
		}
		var wat time.Time
		if withdrawnAt != nil {
			wat = *withdrawnAt
		}
		out = append(out, domain.ReconstituteCommission(
			domain.CommissionID(cid),
			domain.MethodIdentity{Skill: skill, Composition: comp},
			domain.DeploymentIdentity{Anchor: anchor, Artifact: artifact},
			domain.Actor{Kind: domain.ActorKind(byKind), ID: byID},
			domain.CommissionPremise{Stage: domain.Stage(stage), PositionVersion: premisePos},
			rationale, raisedAt, domain.CommissionState(state),
			decidedActor(wKind, wID), wat, wRationale,
		))
	}
	return out, rows.Err()
}

func (s *Store) saveCommissions(ctx context.Context, tx pgx.Tx, f domain.Finding) error {
	for seq, c := range f.Commissions() {
		var withdrawnAt *time.Time
		if !c.WithdrawnAt().IsZero() {
			t := c.WithdrawnAt()
			withdrawnAt = &t
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO finding_commissions
			  (finding_id, commission_id, seq, skill, composition_sha256, anchor, artifact_sha256, commissioned_kind, commissioned_id,
			   premise_stage, premise_position, rationale, raised_at, state, withdrawn_kind, withdrawn_id, withdrawn_at, withdrawal_rationale)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
			ON CONFLICT (finding_id, commission_id)
			DO UPDATE SET state=EXCLUDED.state, withdrawn_kind=EXCLUDED.withdrawn_kind, withdrawn_id=EXCLUDED.withdrawn_id,
			              withdrawn_at=EXCLUDED.withdrawn_at, withdrawal_rationale=EXCLUDED.withdrawal_rationale`,
			string(f.ID()), string(c.ID()), seq, c.Method().Skill, c.Method().Composition, c.Deployment().Anchor, c.Deployment().Artifact,
			string(c.CommissionedBy().Kind), c.CommissionedBy().ID, string(c.Premise().Stage), c.Premise().PositionVersion,
			c.Rationale(), c.RaisedAt(), string(c.State()), string(c.WithdrawnBy().Kind), c.WithdrawnBy().ID, withdrawnAt, c.WithdrawalRationale()); err != nil {
			return err
		}
	}
	return nil
}

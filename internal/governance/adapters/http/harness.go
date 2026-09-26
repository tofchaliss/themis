package http

import (
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// EDR-HARNESS-01: the commission door (D-C-1..6) and the harness-
// evidence proposal route (D-I-5). Actors are bound to the authenticated
// principal exactly as deciders are (EDR-SECURITY-01 D10): a value the
// server cannot verify never overwrites one it can.

func (h *Handler) CommissionFinding(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	var body gen.CommissionRequest
	if !decode(w, r, &body) {
		return
	}
	declared := ""
	if body.ActorId != nil {
		declared = *body.ActorId
	}
	actorID, ok := actorProvenance(r.Context(), declared)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid commissioner", "actor_id is required when authentication is disabled")
		return
	}
	rationale := ""
	if body.Rationale != nil {
		rationale = *body.Rationale
	}
	cid, err := h.write.Commission(r.Context(), domain.FindingID(id),
		domain.MethodIdentity{Skill: body.Skill, Composition: body.CompositionSha256},
		domain.DeploymentIdentity{Anchor: body.Anchor, Artifact: body.ArtifactSha256},
		domain.Actor{Kind: domain.ActorHuman, ID: actorID}, rationale)
	if err != nil {
		writeHarnessErr(w, "cannot commission", err)
		return
	}
	cidStr := string(cid)
	writeJSON(w, http.StatusCreated, gen.CommissionResponse{CommissionId: &cidStr})
}

func (h *Handler) WithdrawCommission(w http.ResponseWriter, r *http.Request, id gen.FindingId, commissionID string) {
	var body gen.WithdrawCommissionRequest
	if !decode(w, r, &body) {
		return
	}
	declared := ""
	if body.ActorId != nil {
		declared = *body.ActorId
	}
	actorID, ok := actorProvenance(r.Context(), declared)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid actor", "actor_id is required when authentication is disabled")
		return
	}
	rationale := ""
	if body.Rationale != nil {
		rationale = *body.Rationale
	}
	if err := h.write.WithdrawCommission(r.Context(), domain.FindingID(id), domain.CommissionID(commissionID), domain.Actor{Kind: domain.ActorHuman, ID: actorID}, rationale); err != nil {
		writeHarnessErr(w, "cannot withdraw commission", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeHarnessErr maps the commission/evidence refusals to problem
// statuses: not-found → 404, state/correspondence → 409, shape → 400.
func writeHarnessErr(w http.ResponseWriter, title string, err error) {
	switch {
	case errors.Is(err, domain.ErrCommissionNotFound):
		writeProblem(w, http.StatusNotFound, title, err.Error())
	case errors.Is(err, domain.ErrCommissionWithdrawn), errors.Is(err, domain.ErrCommissionMismatch), errors.Is(err, domain.ErrDuplicateCommission), errors.Is(err, domain.ErrIllegalTransition):
		writeProblem(w, http.StatusConflict, title, err.Error())
	case errors.Is(err, domain.ErrCommissionMalformed), errors.Is(err, domain.ErrCommissionActor), errors.Is(err, domain.ErrHarnessEvidenceInvalid), errors.Is(err, domain.ErrHarnessEvidenceTrust), errors.Is(err, domain.ErrHarnessEvidenceNoCommit):
		writeProblem(w, http.StatusBadRequest, title, err.Error())
	default:
		writeErr(w, title, err)
	}
}

func fromHarnessEvidence(e gen.HarnessExecutionEvidence) domain.HarnessExecution {
	return domain.HarnessExecution{
		CommissionID: domain.CommissionID(e.CommissionId), AnchorHash: e.AnchorHash, Anchor: e.Anchor, AnchorState: e.AnchorStateAtIntake,
		TaskID: e.TaskId, ArtifactSeq: e.ArtifactBoundSeq, ArtifactID: e.ArtifactObjectId, VerifiedPath: e.VerifiedMemberPath, VerifiedHash: e.VerifiedMemberSha256,
		Skill: e.Skill, Composition: e.SkillCompositionSha256, Contract: e.Contract, ContractHash: e.ContractSha256, ContractState: e.ContractStateAtIntake,
		Reconstructed: e.Reconstruction, Witness: e.ProductionWitness, Constitution: e.ConstitutionHash, HarnessModule: e.HarnessModule,
		Delegations: domain.HarnessDelegations{Count: e.DelegationCount, Seqs: e.DelegationSeqs}, BusinessRefs: e.BusinessRefs,
	}
}

func toHarnessEvidenceView(e *domain.HarnessExecution) *gen.HarnessExecutionEvidence {
	if e == nil {
		return nil
	}
	seqs := e.Delegations.Seqs
	if seqs == nil {
		seqs = []int64{}
	}
	return &gen.HarnessExecutionEvidence{
		CommissionId: string(e.CommissionID), AnchorHash: e.AnchorHash, Anchor: e.Anchor, AnchorStateAtIntake: e.AnchorState,
		TaskId: e.TaskID, ArtifactBoundSeq: e.ArtifactSeq, ArtifactObjectId: e.ArtifactID, VerifiedMemberPath: e.VerifiedPath, VerifiedMemberSha256: e.VerifiedHash,
		Skill: e.Skill, SkillCompositionSha256: e.Composition, Contract: e.Contract, ContractSha256: e.ContractHash, ContractStateAtIntake: e.ContractState,
		Reconstruction: e.Reconstructed, ProductionWitness: e.Witness, ConstitutionHash: e.Constitution, HarnessModule: e.HarnessModule,
		DelegationCount: e.Delegations.Count, DelegationSeqs: seqs, BusinessRefs: append([]string{}, e.BusinessRefs...),
	}
}

func toCommissionView(c domain.Commission) gen.CommissionView {
	raised := c.RaisedAt()
	pos := c.Premise().PositionVersion
	v := gen.CommissionView{
		Id: strptr(string(c.ID())), Skill: strptr(c.Method().Skill), CompositionSha256: strptr(c.Method().Composition),
		Anchor: strptr(c.Deployment().Anchor), ArtifactSha256: strptr(c.Deployment().Artifact),
		CommissionedKind: strptr(string(c.CommissionedBy().Kind)), CommissionedId: strptr(c.CommissionedBy().ID),
		PremiseStage: strptr(string(c.Premise().Stage)), PremisePositionVersion: &pos,
		Rationale: strptr(c.Rationale()), RaisedAt: &raised, State: strptr(string(c.State())),
	}
	if !c.WithdrawnAt().IsZero() {
		wat := c.WithdrawnAt()
		v.WithdrawnAt = &wat
		v.WithdrawnKind = strptr(string(c.WithdrawnBy().Kind))
		v.WithdrawnId = strptr(c.WithdrawnBy().ID)
		v.WithdrawalRationale = strptr(c.WithdrawalRationale())
	}
	return v
}

// harnessTrust reads the submitted trust class for an evidence-bearing
// proposal; absent means the caller asserted nothing, which the
// service refuses against the derived class.
func harnessTrust(body gen.RaiseProposalRequest) value.TrustClass {
	if body.EvidenceTrust == nil {
		return ""
	}
	return value.TrustClass(*body.EvidenceTrust)
}

package http_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

const (
	hxA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hxB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hxC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func commissionBody() map[string]any {
	return map[string]any{"skill": "remediate-dependency@4", "composition_sha256": hxA, "anchor": "rsys@6", "artifact_sha256": hxB, "actor_id": "operator", "rationale": "remediate"}
}

func evidenceBody(cid string) map[string]any {
	return map[string]any{
		"commission_id": cid, "anchor_hash": hxB, "anchor": "rsys@6", "anchor_state_at_intake": "active", "task_id": "fx-1", "artifact_bound_seq": 31,
		"artifact_object_id": "sha256:" + hxC, "verified_member_path": "report.json", "verified_member_sha256": hxC, "skill": "remediate-dependency@4",
		"skill_composition_sha256": hxA, "contract": "report-valid@2", "contract_sha256": hxA, "contract_state_at_intake": "active", "reconstruction": "consistent-pass",
		"production_witness": "l5-witnessed", "constitution_hash": hxA, "harness_module": "harness@v0", "delegation_count": 1, "delegation_seqs": []int64{12}, "business_refs": []string{"CVE-1"},
	}
}

// EDR-HARNESS-01 over the wire: commission → proposal on the execution
// (trust derived, refs Business-Verified) → the Finding view exposes the
// commission and the evidence → withdrawal is forward-only and every
// refusal maps to its problem status.
func TestCommissionDoorAndHarnessProposal(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	srv := server(t, repo, fakeProjection{})
	base := srv.URL + "/findings/fnd-1"

	status, body := do(t, http.MethodPost, base+"/commissions", commissionBody())
	if status != http.StatusCreated {
		t.Fatalf("commission: %d %s", status, body)
	}
	var out struct {
		CommissionID string `json:"commission_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.CommissionID == "" {
		t.Fatalf("response = %s err=%v", body, err)
	}
	cid := out.CommissionID
	if f := repo.byID["fnd-1"]; f.Stage() != domain.StageIdentified || len(f.Commissions()) != 1 || f.Commissions()[0].CommissionedBy().ID != "dev:operator" {
		t.Fatalf("commission recorded wrong: stage %s %+v", f.Stage(), f.Commissions())
	}

	// Commission refusals: no actor when unauthenticated, malformed body,
	// malformed method (400), unknown finding (404).
	noActor := commissionBody()
	delete(noActor, "actor_id")
	if s, _ := do(t, http.MethodPost, base+"/commissions", noActor); s != http.StatusBadRequest {
		t.Errorf("no actor: %d", s)
	}
	if s, _ := doRaw(t, base+"/commissions", "{nope"); s != http.StatusBadRequest {
		t.Errorf("malformed: %d", s)
	}
	badMethod := commissionBody()
	badMethod["skill"] = "Not A Skill"
	if s, _ := do(t, http.MethodPost, base+"/commissions", badMethod); s != http.StatusBadRequest {
		t.Errorf("bad method: %d", s)
	}
	if s, _ := do(t, http.MethodPost, srv.URL+"/findings/ghost/commissions", commissionBody()); s != http.StatusNotFound {
		t.Errorf("unknown finding: %d", s)
	}

	// Proposal on the execution: refusals first, each mapped.
	raise := func(ev map[string]any, trust any) (int, []byte) {
		t.Helper()
		b := map[string]any{"stance": "mitigated", "rationale": "bumped", "evidence": ev}
		if trust != nil {
			b["evidence_trust"] = trust
		}
		return do(t, http.MethodPost, base+"/proposals", b)
	}
	if s, b := raise(evidenceBody(cid), nil); s != http.StatusBadRequest {
		t.Errorf("no trust asserted: %d %s", s, b)
	}
	if s, _ := raise(evidenceBody(cid), "asserted"); s != http.StatusBadRequest {
		t.Errorf("wrong trust: %d", s)
	}
	if s, _ := raise(evidenceBody("d1e2f3a4-0000-4000-8000-000000000009"), "inferred"); s != http.StatusNotFound {
		t.Errorf("unknown commission: %d", s)
	}
	mismatch := evidenceBody(cid)
	mismatch["skill"] = "remediate-dependency@3"
	if s, _ := raise(mismatch, "inferred"); s != http.StatusConflict {
		t.Errorf("method mismatch: %d", s)
	}
	unvouched := evidenceBody(cid)
	unvouched["business_refs"] = []string{"CVE-9999"}
	if s, _ := raise(unvouched, "inferred"); s != http.StatusInternalServerError {
		t.Errorf("unvouched ref: %d", s)
	}
	status, body = raise(evidenceBody(cid), "inferred")
	if status != http.StatusCreated {
		t.Fatalf("raise: %d %s", status, body)
	}

	// The Finding view carries the commission and the proposal's evidence.
	status, body = do(t, http.MethodGet, base, nil)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	var view struct {
		Commissions []struct {
			ID           string  `json:"id"`
			State        string  `json:"state"`
			PremiseStage string  `json:"premise_stage"`
			WithdrawnAt  *string `json:"withdrawn_at"`
		} `json:"commissions"`
		Proposals []struct {
			CommissionID  string `json:"commission_id"`
			EvidenceTrust string `json:"evidence_trust"`
			Harness       *struct {
				TaskID         string  `json:"task_id"`
				DelegationSeqs []int64 `json:"delegation_seqs"`
			} `json:"harness_evidence"`
		} `json:"proposals"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if len(view.Commissions) != 1 || view.Commissions[0].ID != cid || view.Commissions[0].State != "open" || view.Commissions[0].PremiseStage != "identified" || view.Commissions[0].WithdrawnAt != nil {
		t.Fatalf("commissions: %+v", view.Commissions)
	}
	if len(view.Proposals) != 1 || view.Proposals[0].CommissionID != cid || view.Proposals[0].EvidenceTrust != "inferred" || view.Proposals[0].Harness == nil || view.Proposals[0].Harness.TaskID != "fx-1" || len(view.Proposals[0].Harness.DelegationSeqs) != 1 {
		t.Fatalf("proposals: %+v", view.Proposals)
	}

	// Withdrawal: refusals, then 204, then the view shows the witness and a second withdrawal conflicts.
	if s, _ := doRaw(t, base+"/commissions/"+cid+"/withdraw", "{nope"); s != http.StatusBadRequest {
		t.Errorf("withdraw malformed: %d", s)
	}
	if s, _ := do(t, http.MethodPost, base+"/commissions/"+cid+"/withdraw", map[string]any{}); s != http.StatusBadRequest {
		t.Errorf("withdraw no actor: %d", s)
	}
	if s, _ := do(t, http.MethodPost, base+"/commissions/ghost/withdraw", map[string]any{"actor_id": "lead"}); s != http.StatusNotFound {
		t.Errorf("withdraw unknown: %d", s)
	}
	if s, b := do(t, http.MethodPost, base+"/commissions/"+cid+"/withdraw", map[string]any{"actor_id": "lead", "rationale": "premise moved"}); s != http.StatusNoContent {
		t.Fatalf("withdraw: %d %s", s, b)
	}
	if s, _ := do(t, http.MethodPost, base+"/commissions/"+cid+"/withdraw", map[string]any{"actor_id": "lead"}); s != http.StatusConflict {
		t.Errorf("second withdrawal: %d", s)
	}
	if s, _ := raise(evidenceBody(cid), "inferred"); s != http.StatusConflict {
		t.Errorf("proposal on withdrawn commission: %d", s)
	}
	_, body = do(t, http.MethodGet, base, nil)
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if view.Commissions[0].State != "withdrawn" || view.Commissions[0].WithdrawnAt == nil {
		t.Fatalf("withdrawn view: %+v", view.Commissions)
	}
}

// The commissioner is bound to the authenticated principal; the declared
// actor_id is ignored (EDR-SECURITY-01 D10 applied to the commission door).
func TestCommissionActorIsBoundToPrincipal(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	srv := authedServer(t, repo, "k-42")
	b := commissionBody()
	b["actor_id"] = "key:forged"
	if s, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/commissions", b); s != http.StatusCreated {
		t.Fatalf("%d %s", s, body)
	}
	f := repo.byID["fnd-1"]
	if cs := f.Commissions(); len(cs) != 1 || cs[0].CommissionedBy().ID != "key:k-42" {
		t.Fatalf("%+v", cs)
	}
}

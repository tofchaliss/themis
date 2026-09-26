// Command themis-intake is the human-operated decision-door bridge
// (EDR-HARNESS-01, D-I-1): it takes an AI-runtime EXECUTION TUPLE —
// never a record path, an object id, or a commission id — resolves it
// against the local, read-only runtime record plane through Themis's
// own intake adapter, renders the evidence view (three facts: model
// reasoning incl. delegations, artifact, verification), and raises a
// Governance Proposal over the authenticated API with the execution as
// its immutable evidence and the DERIVED trust class.
//
// It runs on the host that holds the runtime state root. Governance
// never reads that root; the runtime never initiates a Governance act.
//
//	themis-intake --state-root DIR --anchors FILE --contracts FILE \
//	  --anchor SHA --task ID --seq N \
//	  [--stance S --rationale R --governance URL]   (omit --stance to only render)
//
// Credential: THEMIS_API_KEY_WRITE (X-API-Key). Never printed.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/tofchaliss/themis-ai-runtime/src/harness/state"

	"github.com/themis-project/themis/internal/governance/adapters/harness"
	"github.com/themis-project/themis/internal/governance/domain"
)

func main() {
	var (
		stateRoot  = flag.String("state-root", "", "runtime state root (the L6 record plane), absolute")
		anchors    = flag.String("anchors", "", "Themis's governed anchors registry (anchors.json)")
		contracts  = flag.String("contracts", "", "Themis's governed verification contracts registry (contracts.json)")
		anchorHash = flag.String("anchor", "", "deployment anchor hash (sha256 hex) — tuple element 1")
		task       = flag.String("task", "", "task id — tuple element 2")
		seq        = flag.Int64("seq", 0, "artifact-bound event seq — tuple element 3")
		stance     = flag.String("stance", "", "proposal stance (Themis vocabulary); omit to render the evidence view only")
		rationale  = flag.String("rationale", "", "proposal rationale (human-readable)")
		findingID  = flag.String("finding", "", "Finding UUID the proposal targets (must be the one the execution read)")
		governance = flag.String("governance", "http://127.0.0.1:8083", "Governance base URL")
		out        = flag.String("out", "", "write the evidence view JSON here as well as stdout")
	)
	flag.Parse()
	fail := func(f string, a ...any) {
		fmt.Fprintf(os.Stderr, "themis-intake: "+f+"\n", a...)
		os.Exit(2)
	}
	for name, v := range map[string]string{"state-root": *stateRoot, "anchors": *anchors, "contracts": *contracts, "anchor": *anchorHash, "task": *task} {
		if v == "" {
			fail("--%s is required", name)
		}
	}
	if *seq <= 0 {
		fail("--seq must be positive")
	}
	root, err := state.OpenRoot(*stateRoot)
	if err != nil {
		fail("record plane: %v", err)
	}
	checkout := harness.Checkout{AnchorsRegistryPath: *anchors, ContractsRegistryPath: *contracts, HarnessModule: harnessModule()}
	res, err := harness.Resolve(root, checkout, harness.Tuple{AnchorHash: *anchorHash, TaskID: *task, ArtifactBoundSeq: *seq})
	if err != nil {
		// A refusal is the answer: link-named, exit 1, nothing raised.
		fmt.Fprintf(os.Stderr, "themis-intake: REFUSED: %v\n", err)
		os.Exit(1)
	}
	ev, trust := harness.Evidence(res, checkout)
	view := evidenceView(res, ev, string(trust))
	vb, _ := json.MarshalIndent(view, "", "  ")
	fmt.Println(string(vb))
	if *out != "" {
		if err := os.WriteFile(*out, append(vb, '\n'), 0o644); err != nil {
			fail("write evidence view: %v", err)
		}
	}
	if *stance == "" {
		return
	}
	if err := ev.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "themis-intake: NOT PROPOSAL-ELIGIBLE: %v\n", err)
		os.Exit(1)
	}
	if *findingID == "" {
		fail("--finding is required to raise a proposal")
	}
	key := os.Getenv("THEMIS_API_KEY_WRITE")
	if key == "" {
		fmt.Fprintln(os.Stderr, "themis-intake: THEMIS_API_KEY_WRITE is not set — the proposal will be raised unauthenticated (dev estates only; the proposer will be recorded as dev:)")
	}
	pid, err := raiseProposal(*governance, key, *findingID, *stance, *rationale, ev, string(trust))
	if err != nil {
		fmt.Fprintf(os.Stderr, "themis-intake: proposal refused by Governance: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("proposal raised: %s (finding %s, commission %s, trust %s)\n", pid, *findingID, ev.CommissionID, trust)
}

func harnessModule() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/tofchaliss/themis-ai-runtime/src/harness" {
				return d.Path + "@" + d.Version
			}
		}
	}
	return "github.com/tofchaliss/themis-ai-runtime/src/harness@workspace"
}

// evidenceView renders the three facts SEPARATELY (proposal: harness
// fact, verification fact, governance fact-to-be). Identities only —
// never report content, never a conclusion (B-T-2).
func evidenceView(r *harness.Resolution, ev domain.HarnessExecution, trust string) map[string]any {
	turns := make([]map[string]any, 0, len(r.ModelTurns))
	for _, m := range r.ModelTurns {
		turns = append(turns, map[string]any{"seq": m.Seq, "object_id": m.ObjectID})
	}
	dels := make([]map[string]any, 0, len(r.Delegations))
	for _, d := range r.Delegations {
		dels = append(dels, map[string]any{"seq": d.Seq, "parent_call_seq": d.ParentCallSeq, "template": d.Template, "model": d.Model, "evidence_refs": d.EvidenceRefs, "output_object_id": d.OutputID, "outcome": d.Outcome})
	}
	return map[string]any{
		"execution": map[string]any{
			"anchor_hash": r.Tuple.AnchorHash, "anchor": ev.Anchor, "anchor_state_at_intake": r.AnchorState,
			"task_id": r.Tuple.TaskID, "constitution_hash": r.Constitution, "commission_id": r.CommissionID, "skill": r.Skill,
		},
		"model_reasoning": map[string]any{"model_turns": turns, "delegations": dels},
		"artifact": map[string]any{
			"object_id": r.ArtifactObjectID, "artifact_bound_seq": r.BindingSeq, "completed_seq": r.CompletedSeq,
			"verified_member_path": r.VerifiedPath, "verified_member_sha256": r.VerifiedHash, "production_witness": r.Witness,
			"l5": map[string]any{"sealed_seq": r.L5.SealedSeq, "egressing_seq": r.L5.EgressingSeq, "egress_op_seq": r.L5.EgressOpSeq},
		},
		"verification": map[string]any{
			"seq": r.VerificationSeq, "contract": ev.Contract, "contract_sha256": r.ContractSHA256, "contract_state_at_intake": r.ContractState,
			"verifier_audit_seq": r.VerifierAuditSeq, "reconstructed_outcome": string(r.Reconstruction.Evaluation.Outcome), "reconstruction_consistent": r.Reconstruction.Consistent,
		},
		"trust_class":                trust,
		"business_verification_refs": r.FindingRefs,
	}
}

func raiseProposal(base, key, findingID, stance, rationale string, ev domain.HarnessExecution, trust string) (string, error) {
	body := map[string]any{
		"stance": stance, "rationale": rationale, "proposer_kind": "human", "evidence_trust": trust,
		"evidence": map[string]any{
			"commission_id": string(ev.CommissionID), "anchor_hash": ev.AnchorHash, "anchor": ev.Anchor, "anchor_state_at_intake": ev.AnchorState,
			"task_id": ev.TaskID, "artifact_bound_seq": ev.ArtifactSeq, "artifact_object_id": ev.ArtifactID,
			"verified_member_path": ev.VerifiedPath, "verified_member_sha256": ev.VerifiedHash,
			"skill": ev.Skill, "skill_composition_sha256": ev.Composition, "contract": ev.Contract, "contract_sha256": ev.ContractHash,
			"contract_state_at_intake": ev.ContractState, "reconstruction": ev.Reconstructed, "production_witness": ev.Witness,
			"constitution_hash": ev.Constitution, "harness_module": ev.HarnessModule,
			"delegation_count": ev.Delegations.Count, "delegation_seqs": nonNil(ev.Delegations.Seqs), "business_refs": ev.BusinessRefs,
		},
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/v1/findings/"+findingID+"/proposals", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out struct {
		ProposalID string `json:"proposal_id"`
	}
	_ = json.Unmarshal(rb, &out)
	return out.ProposalID, nil
}

func nonNil(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

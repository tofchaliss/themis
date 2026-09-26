// Package harness is Governance's outbound adapter to the AI runtime's
// RECORD PLANE (EDR-HARNESS-01, D-I-7): it resolves an execution tuple
// against a runtime state root, re-establishes production (D-T-4, the
// five-link L5/L6 chain, D-W-5) and verification (D-T-5) from the
// record itself, and maps the result to the domain's
// harness-execution/v1 evidence with its DERIVED trust class.
//
// It is the ONLY Themis package that imports the runtime module, and it
// imports exactly its read-only record contracts: state, deployment,
// verification, verification/seam. It never executes anything, writes
// nothing, and reaches no runtime execution package (depguard +
// tests/architecture enforce both). Themis's Governance service never
// links this package: it is composed only by cmd/themis-intake, the
// human-operated bridge (D-I-1).
package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/tofchaliss/themis-ai-runtime/src/harness/deployment"
	"github.com/tofchaliss/themis-ai-runtime/src/harness/state"
	"github.com/tofchaliss/themis-ai-runtime/src/harness/verification"
	vseam "github.com/tofchaliss/themis-ai-runtime/src/harness/verification/seam"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Tuple is the referencable execution tuple (D-T-1): the ADMISSIBILITY
// HANDLE a caller supplies. Nothing else — no object id, no report
// path, no commission id — is ever an input (D-C-5: the commission is
// DERIVED from the record).
type Tuple struct {
	AnchorHash       string
	TaskID           string
	ArtifactBoundSeq int64
}

// Checkout names Themis's OWN governed checkout of the runtime's
// registries: the anchors registry (D-T-2) and the verification
// contracts registry (D-T-5). A deployment property, never per-call.
type Checkout struct {
	AnchorsRegistryPath   string
	ContractsRegistryPath string
	// HarnessModule names the runtime module version this intake was
	// built against (module@pseudo-version); it travels into the evidence.
	HarnessModule string
}

// Typed refusal classes, link-named messages (D-T-4).
var (
	ErrNotReferencable = errors.New("execution not referencable")
	ErrDeployment      = errors.New("deployment-refused")
	ErrProvenance      = errors.New("artifact-provenance-refused")
	ErrVerification    = errors.New("verification-refused")
)

// Witness scope values (D-W-5).
const (
	WitnessL5     = "l5-witnessed"
	WitnessL6Only = "l6-record-only"
)

// premiseL8ToolLess is the premise every witnessing constitution must
// re-affirm (D-L-3): delegates are tool-less with no Governance access.
// A future tool-capable L8 cannot be absorbed by a hash bump.
const premiseL8ToolLess = "l8-delegates-tool-less"

// witnessingConstitutions is the closed table of runtime L6 constitution
// hashes under which the five-link production proof is OWED (D-W-5).
// A record whose constitution is listed must carry the L5 witnesses; a
// record whose constitution is not listed is historical: inspectable,
// never Position-eligible. Every entry re-affirms its premises (D-L-3).
var witnessingConstitutions = map[string][]string{
	// W-M1/W-M2 (2026-09-26): eventWriters folded in; L5 handle.
	"1df0e28548a48b373e779dce8f00ea906c7f98afc009d573afccdf1009d77685": {premiseL8ToolLess},
}

// WitnessingConstitutions exposes the table for tests and tooling.
func WitnessingConstitutions() map[string][]string {
	out := map[string][]string{}
	for k, v := range witnessingConstitutions {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Resolution is everything Themis DERIVED from the tuple.
type Resolution struct {
	Tuple Tuple

	AnchorName    string
	AnchorVersion int
	AnchorState   string

	ArtifactObjectID string
	ArtifactBytes    []byte
	BindingSeq       int64
	CompletedSeq     int64
	Constitution     string
	Witness          string
	L5               L5Links

	VerificationSeq  int64
	ContractName     string
	ContractVersion  int
	ContractSHA256   string
	ContractState    string
	VerifierAuditSeq int64
	Reconstruction   verification.Report
	VerifiedPath     string
	VerifiedHash     string

	CommissionID string // from origin:commission in the CREATED event; "" = none
	Skill        string
	Composition  string

	ModelTurns  []ModelTurn
	Delegations []Delegation
	FindingRefs []string // dependency PURLs + CVE from the RECORDED Finding bytes the execution read
	Events      []state.Event
}

// L5Links are the seqs of the L5-witnessed production links (D-W-5).
type L5Links struct {
	SealedSeq    int64
	EgressingSeq int64
	EgressOpSeq  int64
	EgressAddr   string
}

// ModelTurn is one recorded model output by identity.
type ModelTurn struct {
	Seq      int64
	ObjectID string
}

// Delegation is one l8-delegation witness by identity (D-L-1).
type Delegation struct {
	Seq           int64
	ParentCallSeq int64
	Template      string
	Model         string
	EvidenceRefs  []string
	OutputID      string
	Outcome       string
}

var shaHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func hexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Resolve performs D-T-1 → D-T-2 → D-T-4 (five links when owed) → D-T-5
// under the D-T-6 table. Read-only; consults nothing live.
func Resolve(root *state.Root, checkout Checkout, tuple Tuple) (*Resolution, error) {
	if root == nil {
		return nil, fmt.Errorf("%w: no record plane", ErrNotReferencable)
	}
	if !state.ValidTaskID(tuple.TaskID) {
		return nil, fmt.Errorf("%w: task id %q is not well-formed", ErrNotReferencable, tuple.TaskID)
	}
	if !shaHex.MatchString(tuple.AnchorHash) {
		return nil, fmt.Errorf("%w: anchor hash is not a well-formed sha256 identity", ErrNotReferencable)
	}
	if tuple.ArtifactBoundSeq <= 0 {
		return nil, fmt.Errorf("%w: artifact-bound seq must be positive", ErrNotReferencable)
	}
	sv, err := root.ReadStatus(tuple.TaskID)
	if err != nil {
		return nil, fmt.Errorf("%w: record for task %s unavailable: %v", ErrNotReferencable, tuple.TaskID, err)
	}
	if sv.Verdict != state.VerdictVerified {
		return nil, fmt.Errorf("%w: record verdict %s — no partial acceptance", ErrNotReferencable, sv.Verdict)
	}
	if sv.Status != state.StatusCompleted {
		return nil, fmt.Errorf("%w: not a completed execution (status %s)", ErrNotReferencable, sv.Status)
	}
	man, err := root.ReadManifest(tuple.TaskID)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest unavailable: %v", ErrNotReferencable, err)
	}
	recorded := man.GovernedHashes["deployment_anchor"]
	switch {
	case recorded == "" || recorded == "unanchored":
		return nil, fmt.Errorf("%w: unanchored execution", ErrNotReferencable)
	case recorded != tuple.AnchorHash:
		return nil, fmt.Errorf("%w: the record identifies deployment anchor %s…, the tuple names %s…", ErrNotReferencable, short(recorded), short(tuple.AnchorHash))
	}
	events, err := root.ReadEvents(tuple.TaskID)
	if err != nil {
		return nil, fmt.Errorf("%w: event stream unavailable: %v", ErrNotReferencable, err)
	}
	res := &Resolution{Tuple: tuple, Events: events, BindingSeq: tuple.ArtifactBoundSeq, Constitution: man.ConstitutionHash}
	res.Skill = man.GovernedHashes["skill"]
	res.Composition = man.GovernedHashes["origin:skill_composition"]
	res.CommissionID = man.GovernedHashes["origin:commission"]

	// D-T-2
	anchorObj := materializedAnchorObject(events)
	if anchorObj == "" {
		return nil, fmt.Errorf("%w: the record carries no materialized deployment_anchor object", ErrDeployment)
	}
	anchorBytes, err := root.Store().GetObject(anchorObj)
	if err != nil {
		return nil, fmt.Errorf("%w: recorded anchor bytes unavailable: %v", ErrDeployment, err)
	}
	anchor, err := deployment.VerifyAnchorRecord(recorded, anchorBytes, checkout.AnchorsRegistryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeployment, err)
	}
	res.AnchorName, res.AnchorVersion = anchor.Name, anchor.Deployment
	res.AnchorState, err = anchorStateAtIntake(checkout.AnchorsRegistryPath, anchor.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeployment, err)
	}

	// D-T-4 over the L6 links; then the L5 links when the record's
	// constitution owes them (D-W-5). The branch is on the RECORDED
	// constitution, never the running binary's.
	if err := replayProduction(root, man, events, res); err != nil {
		return nil, err
	}
	if _, owed := witnessingConstitutions[res.Constitution]; owed {
		if err := replayL5(events, res); err != nil {
			return nil, err
		}
		res.Witness = WitnessL5
	} else {
		res.Witness = WitnessL6Only
	}

	// D-T-5
	if err := reestablishVerification(root, checkout, events, res); err != nil {
		return nil, err
	}

	for _, ev := range events {
		switch {
		case ev.Class == state.EvModelTurn && ev.Writer == "l7" && len(ev.Refs) == 1:
			res.ModelTurns = append(res.ModelTurns, ModelTurn{Seq: ev.Seq, ObjectID: ev.Refs[0].ID})
		case ev.Class == state.EvL8Delegation:
			res.Delegations = append(res.Delegations, delegationOf(ev))
		}
	}
	res.FindingRefs = findingRefs(root, events)
	return res, nil
}

func materializedAnchorObject(events []state.Event) string {
	for _, ev := range events {
		if ev.Class != state.EvL2Delivery || ev.Writer != "l7" {
			continue
		}
		var body struct {
			Kind    string            `json:"kind"`
			Objects map[string]string `json:"objects"`
		}
		if json.Unmarshal(ev.Body, &body) != nil || body.Kind != "materialized-governed-artifacts" {
			continue
		}
		id := body.Objects["deployment_anchor"]
		for _, r := range ev.Refs {
			if id != "" && r.ID == id {
				return id
			}
		}
	}
	return ""
}

func anchorStateAtIntake(registryPath, artifactSHA string) (string, error) {
	reg, err := deployment.LoadRegistry(registryPath)
	if err != nil {
		return "", err
	}
	for _, e := range reg.Entries {
		if e.Artifact == artifactSHA {
			return e.State, nil
		}
	}
	return "", fmt.Errorf("anchor %s… not registered on Themis's checkout", short(artifactSHA))
}

type egressManifest struct {
	TaskID  string `json:"task_id"`
	Changes []struct {
		Path    string `json:"path"`
		Type    string `json:"type"`
		NewHash string `json:"new_hash"`
		Content string `json:"content"`
	} `json:"changes"`
}

func replayProduction(root *state.Root, man *state.Manifest, events []state.Event, res *Resolution) error {
	seq := res.BindingSeq
	var binding *state.Event
	for i := range events {
		if events[i].Seq == seq {
			binding = &events[i]
		}
	}
	if binding == nil {
		return fmt.Errorf("%w: no event at seq %d", ErrProvenance, seq)
	}
	if binding.Class != state.EvArtifact {
		return fmt.Errorf("%w: event at seq %d is %s, not artifact-bound", ErrProvenance, seq, binding.Class)
	}
	if binding.Writer != "l6" {
		return fmt.Errorf("%w: artifact-bound at seq %d written by %q, not l6", ErrProvenance, seq, binding.Writer)
	}
	for _, ev := range events {
		if ev.Class == state.EvArtifact && ev.Seq != seq {
			return fmt.Errorf("%w: competing artifact-bound at seq %d (the tuple names seq %d)", ErrProvenance, ev.Seq, seq)
		}
	}
	if len(binding.Refs) != 1 || binding.Refs[0].Class != state.ObjEgressArtifact {
		return fmt.Errorf("%w: artifact-bound at seq %d does not reference exactly one egress-artifact", ErrProvenance, seq)
	}
	var body struct {
		Artifact string `json:"artifact"`
	}
	if json.Unmarshal(binding.Body, &body) != nil || body.Artifact != binding.Refs[0].ID {
		return fmt.Errorf("%w: artifact-bound body names a different address than its reference", ErrProvenance)
	}
	id := binding.Refs[0].ID
	var completed int64
	for _, ev := range events {
		if ev.Class != state.EvLifecycle || (ev.Writer != "l6" && ev.Writer != "l6-recovery") {
			continue
		}
		var lb struct {
			To string `json:"to"`
		}
		if json.Unmarshal(ev.Body, &lb) == nil && lb.To == string(state.StatusCompleted) {
			completed = ev.Seq
		}
	}
	switch {
	case completed == 0:
		return fmt.Errorf("%w: no lifecycle COMPLETED written by l6", ErrProvenance)
	case completed < seq:
		return fmt.Errorf("%w: lifecycle COMPLETED (seq %d) precedes the binding (seq %d)", ErrProvenance, completed, seq)
	}
	inManifest := false
	for _, a := range man.ArtifactAddrs {
		if a == id {
			inManifest = true
		}
	}
	if !inManifest {
		return fmt.Errorf("%w: manifest does not project artifact %s", ErrProvenance, id)
	}
	b, err := root.Store().GetObject(id)
	if err != nil {
		return fmt.Errorf("%w: artifact object %s: %v", ErrProvenance, id, err)
	}
	var em egressManifest
	if err := json.Unmarshal(b, &em); err != nil {
		return fmt.Errorf("%w: artifact %s is not an egress manifest: %v", ErrProvenance, id, err)
	}
	if em.TaskID != res.Tuple.TaskID {
		return fmt.Errorf("%w: egress manifest names task %q, the tuple names %q", ErrProvenance, em.TaskID, res.Tuple.TaskID)
	}
	res.ArtifactObjectID, res.ArtifactBytes, res.CompletedSeq = id, b, completed
	return nil
}

// replayL5 establishes the L5-owned links (D-W-2/3/5) in causal order,
// naming the first failed link: ACTIVE→SEALED(task-complete) →
// SEALED→EGRESSING → l5-op egress acknowledged A → artifact-bound A.
func replayL5(events []state.Event, res *Resolution) error {
	var sealedSeq, egressingSeq, egressOpSeq int64
	var egressAddr string
	egressOps := 0
	for _, ev := range events {
		if ev.Seq >= res.BindingSeq {
			break
		}
		switch ev.Class {
		case state.EvL5Transition:
			if ev.Writer != "l5" {
				return fmt.Errorf("%w: l5-transition at seq %d written by %q, not l5", ErrProvenance, ev.Seq, ev.Writer)
			}
			var b struct{ From, To, Reason string }
			if json.Unmarshal(ev.Body, &b) != nil || b.From == "" || b.To == "" {
				return fmt.Errorf("%w: malformed l5-transition at seq %d", ErrProvenance, ev.Seq)
			}
			switch b.To {
			case "SEALED":
				if b.From != "ACTIVE" {
					return fmt.Errorf("%w: SEALED reached from %s at seq %d, not ACTIVE", ErrProvenance, b.From, ev.Seq)
				}
				if b.Reason != "task-complete" {
					return fmt.Errorf("%w: seal reason %q at seq %d is not task-complete", ErrProvenance, b.Reason, ev.Seq)
				}
				sealedSeq = ev.Seq
			case "EGRESSING":
				if sealedSeq == 0 || b.From != "SEALED" {
					return fmt.Errorf("%w: EGRESSING at seq %d without a preceding ACTIVE→SEALED", ErrProvenance, ev.Seq)
				}
				egressingSeq = ev.Seq
			}
		case state.EvL5Op:
			if ev.Writer != "l5" {
				return fmt.Errorf("%w: l5-op at seq %d written by %q, not l5", ErrProvenance, ev.Seq, ev.Writer)
			}
			var b struct {
				Op      string `json:"op"`
				Outcome string `json:"outcome"`
				Address string `json:"artifact_address"`
			}
			_ = json.Unmarshal(ev.Body, &b)
			if b.Op != "egress" {
				continue
			}
			if b.Outcome != "acknowledged" {
				continue // a refused/failed egress is witnessed but never satisfies production (D-W-3)
			}
			egressOps++
			if egressingSeq == 0 || ev.Seq < egressingSeq {
				return fmt.Errorf("%w: egress acknowledgement at seq %d precedes EGRESSING", ErrProvenance, ev.Seq)
			}
			egressOpSeq, egressAddr = ev.Seq, b.Address
		}
	}
	switch {
	case sealedSeq == 0:
		return fmt.Errorf("%w: missing l5-transition ACTIVE→SEALED task-complete before the binding", ErrProvenance)
	case egressingSeq == 0:
		return fmt.Errorf("%w: missing l5-transition SEALED→EGRESSING before the binding", ErrProvenance)
	case egressOps == 0:
		return fmt.Errorf("%w: missing l5-op egress witness (acknowledged) for artifact %s", ErrProvenance, res.ArtifactObjectID)
	case egressOps > 1:
		return fmt.Errorf("%w: %d acknowledged egress witnesses; exactly one is required", ErrProvenance, egressOps)
	case "sha256:"+egressAddr != res.ArtifactObjectID:
		return fmt.Errorf("%w: egress acknowledged %s…, the binding names %s…", ErrProvenance, short(egressAddr), short(strings.TrimPrefix(res.ArtifactObjectID, "sha256:")))
	}
	res.L5 = L5Links{SealedSeq: sealedSeq, EgressingSeq: egressingSeq, EgressOpSeq: egressOpSeq, EgressAddr: egressAddr}
	return nil
}

func reestablishVerification(root *state.Root, checkout Checkout, events []state.Event, res *Resolution) error {
	var vev *state.Event
	for i := range events {
		ev := &events[i]
		if ev.Class != state.EvVerification {
			continue
		}
		if ev.Seq < res.BindingSeq {
			vev = ev
		} else if vev == nil {
			return fmt.Errorf("%w: verification does not correspond to artifact production (verification seq %d after binding seq %d)", ErrVerification, ev.Seq, res.BindingSeq)
		}
	}
	if vev == nil {
		return fmt.Errorf("%w: no reproducible PASS (no l10-verification precedes the binding)", ErrVerification)
	}
	if vev.Writer != "l10" {
		return fmt.Errorf("%w: l10-verification at seq %d written by %q, not l10", ErrVerification, vev.Seq, vev.Writer)
	}
	rep := vseam.ReconstructEvent(root, *vev, events)
	res.VerificationSeq, res.Reconstruction = vev.Seq, rep
	rec := rep.Evaluation
	if len(rep.MissingInputs) > 0 {
		return fmt.Errorf("%w: verification evidence unavailable (%v)", ErrVerification, rep.MissingInputs)
	}
	if !rep.Consistent {
		return fmt.Errorf("%w: no reproducible PASS (reconstruction inconsistent: %s)", ErrVerification, failedChecks(rep))
	}
	if rec.Outcome != verification.OutcomePass {
		return fmt.Errorf("%w: no reproducible PASS (reconstructed outcome %s)", ErrVerification, rec.Outcome)
	}
	creg, err := verification.LoadRegistry(checkout.ContractsRegistryPath)
	if err != nil {
		return fmt.Errorf("%w: contracts registry unreadable: %v", ErrVerification, err)
	}
	res.ContractName, res.ContractVersion, res.ContractSHA256 = rec.ContractName, rec.ContractVersion, rec.ContractSHA256
	registered := false
	for _, e := range creg.Entries {
		if e.Contract != rec.ContractSHA256 {
			continue
		}
		if e.Name != rec.ContractName || e.Version != rec.ContractVersion {
			return fmt.Errorf("%w: contract not registered (%s@%d's bytes are registered as %s@%d)", ErrVerification, rec.ContractName, rec.ContractVersion, e.Name, e.Version)
		}
		registered, res.ContractState = true, string(e.State)
		break
	}
	if !registered {
		return fmt.Errorf("%w: contract not registered (%s@%d, %s…)", ErrVerification, rec.ContractName, rec.ContractVersion, short(rec.ContractSHA256))
	}
	var auditSeq int64 = -1
	if _, err := fmt.Sscanf(rec.ExecutionRef, "l4:%d", &auditSeq); err != nil {
		return fmt.Errorf("%w: verifier execution not authorized (execution_ref %q)", ErrVerification, rec.ExecutionRef)
	}
	rawBytes, err := root.Store().GetObject("sha256:" + rec.RawObjectID)
	if err != nil || rec.RawObjectID == "" {
		return fmt.Errorf("%w: verification evidence unavailable (raw bytes %s)", ErrVerification, short(rec.RawObjectID))
	}
	rawHex := hexOf(rawBytes)
	var audit *state.Event
	for i := range events {
		if events[i].Seq == auditSeq && events[i].Class == state.EvL4Audit {
			audit = &events[i]
		}
	}
	if audit == nil {
		return fmt.Errorf("%w: verifier execution not authorized (no l4-audit at seq %d)", ErrVerification, auditSeq)
	}
	var ab struct {
		Tool         string `json:"Tool"`
		Decision     string `json:"Decision"`
		ResultHash   string `json:"ResultHash"`
		RegistryHash string `json:"RegistryHash"`
	}
	_ = json.Unmarshal(audit.Body, &ab)
	switch {
	case audit.Writer != "l4":
		return fmt.Errorf("%w: verifier execution not authorized (audit at seq %d written by %q)", ErrVerification, auditSeq, audit.Writer)
	case ab.Decision != "authorized":
		return fmt.Errorf("%w: verifier execution not authorized (decision %q)", ErrVerification, ab.Decision)
	case ab.Tool != rec.Capability:
		return fmt.Errorf("%w: verifier execution not authorized (audit executed %q, record names %q)", ErrVerification, ab.Tool, rec.Capability)
	case ab.RegistryHash != rec.RegistrySHA256:
		return fmt.Errorf("%w: verifier execution not authorized (authorizing registry differs)", ErrVerification)
	case ab.ResultHash != rawHex:
		return fmt.Errorf("%w: verifier execution not authorized (audit ResultHash %s… ≠ raw bytes %s…)", ErrVerification, short(ab.ResultHash), short(rawHex))
	}
	res.VerifierAuditSeq = auditSeq
	var em egressManifest
	_ = json.Unmarshal(res.ArtifactBytes, &em)
	for _, c := range em.Changes {
		if c.Type == "deleted" || c.NewHash != rawHex {
			continue
		}
		if c.Content != string(rawBytes) {
			return fmt.Errorf("%w: verified bytes are not the bound artifact (member %s hashes as the verified bytes but differs)", ErrVerification, c.Path)
		}
		res.VerifiedPath, res.VerifiedHash = c.Path, rawHex
		return nil
	}
	return fmt.Errorf("%w: verified bytes are not the bound artifact (no member of egress %s has hash %s…)", ErrVerification, short(res.ArtifactObjectID), short(rawHex))
}

func failedChecks(rep verification.Report) string {
	var names []string
	for _, c := range rep.Checks {
		if !c.OK {
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return "unnamed"
	}
	return strings.Join(names, ", ")
}

func delegationOf(ev state.Event) Delegation {
	var b struct {
		ParentCallSeq int64 `json:"parent_call_seq"`
		Template      struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"template"`
		ModelIdentity struct {
			Model string `json:"model"`
		} `json:"model_identity"`
		EvidenceRefs []struct {
			Seq      int64  `json:"seq"`
			ObjectID string `json:"object_id"`
		} `json:"evidence_refs"`
		OutputObjectRef string `json:"output_object_ref"`
		Outcome         string `json:"outcome"`
	}
	_ = json.Unmarshal(ev.Body, &b)
	d := Delegation{Seq: ev.Seq, ParentCallSeq: b.ParentCallSeq, Model: b.ModelIdentity.Model, OutputID: b.OutputObjectRef, Outcome: b.Outcome}
	if b.Template.Name != "" {
		d.Template = fmt.Sprintf("%s@%d", b.Template.Name, b.Template.Version)
	}
	for _, r := range b.EvidenceRefs {
		d.EvidenceRefs = append(d.EvidenceRefs, fmt.Sprintf("%d:%s", r.Seq, r.ObjectID))
	}
	return d
}

// findingRefs extracts the identifiers Business Verification will
// vouch (dependency PURLs and the CVE) from the RECORDED bytes of the
// get_finding reads the execution performed — never from model output.
func findingRefs(root *state.Root, events []state.Event) []string {
	seen := map[string]bool{}
	var refs []string
	for _, ev := range events {
		if ev.Class != state.EvL4Audit || ev.Writer != "l4" {
			continue
		}
		var ab struct {
			Tool     string `json:"Tool"`
			Decision string `json:"Decision"`
		}
		if json.Unmarshal(ev.Body, &ab) != nil || ab.Tool != "get_finding" || ab.Decision != "authorized" {
			continue
		}
		for _, r := range ev.Refs {
			b, err := root.Store().GetObject(r.ID)
			if err != nil {
				continue
			}
			var fv struct {
				CVE        string `json:"cve"`
				Components []struct {
					PURL string `json:"purl"`
				} `json:"components"`
			}
			if json.Unmarshal(b, &fv) != nil {
				continue
			}
			if fv.CVE != "" && !seen[fv.CVE] {
				seen[fv.CVE] = true
				refs = append(refs, fv.CVE)
			}
			for _, c := range fv.Components {
				if c.PURL != "" && !seen[c.PURL] {
					seen[c.PURL] = true
					refs = append(refs, c.PURL)
				}
			}
		}
	}
	return refs
}

// Evidence maps a Resolution to the domain's harness-execution/v1
// evidence with its DERIVED trust class. Only an L5-witnessed
// resolution with a cited commission produces valid evidence; the
// domain's Validate refuses the rest.
func Evidence(r *Resolution, checkout Checkout) (domain.HarnessExecution, value.TrustClass) {
	seqs := make([]int64, 0, len(r.Delegations))
	for _, d := range r.Delegations {
		seqs = append(seqs, d.Seq)
	}
	reconstructed := "inconsistent"
	if r.Reconstruction.Consistent && r.Reconstruction.Evaluation.Outcome == verification.OutcomePass {
		reconstructed = "consistent-pass"
	}
	ev := domain.HarnessExecution{
		CommissionID:  domain.CommissionID(r.CommissionID),
		AnchorHash:    r.Tuple.AnchorHash,
		Anchor:        fmt.Sprintf("%s@%d", r.AnchorName, r.AnchorVersion),
		AnchorState:   r.AnchorState,
		TaskID:        r.Tuple.TaskID,
		ArtifactSeq:   r.BindingSeq,
		ArtifactID:    r.ArtifactObjectID,
		VerifiedPath:  r.VerifiedPath,
		VerifiedHash:  r.VerifiedHash,
		Skill:         r.Skill,
		Composition:   r.Composition,
		Contract:      fmt.Sprintf("%s@%d", r.ContractName, r.ContractVersion),
		ContractHash:  r.ContractSHA256,
		ContractState: r.ContractState,
		Reconstructed: reconstructed,
		Witness:       r.Witness,
		Constitution:  r.Constitution,
		HarnessModule: checkout.HarnessModule,
		Delegations:   domain.HarnessDelegations{Count: len(seqs), Seqs: seqs},
		BusinessRefs:  append([]string(nil), r.FindingRefs...),
	}
	return ev, ev.DerivedTrust()
}

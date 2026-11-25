package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Decision copy (EDR-SYNC-01 revision 2, D9-D11). A person who decides a Finding may name the
// other Findings of the same CVE in the same product that the decision is copied to. The copy
// is a one-time act: each copy is a Position of its own, recorded against the same person,
// that names where it came from (PropagationSource) and is never copied further. Unlike a
// scoped decision it may land on a Finding that already has a Position, because the person
// picked that Finding by hand; Positions are append-only, so the earlier one stays in history.

// ErrScopeAndCopy is returned when one decision carries both a propagating scope and copy
// targets: they are two ways to say how wide a decision reaches, and only one may be used.
var ErrScopeAndCopy = errors.New("governance: a decision takes a scope or copy targets, not both")

// LevelVulnerability marks a Finding that shares the CVE but not the component. A decision
// about one component says nothing about another, so such a Finding is listed and never copied to.
const LevelVulnerability RollForwardLevel = "vulnerability"

// CopyLevel is how alike a copy target is to its source: artifact or component when the
// decision can be copied, vulnerability when it cannot.
func CopyLevel(target, source []MatchedComponent) RollForwardLevel {
	if level := RollForwardEligibility(target, source); level != "" {
		return level
	}
	return LevelVulnerability
}

// normalizeCopyTo trims the ids, drops blanks and repeats, and keeps the order given.
func normalizeCopyTo(ids []FindingID) []FindingID {
	var out []FindingID
	seen := map[FindingID]bool{}
	for _, id := range ids {
		id = FindingID(strings.TrimSpace(string(id)))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// CopiedProposalID is the deterministic id of the proposal a copied Position accepts on
// `target`, carrying `source`'s Position `version`: the same triple always folds to the same
// id, so a retried copy establishes nothing twice (ErrDuplicateProposal is the signal).
func CopiedProposalID(target, source FindingID, version int) ProposalID {
	return ProposalID("copied:" + string(target) + ":" + string(source) + ":v" + strconv.Itoa(version))
}

// CopiedRationale is the rationale of a copied Position: the original verbatim, then one line
// naming the source release and Finding, the Position version and how alike the two Findings
// are. sourceLabel is the source release as a person knows it ("<project> <version>"); blank
// falls back to the release id.
func CopiedRationale(source Finding, sourceLabel string, pos Position, level RollForwardLevel) string {
	from := strings.TrimSpace(sourceLabel)
	if from == "" {
		from = "release " + source.ReleaseID()
	}
	suffix := fmt.Sprintf("copied from %s (Finding %s), Position v%d, %s level",
		from, source.ID(), pos.Version(), level)
	if r := strings.TrimSpace(pos.Rationale()); r != "" {
		return r + " — " + suffix
	}
	return suffix
}

// CopyTo returns the Findings the decider asked this decision to be copied to; none on a
// decision taken for its own Finding only.
func (p Position) CopyTo() []FindingID {
	return append([]FindingID(nil), p.inputs.CopyTo...)
}

// IsCopySource reports whether this Position still has copies to make: it names targets and
// was taken directly. A copied Position names none, so a copy is never copied further.
func (p Position) IsCopySource() bool {
	return len(p.inputs.CopyTo) > 0 && p.inputs.PropagatedFrom.IsZero()
}

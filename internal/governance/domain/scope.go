package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Decision scope (EDR-SYNC-01 D1). A person who decides a Finding may say how wide the subject
// of that decision is: this Finding only (the default, and everything before this record), every
// Finding of the same CVE on the releases of the same project, or on the releases of every
// project of the same product. Scope widens the SUBJECT of one person's decision; it adds no
// decider — each Position it produces is recorded against that person, and says where it came
// from (PropagationSource).

// DecisionScope names how wide a decision reaches.
type DecisionScope string

const (
	// ScopeRelease is this Finding only. The empty string means the same, so every decision taken
	// before this record reads as release-scoped without a rewrite.
	ScopeRelease DecisionScope = "release"
	// ScopeProject covers the same CVE on every release of the same project.
	ScopeProject DecisionScope = "project"
	// ScopeProduct covers the same CVE on every release of every project of the same product.
	ScopeProduct DecisionScope = "product"
)

// ErrInvalidScope is returned for a scope outside the closed set.
var ErrInvalidScope = errors.New("governance: decision scope must be release, project or product")

// ParseDecisionScope normalizes a scope from the wire: blank is release; anything outside the
// closed set is refused.
func ParseDecisionScope(s string) (DecisionScope, error) {
	switch sc := DecisionScope(strings.ToLower(strings.TrimSpace(s))); sc {
	case "", ScopeRelease:
		return ScopeRelease, nil
	case ScopeProject, ScopeProduct:
		return sc, nil
	default:
		return "", ErrInvalidScope
	}
}

// Propagates reports whether a decision of this scope reaches other Findings at all.
func (s DecisionScope) Propagates() bool { return s == ScopeProject || s == ScopeProduct }

// Covers reports whether a decision of this scope, taken on a Finding whose release belongs to
// (product, project), reaches a target whose release belongs to (targetProduct, targetProject).
// A blank owner on either side covers nothing: an unresolved identity is not a match.
func (s DecisionScope) Covers(product, project, targetProduct, targetProject string) bool {
	switch s {
	case ScopeProject:
		return project != "" && project == targetProject
	case ScopeProduct:
		return product != "" && product == targetProduct
	default:
		return false
	}
}

// PropagationSource names the Position a propagated Position was applied from (D3): the
// Finding the person decided on, and the version they established there. Zero on a Position a
// person established directly.
type PropagationSource struct {
	FindingID FindingID
	Version   int
}

// IsZero reports whether no source is named (a direct decision).
func (p PropagationSource) IsZero() bool { return p.FindingID == "" && p.Version == 0 }

// ScopedProposalID is the deterministic id of the proposal a propagated Position accepts on
// `target`, carrying `source`'s Position `version`: the same triple always folds to the same id,
// so a re-run establishes nothing twice (ErrDuplicateProposal is the idempotency signal).
func ScopedProposalID(target, source FindingID, version int) ProposalID {
	return ProposalID("scoped:" + string(target) + ":" + string(source) + ":v" + strconv.Itoa(version))
}

// ScopedRationale is the rationale of a propagated Position: the original verbatim, then one
// line naming the scope, the source release and Finding, the Position version and how alike the
// two Findings are (D3, D7) — so the audit reads where this stance came from without a lookup.
func ScopedRationale(source Finding, pos Position, level RollForwardLevel) string {
	suffix := fmt.Sprintf("applied by scope %s from release %s (Finding %s), Position v%d, %s level",
		pos.Scope(), source.ReleaseID(), source.ID(), pos.Version(), level)
	if r := strings.TrimSpace(pos.Rationale()); r != "" {
		return r + " — " + suffix
	}
	return suffix
}

// Scope returns the decision scope this Position was taken with; a Position from before
// EDR-SYNC-01 reads as release-scoped.
func (p Position) Scope() DecisionScope {
	if p.inputs.Scope == "" {
		return ScopeRelease
	}
	return p.inputs.Scope
}

// PropagatedFrom returns the source this Position was applied from, and whether there is one.
func (p Position) PropagatedFrom() (PropagationSource, bool) {
	return p.inputs.PropagatedFrom, !p.inputs.PropagatedFrom.IsZero()
}

// IsScopedSource reports whether this Position is a standing scoped decision other Findings
// may be applied from: taken with a propagating scope, and taken directly (a propagated
// Position follows its source and is never a source itself, so chains cannot form).
func (p Position) IsScopedSource() bool {
	return p.Scope().Propagates() && p.inputs.PropagatedFrom.IsZero()
}

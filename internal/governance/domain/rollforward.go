package domain

import (
	"sort"
	"strings"
)

// Roll-forward (EDR-ROLLFORWARD-01): when a Finding opens and the SAME CVE was already decided
// on another release of the same project, Governance proposes that decision here. It is a
// PROPOSAL a human accepts, never a Position copied — the authority line (EDR-GOVERNANCE-01
// D11) is untouched. This file holds the two pure rules the proposal rests on: WHICH past
// Position is a judgement worth carrying, and WHETHER the two Findings are alike enough for it
// to be carried (the granularity decision, D2/D3).

// RollForwardLevel names how alike the target and the precedent Findings are. The three VAMS
// levels are expressed as rules over the components, without a per-component Position:
//
//   - LevelArtifact: the same carrier builds, purl for purl — the previous release shipped
//     exactly these artifacts and somebody decided about them.
//   - LevelComponent: the same packages at other versions — the decision was about the
//     package and may well hold, but the version moved, so it is a proposal to re-read.
//   - "" (ineligible): only the CVE is shared, or the target has no carrier at all. A
//     vulnerability-level reuse is NOT proposed (D3): a decision taken about one component says
//     nothing about a different one, and a Finding whose every component is scope-class has no
//     subject to take a stance about (EDR-ATTRIBUTION-01 D12 — the CVE-2026-33006 fixture).
type RollForwardLevel string

const (
	LevelArtifact  RollForwardLevel = "artifact"
	LevelComponent RollForwardLevel = "component"
)

// RollForwardEligibility decides whether a Position on `precedent` may be proposed on `target`
// and at which level. Both are read through their ACTIVE carrier components: retired matches
// and scope-class components take no part, because a decision is about what carries the flaw.
func RollForwardEligibility(target, precedent []MatchedComponent) RollForwardLevel {
	t, p := carrierPURLs(target), carrierPURLs(precedent)
	if len(t) == 0 || len(p) == 0 {
		return ""
	}
	if sameSet(t, p) {
		return LevelArtifact
	}
	if sameSet(packageKeys(t), packageKeys(p)) {
		return LevelComponent
	}
	return ""
}

// carrierPURLs lists the distinct PURLs of the components a stance can be about: active, and
// not scope-class (unknown acts as carrier, as everywhere — EDR-CORRELATION-01).
func carrierPURLs(comps []MatchedComponent) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range comps {
		if c.Retired || c.ClaimClass == ClaimScope || strings.TrimSpace(c.PURL) == "" {
			continue
		}
		if !seen[c.PURL] {
			seen[c.PURL] = true
			out = append(out, c.PURL)
		}
	}
	sort.Strings(out)
	return out
}

// packageKeys reduces PURLs to their package identity: everything before the `@version` and any
// qualifiers, so `pkg:rpm/rocky/libtiff@4.0.9-38.el8_10?arch=x86_64` and
// `pkg:rpm/rocky/libtiff@4.0.9-39.el8_10` are the same package.
func packageKeys(purls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range purls {
		k := p
		if i := strings.IndexAny(k, "@?#"); i >= 0 {
			k = k[:i]
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// JudgedPosition returns the current Position when it is a JUDGEMENT — taken by a person or on
// an AI's proposal — and not a rule's verdict: a Position a policy established, or one that
// accepted a system-raised proposal (the version-range verdict, a vendor statement), is
// arithmetic about THIS release's facts and re-derives on its own wherever those facts hold, so
// it is never carried to another release (the AI-RF-4/4b rule, applied here for the same reason).
func (f Finding) JudgedPosition() (Position, bool) {
	pos, ok := f.CurrentPosition()
	if !ok {
		return Position{}, false
	}
	if pos.Actor().Kind == ActorPolicy || pos.Actor().Kind == ActorSystem {
		return Position{}, false
	}
	for _, p := range f.proposals {
		if p.ID() == pos.Inputs().AcceptedProposalID && p.Proposer().Kind == ActorSystem {
			return Position{}, false
		}
	}
	return pos, true
}

// RollForwardProposalID is the deterministic id of the roll-forward proposal on `target` carrying
// `source`'s Position: the same pair always folds to the same id, so a re-run raises nothing new.
func RollForwardProposalID(target, source FindingID) ProposalID {
	return ProposalID("rollforward:" + string(target) + ":" + string(source))
}

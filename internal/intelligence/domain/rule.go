package domain

import (
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

// EngineRule is the deterministic, all-Go rule engine (Revision 3 / Δ2): it settles the
// clear-cut cases from the assembled grounding, with no provider call, so the LLM engine
// runs only when no rule can decide (deterministic-first).
const EngineRule EngineKind = "rule"

// RuleDecision is a deterministic Rule-engine conclusion. It is certain in one direction
// only (a recommendable Stance the rule can be sure of — Δ2: not_affected), and carries
// the rule id + a plain reason + grounded evidence refs (every ref must exist in the
// AssembledContext, exactly as an LLM answer must). A nil decision means "defer".
type RuleDecision struct {
	Stance   Stance
	RuleID   string
	Reason   string
	Evidence []Evidence
}

// AsOutput renders the decision as the same RawOutput shape an LLM answer produces, so a
// rule decision passes the identical stage-2 business validation (finding = subject,
// evidence grounded, stance allowed) and BuildProposal path. A deterministic decision is
// certain, so its confidence is 1.0.
func (d RuleDecision) AsOutput(subjectFindingID string) RawOutput {
	ev := make([]RawEvidence, 0, len(d.Evidence))
	for _, e := range d.Evidence {
		ev = append(ev, RawEvidence(e))
	}
	return RawOutput{
		FindingID:         subjectFindingID,
		RecommendedStance: string(d.Stance),
		Confidence:        1.0,
		Evidence:          ev,
		Reasoning:         d.Reason,
	}
}

// Rule is one deterministic predicate over the assembled grounding. Decide returns a
// decision and true when the rule is certain, or the zero value and false to defer.
type Rule interface {
	ID() string
	Decide(ac AssembledContext) (RuleDecision, bool)
}

// RuleSet is an ordered set of rules evaluated first-decision-wins; if no rule decides,
// it defers (false). Δ2 ships one rule (version-range); the set keeps adding rules
// additive — provided a new rule never duplicates a Governance-owned decision.
type RuleSet []Rule

// Decide returns the first rule's decision, or defers when none is certain.
func (rs RuleSet) Decide(ac AssembledContext) (RuleDecision, bool) {
	for _, r := range rs {
		if d, ok := r.Decide(ac); ok {
			return d, true
		}
	}
	return RuleDecision{}, false
}

// VersionRangeRule decides not_affected when EVERY matched component of the Finding is
// provably outside the Faultline's reconciled affected range (value.RangeOutOfRange).
// It is certain in one direction only: it never decides affected ("in range" is the
// LLM's judgment), and it defers whenever any component is in-range or undecidable, when
// there is no reconciled range, or when a component version cannot be read. Checking the
// reconciled (backport-aware) range — not a feed's query-time filter — is what lets it
// catch a distro backport (upstream flags the version; the distro range excludes the
// build) that discovery could not.
type VersionRangeRule struct{}

// ID is the rule's stable identifier, carried in the decision provenance.
func (VersionRangeRule) ID() string { return "version-range" }

// Decide applies the version-range rule to the assembled grounding.
func (VersionRangeRule) Decide(ac AssembledContext) (RuleDecision, bool) {
	ranges := ac.Faultline.AffectedRanges
	if len(ranges) == 0 || len(ac.Finding.Components) == 0 {
		return RuleDecision{}, false // no reconciled range or no matched component → defer
	}
	for _, purl := range ac.Finding.Components {
		ecosystem, version, ok := parseComponentPURL(purl)
		if !ok || version == "" {
			return RuleDecision{}, false // cannot read a component's version → not certain → defer
		}
		r := value.AffectedRange{Ecosystem: ecosystem, Groups: ranges}
		if r.Applicability(version) != value.RangeOutOfRange {
			return RuleDecision{}, false // in-range or undecidable → defer to the LLM
		}
	}
	// Every matched component is provably outside the reconciled affected range.
	evidence := make([]Evidence, 0, len(ac.Finding.Components)+1)
	for _, purl := range ac.Finding.Components {
		evidence = append(evidence, Evidence{Kind: "component", Ref: purl})
	}
	if ac.Faultline.CVE != "" {
		evidence = append(evidence, Evidence{Kind: "cve", Ref: ac.Faultline.CVE})
	}
	return RuleDecision{
		Stance:   StanceNotAffected,
		RuleID:   "version-range",
		Reason:   "every matched component version is outside the reconciled affected range",
		Evidence: evidence,
	}, true
}

// parseComponentPURL extracts the ecosystem (purl type) and version from a component
// purl such as "pkg:apk/openssl@1.1.1k-r0" — the ecosystem is the type before the first
// "/", the version follows the LAST "@" (npm scoped names %40-encode their "@", so a
// literal "@" unambiguously starts the version), with any ?qualifiers/#subpath stripped.
// ok is false for a non-purl string; version is "" when the purl carries no version.
func parseComponentPURL(purl string) (ecosystem, version string, ok bool) {
	s := strings.TrimSpace(purl)
	if !strings.HasPrefix(s, "pkg:") {
		return "", "", false
	}
	s = s[len("pkg:"):]
	slash := strings.Index(s, "/")
	if slash <= 0 {
		return "", "", false
	}
	ecosystem = s[:slash]
	rest := s[slash+1:]
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return ecosystem, "", true
	}
	return ecosystem, value.StripVersionQualifiers(rest[at+1:]), true
}

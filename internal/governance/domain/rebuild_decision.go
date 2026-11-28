package domain

import (
	"encoding/json"
	"time"
)

// The rebuild decision (EDR-REBUILD-01 D9, D27, D29; step R2 part 2). A trigger of D3 makes
// Governance judge one Release. When the judgement ends in "recommend" or "request", Governance
// records a decision with the facts FROZEN as they were read, and publishes it. The record is
// the audit copy; the event is the transport copy (D29). A decision starts no build: opening a
// cycle and asking a build system is Communication's work in a later step.

// The two triggers of D3.
const (
	// RebuildTriggerNewSBOM: a new SBOM of the Release was judged (release_evaluated, cause new_sbom).
	RebuildTriggerNewSBOM = "new_sbom"
	// RebuildTriggerFixAvailable: a vendor fix is newly on record for open rows of the Release.
	RebuildTriggerFixAvailable = "fix_available"
)

// RebuildTriggerOfEvaluation says whether a finished release evaluation is a rebuild trigger,
// and which. Only a new SBOM is one: a re-discovery never starts a cycle (D3, M2-3).
func RebuildTriggerOfEvaluation(cause string) (trigger string, ok bool) {
	if cause == CauseNewSBOM {
		return RebuildTriggerNewSBOM, true
	}
	return "", false
}

// Why a trigger ended in outcome none.
const (
	// RebuildNoneModeOff: the effective mode of the Release is off (no tag, or a level says off).
	RebuildNoneModeOff = "mode_off"
	// RebuildNoneNothingCounts: the mode allows a rebuild, and no component counts.
	RebuildNoneNothingCounts = "nothing_counts"
	// RebuildNoneGaveUp: the Release could not be judged for RebuildTriggerMaxAge (its owners,
	// tags or fix verdicts could not be read), so the trigger was closed unjudged.
	RebuildNoneGaveUp = "gave_up"
)

// RebuildTriggerMaxAge is how long a trigger that cannot be judged stays open. After it the
// trigger is closed with RebuildNoneGaveUp: a rebuild asked for a day late answers a question
// nobody is asking any more, and the next trigger of the Release judges it afresh.
const RebuildTriggerMaxAge = 24 * time.Hour

// RebuildNoneReason says why a judgement with outcome none asked for nothing.
func RebuildNoneReason(mode RebuildMode) string {
	if mode == RebuildModeAuto || mode == RebuildModeAsk {
		return RebuildNoneNothingCounts
	}
	return RebuildNoneModeOff
}

// RebuildDecisionEntry is one component of one Finding with the facts the decision used (D29,
// D34). The pair (FindingID, PURL) is unique within one list.
type RebuildDecisionEntry struct {
	FindingID      string `json:"finding_id"`
	CVE            string `json:"cve"`
	PURL           string `json:"purl"`
	CurrentVersion string `json:"current_version"`
	// FixedVersions are the vendor bounds the install is below, as Knowledge recorded them.
	// A list, not one value: Governance orders no version strings (D30).
	FixedVersions []string `json:"fixed_versions"`
	// FixSource is "" when no fix is known for the entry (possible only with fix_required off).
	FixSource      string `json:"fix_source"`
	Severity       string `json:"severity"`
	Score          int    `json:"score"`
	ScoreSource    string `json:"score_source"`
	KnownExploited bool   `json:"known_exploited"`
	// ClaimClass is carrier, scope or unknown.
	ClaimClass string `json:"claim_class"`
	// Position is none, or the stance in force.
	Position string `json:"position"`
	// AssessmentState is the state of the component assessment (D35).
	AssessmentState string   `json:"assessment_state"`
	CountedBecause  []string `json:"counted_because"`
}

// RebuildDecisionPolicy is the policy in force as the decision read it: which record, which
// version, and its values. The values are frozen too, so the decision still reads after the
// policy changes.
type RebuildDecisionPolicy struct {
	ScopeKind           string `json:"scope_kind"`
	ScopeID             string `json:"scope_id"`
	Version             int    `json:"version"`
	FixRequired         bool   `json:"fix_required"`
	SeverityFloor       string `json:"severity_floor"`
	CountKnownExploited bool   `json:"count_known_exploited"`
	SkipDecided         bool   `json:"skip_decided"`
	CarrierOnly         bool   `json:"carrier_only"`
	CoolDownSeconds     int64  `json:"cool_down_seconds"`
	Mode                string `json:"mode"`
}

// Why a decision is a recommendation and not a request (D5, D10 item 6).
const (
	// RebuildRecommendModeAsk: the effective mode of the Release is ask, so a person decides.
	RebuildRecommendModeAsk = "mode_ask"
	// RebuildRecommendNoBuildProfile: no build profile applies to the Release, own or
	// inherited, so no build could be asked for whatever the mode. No profile, no request.
	RebuildRecommendNoBuildProfile = "no_build_profile"
)

// RebuildOutcomeWithProfile applies "no profile, no request" (D10 item 6) to the outcome the
// mode gives. A request with no build profile becomes a recommendation that says so; a
// recommendation says whether the mode or the missing profile holds it. An outcome of none is
// returned as it is.
func RebuildOutcomeWithProfile(outcome string, profileFound bool) (out, recommendReason string) {
	switch {
	case outcome != RebuildOutcomeRequest && outcome != RebuildOutcomeRecommend:
		return outcome, ""
	case !profileFound:
		return RebuildOutcomeRecommend, RebuildRecommendNoBuildProfile
	case outcome == RebuildOutcomeRecommend:
		return RebuildOutcomeRecommend, RebuildRecommendModeAsk
	default:
		return RebuildOutcomeRequest, ""
	}
}

// RebuildDecisionBuildProfile names the build profile a decision used (D16): where it is
// stored (project or release), its revision there, and the digest of its stored bytes.
type RebuildDecisionBuildProfile struct {
	Scope    string `json:"scope"`
	Revision int    `json:"revision"`
	SHA256   string `json:"sha256"`
}

// RebuildDecision is one recorded decision and the payload of
// governance.rebuild_recommended.v1 (outcome recommend) and governance.rebuild_requested.v1
// (outcome request). Its DecisionID is the identity of a recommendation (D27).
type RebuildDecision struct {
	DecisionID string `json:"decision_id"`
	ReleaseID  string `json:"release_id"`
	ProductID  string `json:"product_id"`
	ProjectID  string `json:"project_id"`
	// TriggerID with TriggerSource names the event that caused the judgement, so a redelivered
	// event is the same trigger (D27). TriggerType is one of the RebuildTrigger* names.
	TriggerID     string `json:"trigger_id"`
	TriggerSource string `json:"trigger_source"`
	TriggerType   string `json:"trigger_type"`
	// Outcome is recommend or request. A judgement with outcome none records no decision.
	Outcome string `json:"outcome"`
	// RecommendReason says why the outcome is recommend (RebuildRecommend*); "" on a request.
	RecommendReason string `json:"recommend_reason,omitempty"`
	// Build is the build profile that applies to the Release, copied and frozen here (D10 item
	// 7). Themis does not read inside it. Absent when no profile applies. It is the same JSON
	// value Registry stores; a JSON store may reorder its keys, so BuildProfile.SHA256 names
	// the stored revision and is not a digest of these bytes.
	Build json.RawMessage `json:"build,omitempty"`
	// BuildProfile names that profile (D16). Nil exactly when Build is absent.
	BuildProfile *RebuildDecisionBuildProfile `json:"build_profile,omitempty"`
	// EffectiveMode is D17 whole, and EffectiveModeSetBy the value that set it.
	EffectiveMode      string `json:"effective_mode"`
	EffectiveModeSetBy string `json:"effective_mode_set_by"`
	InstallationMode   string `json:"installation_mode"`
	// Tag is the rebuild tag that applies ("" when none) and TagLevel where it was read.
	Tag      string                `json:"tag"`
	TagLevel string                `json:"tag_level"`
	Policy   RebuildDecisionPolicy `json:"policy"`
	// Considered counts the open component occurrences the policy looked at; Skipped says how
	// many did not count, by reason.
	Considered int            `json:"considered"`
	Skipped    map[string]int `json:"skipped"`
	// Targeted are the components the rebuild is asked for. Never empty.
	Targeted []RebuildDecisionEntry `json:"targeted"`
	// OtherStream are the components whose fix exists only in another module stream. They are
	// not part of the ask; they are carried so that a person can act on them.
	OtherStream []RebuildDecisionEntry `json:"other_stream"`
	DecidedAt   time.Time              `json:"decided_at"`
}

// RebuildClaimClassName is D34's claim class: carrier, scope, and unknown for everything else
// (an empty or unreadable class acts as carrier and is said to be unknown).
func RebuildClaimClassName(class string) string {
	switch class {
	case "carrier", ClaimScope:
		return class
	default:
		return "unknown"
	}
}

// RebuildPositionName is D34's position: none, or the stance in force.
func RebuildPositionName(s Stance) string {
	if s == "" {
		return "none"
	}
	return string(s)
}

package domain

import (
	"sort"
	"time"
)

// The rebuild recommendation (EDR-REBUILD-01 D15, D26, D27, D41, D44 to D46; step R4). A
// recommendation is a rebuild decision with outcome recommend, and its decision id is its
// identity (D27). A Release has at most one standing recommendation. Only a person approves
// one, and an approval is what publishes the request in mode ask.

// The states of a recommendation (D44). Every state except standing is final.
const (
	// RebuildRecStanding: the one open recommendation of the Release. Only it can be approved.
	RebuildRecStanding = "standing"
	// RebuildRecApproved: a person approved it and the request was published.
	RebuildRecApproved = "approved"
	// RebuildRecSuperseded: a later trigger gave a different result.
	RebuildRecSuperseded = "superseded"
	// RebuildRecExpired: RebuildRecommendationTTL passed with no answer.
	RebuildRecExpired = "expired"
	// RebuildRecWithdrawn: a later trigger found nothing to ask for, or the mode is no longer ask.
	RebuildRecWithdrawn = "withdrawn"
)

// RebuildRecommendationTTL is how long a recommendation waits for an answer (D15 item 4).
const RebuildRecommendationTTL = 7 * 24 * time.Hour

// RebuildApprovedHold is how long an approved recommendation keeps new recommendations of its
// Release back while Governance has not heard that the rebuild cycle closed (D44 item 7). The
// hold ends early with the closure. It has an end of its own because a request can be held or
// refused on the way and then no cycle ever closes; a recommendation made after the hold joins
// a cycle that is still open, so the bound costs a notice and never a second build.
const RebuildApprovedHold = 24 * time.Hour

// RebuildOutcomeUnchanged closes a trigger whose result equals the standing recommendation
// (D41 item 2). It records no decision and tells nobody.
const RebuildOutcomeUnchanged = "unchanged"

// RebuildNoneCycleOpen: a recommendation of the Release was approved and its cycle is not known
// to be closed, so no new recommendation is made now (D44 item 7). The Release is judged again
// when the cycle closes.
const RebuildNoneCycleOpen = "cycle_open"

// RebuildTriggerModeChanged: an approval found that the effective mode is no longer ask, so
// the recommendation was withdrawn and the Release is judged again (D45 item 2).
const RebuildTriggerModeChanged = "mode_changed"

// RebuildRecommendationExpired says whether a recommendation decided at decidedAt is past its
// time at now (D44 item 1: by the clock, whether or not anything has marked it yet).
func RebuildRecommendationExpired(decidedAt, now time.Time) bool {
	return !now.Before(decidedAt.Add(RebuildRecommendationTTL))
}

// RebuildApprovedHolds says whether an approval made at approvedAt still keeps new
// recommendations back at now.
func RebuildApprovedHolds(approvedAt, now time.Time) bool {
	return now.Before(approvedAt.Add(RebuildApprovedHold))
}

// SameRebuildRecommendation says whether b asks a person for the same thing as a (D41 item 2):
// the same targeted components, the same policy record and version, the same build profile
// revision, and the same reason for being a recommendation.
func SameRebuildRecommendation(a, b RebuildDecision) bool {
	if a.Policy.ScopeKind != b.Policy.ScopeKind || a.Policy.ScopeID != b.Policy.ScopeID ||
		a.Policy.Version != b.Policy.Version || a.RecommendReason != b.RecommendReason {
		return false
	}
	if (a.BuildProfile == nil) != (b.BuildProfile == nil) {
		return false
	}
	if a.BuildProfile != nil && *a.BuildProfile != *b.BuildProfile {
		return false
	}
	ta, tb := rebuildTargetKeys(a.Targeted), rebuildTargetKeys(b.Targeted)
	if len(ta) != len(tb) {
		return false
	}
	for i := range ta {
		if ta[i] != tb[i] {
			return false
		}
	}
	return true
}

func rebuildTargetKeys(entries []RebuildDecisionEntry) []string {
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.FindingID+"\x00"+e.PURL)
	}
	sort.Strings(keys)
	return keys
}

// RebuildPolicyVersions are the versions of the three policy records that can apply to one
// Release, as one reader saw them. 0 means that no record is stored at that level.
type RebuildPolicyVersions struct {
	Installation int `json:"installation"`
	Product      int `json:"product"`
	Release      int `json:"release"`
}

// RebuildApproval is what an approval records (D15, D22, D46): who, with which key, when, and
// the inputs of the effective mode it rested on.
type RebuildApproval struct {
	Actor string `json:"actor"`
	// KeyName and KeyScopes name the API key that carried the approval. A key is a credential,
	// not a person; they are recorded so that an approval by a build job's key is visible.
	KeyName    string    `json:"key_name"`
	KeyScopes  []string  `json:"key_scopes"`
	ApprovedAt time.Time `json:"approved_at"`
	// PolicyVersions were checked under the lock that blocks a policy write (D46 item 3).
	PolicyVersions RebuildPolicyVersions `json:"policy_versions"`
	// Tag and TagLevel are the rebuild tag read fresh from Registry at TagsReadAt (D46 item 8).
	Tag        string    `json:"tag"`
	TagLevel   string    `json:"tag_level"`
	TagsReadAt time.Time `json:"tags_read_at"`
}

// RebuildRecommendationExpiredEvent is the payload of
// governance.rebuild_recommendation_expired.v1 (D26). It starts nothing.
type RebuildRecommendationExpiredEvent struct {
	DecisionID    string    `json:"decision_id"`
	ReleaseID     string    `json:"release_id"`
	ProductID     string    `json:"product_id"`
	ProjectID     string    `json:"project_id"`
	TargetedCount int       `json:"targeted_count"`
	DecidedAt     time.Time `json:"decided_at"`
	ExpiredAt     time.Time `json:"expired_at"`
}

// NewRebuildRecommendationExpired builds the event for a recommendation that ran out at at.
func NewRebuildRecommendationExpired(d RebuildDecision, at time.Time) RebuildRecommendationExpiredEvent {
	return RebuildRecommendationExpiredEvent{
		DecisionID: d.DecisionID, ReleaseID: d.ReleaseID, ProductID: d.ProductID, ProjectID: d.ProjectID,
		TargetedCount: len(d.Targeted), DecidedAt: d.DecidedAt, ExpiredAt: at,
	}
}

// ApprovedRebuildRequest turns an approved recommendation into the request that is published
// (D27 item 3): the same decision id and the same frozen facts, outcome request, and the
// approval. Nothing is evaluated again (D46 item 10).
func ApprovedRebuildRequest(d RebuildDecision, a RebuildApproval) RebuildDecision {
	d.Outcome, d.RecommendReason = RebuildOutcomeRequest, ""
	d.Approval = &a
	return d
}

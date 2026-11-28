package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The approval of a rebuild recommendation and its expiry (EDR-REBUILD-01 D15, D22, D26, D32,
// D41, D44 to D46; step R4). In mode ask a trigger ends in a recommendation and nothing is
// asked of a build system until a person approves it. The approval publishes the request with
// the facts the recommendation froze; nothing is evaluated again in between.

// What an approval call ended in.
const (
	// RebuildApprovalApproved: the recommendation is approved and the request is published.
	RebuildApprovalApproved = "approved"
	// RebuildApprovalNotStanding: the decision is not the standing recommendation of its
	// Release (superseded, approved before, withdrawn, or expired earlier).
	RebuildApprovalNotStanding = "not_standing"
	// RebuildApprovalExpired: it was past its time; this call or an earlier one recorded so.
	RebuildApprovalExpired = "expired"
	// RebuildApprovalWithdrawn: the effective mode is no longer ask. The recommendation was
	// withdrawn and the Release is judged again; this call started no build (D45 item 2).
	RebuildApprovalWithdrawn = "withdrawn"
	// RebuildApprovalNoBuildProfile: no build profile applies to the Release, so there is
	// nothing a build system could be asked (D10 item 6). The recommendation stays standing.
	RebuildApprovalNoBuildProfile = "no_build_profile"
)

var (
	// ErrRebuildRecommendationNotFound: no recommendation has this decision id.
	ErrRebuildRecommendationNotFound = errors.New("governance: no rebuild recommendation with this decision id")
	// ErrRebuildApprovalActorRequired: an approval names the person who gives it (D22).
	ErrRebuildApprovalActorRequired = errors.New("governance: a rebuild approval needs a named actor")
	// ErrRebuildModeUnread: the effective mode could not be established (Registry or the policy
	// store did not answer). The approval is refused and the recommendation stays standing: this
	// read authorizes a build, so it fails closed (D46 item 7).
	ErrRebuildModeUnread = errors.New("governance: the rebuild mode of this release could not be read, so the approval was refused")
	// ErrRebuildApprovalBusy: the rebuild policy kept changing under the approval. Nothing was
	// written; the caller may try again.
	ErrRebuildApprovalBusy = errors.New("governance: the rebuild policy changed during the approval; try again")
	// ErrRebuildApprovalUnavailable is returned when the approval is not wired.
	ErrRebuildApprovalUnavailable = errors.New("governance: rebuild approval not configured")
)

// rebuildApprovalTries bounds how often an approval starts over because a policy changed
// between its read and its write.
const rebuildApprovalTries = 3

// RebuildApprovalKey names the API key that carried an approval.
type RebuildApprovalKey struct {
	Name   string
	Scopes []string
}

// RebuildApprovalWrite is one conditional write of an approval (D45 item 1, D46).
type RebuildApprovalWrite struct {
	Decision domain.RebuildDecision
	Now      time.Time
	// Expected are the policy versions the mode was computed from. The store reads them again
	// under a lock that blocks every policy write, and writes nothing when they differ.
	Expected domain.RebuildPolicyVersions
	// Approve is true when the effective mode is ask. False withdraws the recommendation and
	// records the trigger TriggerID (D45 item 2).
	Approve   bool
	Approval  domain.RebuildApproval
	Request   OutboxNote
	Expired   OutboxNote
	TriggerID string
}

// What the store did with a RebuildApprovalWrite.
const (
	RebuildApprovalWritePolicyChanged = "policy_changed"
)

// RebuildApprovalStore is the persistence seam of the approval and of the expiry sweep.
type RebuildApprovalStore interface {
	// RebuildRecommendation reads one recommendation by its decision id.
	RebuildRecommendation(ctx context.Context, decisionID string) (RebuildRecommendation, bool, error)
	// LatestRebuildRecommendation reads the newest recommendation of a Release, in any state.
	LatestRebuildRecommendation(ctx context.Context, releaseID string) (RebuildRecommendation, bool, error)
	RebuildRecommendationStatus(ctx context.Context, releaseID string) (RebuildRecommendationStatus, error)
	// ApproveRebuildRecommendation does, in ONE transaction and in this order: take the lock
	// that blocks policy writes; compare the policy versions (differ: nothing is written,
	// RebuildApprovalWritePolicyChanged); expire a recommendation past its time, with the Expired
	// note (RebuildApprovalExpired); then move standing to approved with the Request note, or
	// to withdrawn with the trigger. A recommendation that is not standing is left alone
	// (RebuildApprovalNotStanding).
	ApproveRebuildRecommendation(ctx context.Context, in RebuildApprovalWrite) (result string, err error)
	// StandingRebuildRecommendationsBefore lists standing recommendations decided at or before
	// the given time, oldest first, bounded.
	StandingRebuildRecommendationsBefore(ctx context.Context, before time.Time, limit int) ([]RebuildRecommendation, error)
	ExpireRebuildRecommendation(ctx context.Context, decisionID string, at time.Time, note OutboxNote) (moved bool, err error)
}

// RebuildApprovalAnswer is what an approval call says.
type RebuildApprovalAnswer struct {
	// Result is one of RebuildApproval*.
	Result     string
	DecisionID string
	ReleaseID  string
	// State is the state of the recommendation after the call.
	State string
	// StandingID is the decision id of the recommendation that is standing for the Release
	// now, "" when none is (D41 item 4).
	StandingID string
	// EffectiveMode is the mode in force, set when the call read it.
	EffectiveMode string
}

// RebuildApprovalService approves recommendations.
type RebuildApprovalService struct {
	store  RebuildApprovalStore
	policy *RebuildPolicyService
	ids    IDGenerator
	clock  Clock
}

// NewRebuildApprovalService wires the service.
func NewRebuildApprovalService(store RebuildApprovalStore, policy *RebuildPolicyService, ids IDGenerator, clock Clock) *RebuildApprovalService {
	return &RebuildApprovalService{store: store, policy: policy, ids: ids, clock: clock}
}

// Recommendation reads one recommendation.
func (s *RebuildApprovalService) Recommendation(ctx context.Context, decisionID string) (RebuildRecommendation, error) {
	if s == nil || s.store == nil {
		return RebuildRecommendation{}, ErrRebuildApprovalUnavailable
	}
	rec, found, err := s.store.RebuildRecommendation(ctx, strings.TrimSpace(decisionID))
	if err != nil {
		return RebuildRecommendation{}, err
	}
	if !found {
		return RebuildRecommendation{}, ErrRebuildRecommendationNotFound
	}
	return rec, nil
}

// Latest reads the newest recommendation of a Release.
func (s *RebuildApprovalService) Latest(ctx context.Context, releaseID string) (RebuildRecommendation, error) {
	if s == nil || s.store == nil {
		return RebuildRecommendation{}, ErrRebuildApprovalUnavailable
	}
	rec, found, err := s.store.LatestRebuildRecommendation(ctx, strings.TrimSpace(releaseID))
	if err != nil {
		return RebuildRecommendation{}, err
	}
	if !found {
		return RebuildRecommendation{}, ErrRebuildRecommendationNotFound
	}
	return rec, nil
}

// Now is the service's clock, for a reader that shows how long a recommendation still waits.
func (s *RebuildApprovalService) Now() time.Time { return s.clock.Now().UTC() }

// Approve is the "start rebuild" action of mode ask. It never evaluates the policy rules and
// never builds: it publishes the request the recommendation froze, or it says why not.
func (s *RebuildApprovalService) Approve(ctx context.Context, decisionID, actor string, key RebuildApprovalKey) (RebuildApprovalAnswer, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return RebuildApprovalAnswer{}, ErrRebuildApprovalActorRequired
	}
	rec, err := s.Recommendation(ctx, decisionID)
	if err != nil {
		return RebuildApprovalAnswer{}, err
	}
	d := rec.Decision
	ans := RebuildApprovalAnswer{DecisionID: d.DecisionID, ReleaseID: d.ReleaseID, State: rec.State}
	if rec.State != domain.RebuildRecStanding {
		return s.notStanding(ctx, ans)
	}
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	expired := OutboxNote{EventType: EventRebuildRecommendationExpired, OccurredAt: now,
		Event: domain.NewRebuildRecommendationExpired(d, now)}
	// Expiry comes first, whatever the mode is now (D46 item 1).
	if domain.RebuildRecommendationExpired(d.DecidedAt, now) {
		if _, err := s.store.ExpireRebuildRecommendation(ctx, d.DecisionID, now, expired); err != nil {
			return RebuildApprovalAnswer{}, err
		}
		ans.Result, ans.State = RebuildApprovalExpired, domain.RebuildRecExpired
		return ans, nil
	}
	if d.RecommendReason == domain.RebuildRecommendNoBuildProfile {
		ans.Result, ans.StandingID = RebuildApprovalNoBuildProfile, d.DecisionID
		return ans, nil
	}
	for try := 0; try < rebuildApprovalTries; try++ {
		// The tags are read fresh from Registry on every try, and an unread mode refuses.
		pol, err := s.policy.InForce(ctx, d.ReleaseID)
		if err != nil || !pol.TagsApplied {
			return RebuildApprovalAnswer{}, ErrRebuildModeUnread
		}
		ans.EffectiveMode = string(pol.EffectiveMode)
		approval := domain.RebuildApproval{
			Actor: actor, KeyName: key.Name, KeyScopes: append([]string{}, key.Scopes...), ApprovedAt: now,
			PolicyVersions: pol.Versions, Tag: pol.Tag.Tag, TagLevel: pol.Tag.Level, TagsReadAt: now,
		}
		result, err := s.store.ApproveRebuildRecommendation(ctx, RebuildApprovalWrite{
			Decision: d, Now: now, Expected: pol.Versions,
			Approve: pol.EffectiveMode == domain.RebuildModeAsk, Approval: approval,
			Request: OutboxNote{EventType: EventRebuildRequested, OccurredAt: now,
				Event: domain.ApprovedRebuildRequest(d, approval)},
			Expired: expired, TriggerID: s.ids.NewID(),
		})
		if err != nil {
			return RebuildApprovalAnswer{}, err
		}
		switch result {
		case RebuildApprovalWritePolicyChanged:
			continue
		case RebuildApprovalNotStanding:
			return s.notStanding(ctx, ans)
		case RebuildApprovalApproved:
			ans.State = domain.RebuildRecApproved
		case RebuildApprovalWithdrawn:
			ans.State = domain.RebuildRecWithdrawn
		default:
			ans.State = domain.RebuildRecExpired
		}
		ans.Result = result
		return ans, nil
	}
	return RebuildApprovalAnswer{}, ErrRebuildApprovalBusy
}

// notStanding answers a refused approval with the recommendation that is standing now.
func (s *RebuildApprovalService) notStanding(ctx context.Context, ans RebuildApprovalAnswer) (RebuildApprovalAnswer, error) {
	status, err := s.store.RebuildRecommendationStatus(ctx, ans.ReleaseID)
	if err != nil {
		return RebuildApprovalAnswer{}, err
	}
	if st := status.Standing; st != nil && !domain.RebuildRecommendationExpired(st.Decision.DecidedAt, s.clock.Now().UTC()) {
		ans.StandingID = st.Decision.DecisionID
	}
	if cur, found, err := s.store.RebuildRecommendation(ctx, ans.DecisionID); err == nil && found {
		ans.State = cur.State
	}
	ans.Result = RebuildApprovalNotStanding
	return ans, nil
}

// rebuildExpiryBatch bounds one pass of the expiry sweep.
const rebuildExpiryBatch = 100

// RebuildExpirySweep finds recommendations past their time and records the expiry once, with
// its event (D32). It evaluates nothing, approves nothing and builds nothing.
type RebuildExpirySweep struct {
	store RebuildApprovalStore
	clock Clock
}

// NewRebuildExpirySweep wires the sweep.
func NewRebuildExpirySweep(store RebuildApprovalStore, clock Clock) *RebuildExpirySweep {
	return &RebuildExpirySweep{store: store, clock: clock}
}

// Tick performs one pass and reports how many recommendations it expired.
func (s *RebuildExpirySweep) Tick(ctx context.Context) (expired int, err error) {
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	recs, err := s.store.StandingRebuildRecommendationsBefore(ctx, now.Add(-domain.RebuildRecommendationTTL), rebuildExpiryBatch)
	if err != nil {
		return 0, err
	}
	for _, rec := range recs {
		moved, err := expireRebuildRecommendation(ctx, s.store, rec, now)
		if err != nil {
			return expired, err
		}
		if moved {
			expired++
		}
	}
	return expired, nil
}

// RunEvery sweeps on a cadence until ctx is cancelled. report may be nil.
func (s *RebuildExpirySweep) RunEvery(ctx context.Context, every time.Duration, report func(expired int, err error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.Tick(ctx)
			if report != nil {
				report(n, err)
			}
		}
	}
}

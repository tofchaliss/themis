package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// Communication acts on Governance's rebuild decision (EDR-REBUILD-01 step R3). Governance
// decides WHETHER a Release should be rebuilt (D9); this file keeps what follows: one open cycle
// per Release (D13), the cool-down (D14), one request per attempt and try (D23, D40), and what
// the connector and a person say about a request (D20, D24, D25, D28). Nothing here touches a
// Finding. A request is a request and never a command (D6).

// Where a cycle comes from.
const (
	// CycleOriginEvaluation: the posture of a new SBOM opened it (M2-8). The value of every
	// cycle made before step R3.
	CycleOriginEvaluation = "evaluation"
	// CycleOriginDecision: a rebuild decision of Governance opened it.
	CycleOriginDecision = "decision"
)

// The two values of THEMIS_COMMUNICATION_REBUILD_OPEN_FROM: what opens a cycle.
const (
	RebuildOpenFromEvaluation = CycleOriginEvaluation
	RebuildOpenFromDecision   = CycleOriginDecision
)

// Cycle states added by step R3.
const (
	// CycleRefused: the connector refused MaxRefusalsPerCycle times (D20 item 4).
	CycleRefused = "refused"
	// CycleStopped: a person stopped the cycle.
	CycleStopped = "stopped"
)

// The states of one request, in the words of D25. RequestNotSubmitted is a person's answer to
// an uncertain request (D24).
const (
	RequestRequested     = "requested"
	RequestDelivered     = "delivered"
	RequestSubmitted     = "submitted"
	RequestRefused       = "refused"
	RequestUncertain     = "uncertain"
	RequestNotSubmitted  = "not_submitted"
	RequestBuildReported = "build_reported"
	RequestEvaluated     = "evaluated"
)

// How a request leaves Themis.
const (
	// ChannelWebhook: the signed rebuild_requested event to a connector (D6).
	ChannelWebhook = "webhook"
	// ChannelJenkins: the built-in Jenkins sender (D43).
	ChannelJenkins = "jenkins"
	// ChannelUnsigned: a rebuild_requested route is set and its audience has no signing secret.
	// Nothing is sent on it (D6).
	ChannelUnsigned = "unsigned"
)

// Why a decision opened no cycle.
const (
	HoldCoolDown      = "cool_down"
	HoldUnsignedRoute = "unsigned_route"
)

// What a decision led to.
const (
	DecisionIgnored = "ignored" // this node opens cycles from the posture, or the decision names nothing
	DecisionJoined  = "joined"  // a cycle is open; the decision joined it (D13)
	DecisionHeld    = "held"    // no cycle: the cool-down or an unsigned route
	DecisionOpened  = "opened"  // a cycle opened and the first request was made
)

// The kinds of notice a person gets about a request.
const (
	NoticeRefused      = "refused"
	NoticeCycleRefused = "cycle_refused"
	NoticeUncertain    = "uncertain"
)

const (
	// MaxRefusalsPerCycle is D20's limit: after it the cycle stops as refused.
	MaxRefusalsPerCycle = 3
	// SilentRequestLimit is D28 item 3: a delivered request with no status call and no build
	// callback after this time is shown as uncertain.
	SilentRequestLimit = 24 * time.Hour
	// silentReason is recorded on a request the sweep turned uncertain.
	silentReason = "no status call and no build callback within 24 hours"
)

var (
	// ErrRebuildRequestsUnavailable — this node keeps no rebuild requests (outward delivery is off).
	ErrRebuildRequestsUnavailable = errors.New("rebuild requests are not kept on this node (outward delivery is off)")
	// ErrRebuildRequestNotFound — no request carries that intent id.
	ErrRebuildRequestNotFound = errors.New("rebuild request not found")
	// ErrStatusIncomplete — a status call names no intent.
	ErrStatusIncomplete = errors.New("rebuild status incomplete: intent_id is required")
	// ErrStatusUnknown — the status is not one of submitted, refused, uncertain.
	ErrStatusUnknown = errors.New("rebuild status must be submitted, refused or uncertain")
	// ErrStatusConflict — the request is past the point where this status can apply.
	ErrStatusConflict = errors.New("rebuild status does not apply to the request in its present state")
	// ErrActorRequired — a person's action names no person (D22, D24).
	ErrActorRequired = errors.New("a named actor is required")
	// ErrSettleAnswer — the answer is not submitted or not_submitted.
	ErrSettleAnswer = errors.New("the answer must be submitted or not_submitted")
	// ErrNotUncertain — only an uncertain request can be settled.
	ErrNotUncertain = errors.New("only an uncertain rebuild request can be settled")
	// ErrNoOpenCycle — the Release has no open cycle.
	ErrNoOpenCycle = errors.New("the release has no open rebuild cycle")
	// ErrRequestInFlight — the last request is still open, so no new one is made.
	ErrRequestInFlight = errors.New("the last rebuild request of the cycle is still open")
	// ErrRebuildHeld — no request can be sent: the route has no signing secret.
	ErrRebuildHeld = errors.New("no rebuild request can be sent: the rebuild_requested route has no signing secret")
)

// RebuildRequest is one request of a decision cycle: one intent, one attempt number, one try
// number. It is evidence about a request and changes no Finding.
type RebuildRequest struct {
	IntentID   string
	CycleID    int64
	ReleaseID  string
	DecisionID string
	Attempt    int
	Try        int
	Channel    string
	State      string
	// Reason is what the connector said with a refusal or an uncertain answer, or the sweep's text.
	Reason string
	// BuildRef is the identity the build system gave at submitted (D38 item 5).
	BuildRef           string
	ExecutionStartedAt time.Time
	RequestedAt        time.Time
	DeliveredAt        time.Time
	StatusAt           time.Time
	ReportedBy         string
	SettledAnswer      string
	SettledBy          string
	SettledAt          time.Time
	SettleNote         string
}

// RebuildHold records a decision that opened no cycle, and why (D14 item 5).
type RebuildHold struct {
	ReleaseID  string
	DecisionID string
	Reason     string
	Until      time.Time // zero when the hold has no end of its own
	RecordedAt time.Time
}

// RebuildRequests is the store port for requests, holds and the last evaluated SBOM.
type RebuildRequests interface {
	// CreateRequest stores a request. A second call with the same intent id stores nothing.
	CreateRequest(ctx context.Context, r RebuildRequest) error
	// RequestByIntent returns one request, or ErrRebuildRequestNotFound.
	RequestByIntent(ctx context.Context, intentID string) (RebuildRequest, error)
	// LatestRequest returns the newest request of a cycle (highest attempt, then try).
	LatestRequest(ctx context.Context, cycleID int64) (RebuildRequest, bool, error)
	// ListRequests returns a cycle's requests, oldest first.
	ListRequests(ctx context.Context, cycleID int64) ([]RebuildRequest, error)
	// UpdateRequest persists the mutable half of a request.
	UpdateRequest(ctx context.Context, r RebuildRequest) error
	// LastDeliveredAt is when a request of the Release was last delivered (D14).
	LastDeliveredAt(ctx context.Context, releaseID string) (time.Time, bool, error)
	// SilentRequests returns webhook requests still `delivered` since before the given time.
	SilentRequests(ctx context.Context, before time.Time) ([]RebuildRequest, error)
	SaveHold(ctx context.Context, h RebuildHold) error
	ClearHold(ctx context.Context, releaseID string) error
	Hold(ctx context.Context, releaseID string) (RebuildHold, bool, error)
	// SaveLastSBOM records the SBOM evaluated last for a Release; LastSBOM reads it ("" = none).
	SaveLastSBOM(ctx context.Context, releaseID, sbomID string, at time.Time) error
	LastSBOM(ctx context.Context, releaseID string) (string, error)
}

// CycleClosedNotifier is told when a cycle closes with decisions that joined it, so that the
// policy is evaluated once more for the Release (D21).
type CycleClosedNotifier interface {
	CycleClosed(ctx context.Context, c RebuildCycle) error
}

// EventRebuildCycleClosed is the fact Communication publishes for Governance when a cycle
// closes with decisions that joined it (D21).
const EventRebuildCycleClosed = "communication.rebuild_cycle_closed"

// RebuildCycleClosed is the payload of communication.rebuild_cycle_closed.v1.
type RebuildCycleClosed struct {
	CycleID    int64     `json:"cycle_id"`
	ReleaseID  string    `json:"release_id"`
	ProductID  string    `json:"product_id"`
	ProjectID  string    `json:"project_id"`
	Origin     string    `json:"origin"`
	State      string    `json:"state"`
	DecisionID string    `json:"decision_id"`
	Joined     []string  `json:"joined_decision_ids"`
	ClosedAt   time.Time `json:"closed_at"`
}

// CycleClosedEvent builds the event for a closed cycle.
func CycleClosedEvent(c RebuildCycle) RebuildCycleClosed {
	origin := c.Origin
	if origin == "" {
		origin = CycleOriginEvaluation
	}
	return RebuildCycleClosed{CycleID: c.ID, ReleaseID: c.ReleaseID, ProductID: c.ProductID, ProjectID: c.ProjectID,
		Origin: origin, State: c.State, DecisionID: c.DecisionID, Joined: append([]string{}, c.Joined...), ClosedAt: c.UpdatedAt.UTC()}
}

// RebuildDecisionFacts is what the loop reads from governance.rebuild_requested.v1. Raw is the
// whole decision as it arrived; the request payload is built from it (D36).
type RebuildDecisionFacts struct {
	DecisionID  string
	ReleaseID   string
	ProductID   string
	ProjectID   string
	TriggerType string
	CoolDown    time.Duration
	CVEs        []string
	Raw         []byte
}

// DecisionOutcome is what one decision led to.
type DecisionOutcome struct {
	State      string
	HoldReason string
	Cycle      RebuildCycle
	// Requested says whether a request was made for this decision.
	Requested bool
}

// RebuildStatus is the connector's status call for one request (D28 item 2).
type RebuildStatus struct {
	IntentID         string
	Status           string
	Reason           string
	BuildRef         string
	ExecutionStarted bool
	ReportedBy       string
}

// RebuildView is what a person is shown for one Release: its newest cycle, that cycle's
// requests, and a decision that is held back.
type RebuildView struct {
	Cycle    *RebuildCycle
	Requests []RebuildRequest
	Hold     *RebuildHold
}

// WithDecisions lets the loop act on rebuild decisions and keep requests. openFrom is
// RebuildOpenFromDecision or RebuildOpenFromEvaluation; anything else is evaluation, the rule
// before step R3.
func (l *RebuildLoop) WithDecisions(requests RebuildRequests, openFrom string) *RebuildLoop {
	l.requests = requests
	l.openFrom = RebuildOpenFromEvaluation
	if strings.TrimSpace(openFrom) == RebuildOpenFromDecision {
		l.openFrom = RebuildOpenFromDecision
	}
	return l
}

// WithCycleClosed attaches what is told when a cycle closes (D21).
func (l *RebuildLoop) WithCycleClosed(n CycleClosedNotifier) *RebuildLoop {
	l.closed = n
	return l
}

// OpensFromDecision reports whether a decision, and not the posture, opens a cycle here.
func (l *RebuildLoop) OpensFromDecision() bool {
	return l.requests != nil && l.openFrom == RebuildOpenFromDecision
}

// cycleClosed tells the notifier about a cycle that is no longer open, when a decision joined
// it while it was open. D21 evaluates the policy again so that what qualified in the meantime
// is not lost. A cycle nobody joined has nothing waiting: evaluating again would only ask once
// more for the set this cycle could not close, without end.
func (l *RebuildLoop) cycleClosed(ctx context.Context, c RebuildCycle) error {
	// A cycle opened from a decision always says that it closed: Governance holds new
	// recommendations back until then (D44 item 7). A cycle opened from a posture says so only
	// when decisions joined it.
	if l.closed == nil || c.State == CycleOpen || (len(c.Joined) == 0 && c.Origin != CycleOriginDecision) {
		return nil
	}
	return l.closed.CycleClosed(ctx, c)
}

// attemptHeld reports whether a request holds its attempt: reserved (delivered, uncertain) or
// used (submitted, build_reported). D28.
func attemptHeld(state string) bool {
	switch state {
	case RequestDelivered, RequestSubmitted, RequestUncertain, RequestBuildReported:
		return true
	}
	return false
}

// attemptGivenBack reports whether a request gave its attempt back, so that the same attempt
// may be asked for again with the next try number (D20, D24, D40).
func attemptGivenBack(state string) bool {
	return state == RequestRefused || state == RequestNotSubmitted
}

// Request acts on one rebuild decision of Governance. It joins an open cycle, or holds the
// decision back, or opens a cycle and makes its first request. It runs inside the caller's unit
// of work, so the cycle and the request commit with the event.
func (l *RebuildLoop) Request(ctx context.Context, lineage IntentLineage, d RebuildDecisionFacts) (DecisionOutcome, error) {
	if !l.OpensFromDecision() || strings.TrimSpace(d.ReleaseID) == "" || strings.TrimSpace(d.DecisionID) == "" || len(d.CVEs) == 0 {
		return DecisionOutcome{State: DecisionIgnored}, nil
	}
	now := l.clock.Now()
	cycle, found, err := l.cycles.OpenCycle(ctx, d.ReleaseID)
	if err != nil {
		return DecisionOutcome{}, err
	}
	if found {
		return l.join(ctx, lineage, cycle, d.DecisionID, now)
	}
	if l.intents.RebuildChannel(ctx, d.ReleaseID) == ChannelUnsigned {
		return l.hold(ctx, RebuildHold{ReleaseID: d.ReleaseID, DecisionID: d.DecisionID, Reason: HoldUnsignedRoute, RecordedAt: now})
	}
	last, delivered, err := l.requests.LastDeliveredAt(ctx, d.ReleaseID)
	if err != nil {
		return DecisionOutcome{}, err
	}
	if until := last.Add(d.CoolDown); delivered && now.Before(until) {
		return l.hold(ctx, RebuildHold{ReleaseID: d.ReleaseID, DecisionID: d.DecisionID, Reason: HoldCoolDown, Until: until, RecordedAt: now})
	}
	sbom, err := l.requests.LastSBOM(ctx, d.ReleaseID)
	if err != nil {
		return DecisionOutcome{}, err
	}
	targeted := domain.TargetedSetOf(d.CVEs).CVEs()
	cycle, err = l.cycles.CreateCycle(ctx, RebuildCycle{
		ReleaseID: d.ReleaseID, OriginEventID: lineage.EventID, BaselineSBOMID: sbom, LastSBOMID: sbom,
		Targeted: targeted, Attempts: 1, State: CycleOpen, OpenedAt: now, UpdatedAt: now,
		Origin: CycleOriginDecision, DecisionID: d.DecisionID, Decision: d.Raw,
		ProductID: d.ProductID, ProjectID: d.ProjectID, Joined: []string{},
	})
	if err != nil {
		return DecisionOutcome{}, err
	}
	if err := l.requests.ClearHold(ctx, d.ReleaseID); err != nil {
		return DecisionOutcome{}, err
	}
	_, asked, err := l.ask(ctx, lineage, cycle, 1, 1)
	if err != nil {
		return DecisionOutcome{}, err
	}
	return DecisionOutcome{State: DecisionOpened, Cycle: cycle, Requested: asked}, nil
}

// join records a decision on the open cycle (D13). The targeted set does not change (D21). A
// decision is also "the next trigger" of D20 item 3: a request whose attempt was given back is
// made again.
func (l *RebuildLoop) join(ctx context.Context, lineage IntentLineage, cycle RebuildCycle, decisionID string, now time.Time) (DecisionOutcome, error) {
	if cycle.DecisionID != decisionID && !contains(cycle.Joined, decisionID) {
		cycle.Joined = append(append([]string{}, cycle.Joined...), decisionID)
		cycle.UpdatedAt = now
		if err := l.cycles.UpdateCycle(ctx, cycle); err != nil {
			return DecisionOutcome{}, err
		}
	}
	out := DecisionOutcome{State: DecisionJoined, Cycle: cycle}
	if cycle.Origin != CycleOriginDecision {
		return out, nil
	}
	attempt, try, again, err := l.nextRequest(ctx, cycle)
	if err != nil || !again {
		return out, err
	}
	_, out.Requested, err = l.ask(ctx, lineage, cycle, attempt, try)
	return out, err
}

// hold records why a decision opened no cycle.
func (l *RebuildLoop) hold(ctx context.Context, h RebuildHold) (DecisionOutcome, error) {
	if err := l.requests.SaveHold(ctx, h); err != nil {
		return DecisionOutcome{}, err
	}
	return DecisionOutcome{State: DecisionHeld, HoldReason: h.Reason}, nil
}

// nextRequest says which request an open decision cycle is waiting to make, if any: the same
// attempt with the next try after a refusal or a "not submitted", or the cycle's present attempt
// when it has no open request at all. again=false while a request is in flight.
func (l *RebuildLoop) nextRequest(ctx context.Context, cycle RebuildCycle) (attempt, try int, again bool, err error) {
	latest, has, err := l.requests.LatestRequest(ctx, cycle.ID)
	switch {
	case err != nil:
		return 0, 0, false, err
	case !has || latest.State == RequestEvaluated:
		return cycle.Attempts, 1, !has || latest.Attempt < cycle.Attempts, nil
	case attemptGivenBack(latest.State):
		return latest.Attempt, latest.Try + 1, true, nil
	default:
		return 0, 0, false, nil
	}
}

// ask makes one request of a decision cycle: the intent, and its request row. asked=false when
// nothing could be sent because the route has no signing secret; the hold says so.
func (l *RebuildLoop) ask(ctx context.Context, lineage IntentLineage, cycle RebuildCycle, attempt, try int) (Intent, bool, error) {
	now := l.clock.Now()
	if l.intents.RebuildChannel(ctx, cycle.ReleaseID) == ChannelUnsigned {
		_, err := l.hold(ctx, RebuildHold{ReleaseID: cycle.ReleaseID, DecisionID: cycle.DecisionID, Reason: HoldUnsignedRoute, RecordedAt: now})
		return Intent{}, false, err
	}
	in, channel, err := l.intents.EnqueueRebuildRequest(ctx, lineage, cycle, attempt, try, l.maxAttempts)
	if err != nil {
		return Intent{}, false, err
	}
	err = l.requests.CreateRequest(ctx, RebuildRequest{
		IntentID: in.ID, CycleID: cycle.ID, ReleaseID: cycle.ReleaseID, DecisionID: cycle.DecisionID,
		Attempt: attempt, Try: try, Channel: channel, State: RequestRequested, RequestedAt: now,
	})
	return in, err == nil, err
}

// evaluateDecisionCycle is Evaluate for a cycle a decision opened. The comparison is M2-8's. What
// differs is the attempt: it advances only when the last request held its attempt (D28). A
// request that was refused is made again with the next try; one still on its way is waited for.
func (l *RebuildLoop) evaluateDecisionCycle(ctx context.Context, cycle RebuildCycle, current []domain.PostureRow, sbomID string, now time.Time) (RebuildOutcome, error) {
	set := domain.TargetedSetOf(cycle.Targeted)
	closure := set.Closure(current)
	out := RebuildOutcome{Attempt: cycle.Attempts, Targeted: set.CVEs(), Closed: closure.Closed, Open: closure.Open,
		BaselineSBO: cycle.LastSBOMID, PriorSBO: sbomID}
	latest, has, err := l.requests.LatestRequest(ctx, cycle.ID)
	if err != nil {
		return RebuildOutcome{}, err
	}
	held := has && attemptHeld(latest.State)
	if held {
		latest.State, latest.StatusAt = RequestEvaluated, now
		if err := l.requests.UpdateRequest(ctx, latest); err != nil {
			return RebuildOutcome{}, err
		}
	}
	cycle.LastSBOMID, cycle.UpdatedAt = sbomID, now
	switch {
	case closure.Complete:
		cycle.State, out.State = CycleSucceeded, OutcomeSucceeded
	case held && cycle.Attempts >= l.maxAttempts:
		cycle.State, out.State = CycleExhausted, OutcomeExhausted
	case held:
		cycle.Attempts++
		out.State, out.NextAttempt, out.nextTry = OutcomeContinuing, cycle.Attempts, 1
	case has && attemptGivenBack(latest.State):
		out.State, out.NextAttempt, out.nextTry = OutcomeContinuing, latest.Attempt, latest.Try+1
	case !has:
		out.State, out.NextAttempt, out.nextTry = OutcomeContinuing, cycle.Attempts, 1
	default: // a request is still on its way, or the next one is already made
		out.State = OutcomeContinuing
	}
	if err := l.cycles.UpdateCycle(ctx, cycle); err != nil {
		return RebuildOutcome{}, err
	}
	out.cycle = cycle
	return out, l.cycleClosed(ctx, cycle)
}

// RecordStatus records the connector's status call for one request (D28 item 2). It changes the
// request, and for a refusal the cycle's refusal counter (D20). It changes no Finding.
func (l *RebuildLoop) RecordStatus(ctx context.Context, st RebuildStatus) (RebuildRequest, error) {
	if l.requests == nil {
		return RebuildRequest{}, ErrRebuildRequestsUnavailable
	}
	st.IntentID, st.Status = strings.TrimSpace(st.IntentID), strings.TrimSpace(st.Status)
	if st.IntentID == "" {
		return RebuildRequest{}, ErrStatusIncomplete
	}
	if st.Status != RequestSubmitted && st.Status != RequestRefused && st.Status != RequestUncertain {
		return RebuildRequest{}, ErrStatusUnknown
	}
	req, err := l.requests.RequestByIntent(ctx, st.IntentID)
	if err != nil {
		return RebuildRequest{}, err
	}
	now := l.clock.Now()
	switch {
	case req.State == RequestRequested || req.State == RequestDelivered || req.State == RequestUncertain:
	case req.State == RequestSubmitted && st.Status == RequestSubmitted: // said again; keep the newest facts
	default:
		return RebuildRequest{}, ErrStatusConflict
	}
	if req.DeliveredAt.IsZero() {
		req.DeliveredAt = now // a status call proves the event arrived
	}
	req.State, req.StatusAt, req.ReportedBy = st.Status, now, st.ReportedBy
	req.Reason = strings.TrimSpace(st.Reason)
	if ref := strings.TrimSpace(st.BuildRef); ref != "" {
		req.BuildRef = ref
	}
	if st.ExecutionStarted && req.ExecutionStartedAt.IsZero() {
		req.ExecutionStartedAt = now
	}
	if err := l.requests.UpdateRequest(ctx, req); err != nil {
		return RebuildRequest{}, err
	}
	switch st.Status {
	case RequestRefused:
		return req, l.refused(ctx, req, now)
	case RequestUncertain:
		return req, l.notice(ctx, req, NoticeUncertain)
	}
	return req, nil
}

// refused counts a refusal on the cycle and tells a person. The third refusal stops the cycle.
func (l *RebuildLoop) refused(ctx context.Context, req RebuildRequest, now time.Time) error {
	cycle, found, err := l.cycles.CycleByID(ctx, req.CycleID)
	if err != nil || !found || cycle.State != CycleOpen {
		return err
	}
	cycle.Refusals++
	cycle.UpdatedAt = now
	kind := NoticeRefused
	if cycle.Refusals >= MaxRefusalsPerCycle {
		cycle.State, kind = CycleRefused, NoticeCycleRefused
	}
	if err := l.cycles.UpdateCycle(ctx, cycle); err != nil {
		return err
	}
	if err := l.notice(ctx, req, kind); err != nil {
		return err
	}
	return l.cycleClosed(ctx, cycle)
}

// notice tells the evaluation audience about one request, once per request and kind.
func (l *RebuildLoop) notice(ctx context.Context, req RebuildRequest, kind string) error {
	_, err := l.intents.EnqueueRebuildNotice(ctx, req, kind)
	return err
}

// Settle records a person's answer to an uncertain request (D24): submitted keeps the attempt,
// not_submitted gives it back.
func (l *RebuildLoop) Settle(ctx context.Context, intentID, answer, actor, note string) (RebuildRequest, error) {
	if l.requests == nil {
		return RebuildRequest{}, ErrRebuildRequestsUnavailable
	}
	actor, answer = strings.TrimSpace(actor), strings.TrimSpace(answer)
	if actor == "" {
		return RebuildRequest{}, ErrActorRequired
	}
	if answer != RequestSubmitted && answer != RequestNotSubmitted {
		return RebuildRequest{}, ErrSettleAnswer
	}
	req, err := l.requests.RequestByIntent(ctx, strings.TrimSpace(intentID))
	if err != nil {
		return RebuildRequest{}, err
	}
	if req.State != RequestUncertain {
		return RebuildRequest{}, ErrNotUncertain
	}
	req.State, req.SettledAnswer, req.SettledBy = answer, answer, actor
	req.SettledAt, req.SettleNote = l.clock.Now(), strings.TrimSpace(note)
	return req, l.requests.UpdateRequest(ctx, req)
}

// RequestAgain makes the cycle's waiting request on a person's word (D20 item 3): the same
// attempt with the next try after a refusal or a "not submitted".
func (l *RebuildLoop) RequestAgain(ctx context.Context, releaseID, actor string) (RebuildRequest, error) {
	if l.requests == nil {
		return RebuildRequest{}, ErrRebuildRequestsUnavailable
	}
	if actor = strings.TrimSpace(actor); actor == "" {
		return RebuildRequest{}, ErrActorRequired
	}
	cycle, found, err := l.cycles.OpenCycle(ctx, releaseID)
	if err != nil {
		return RebuildRequest{}, err
	}
	if !found || cycle.Origin != CycleOriginDecision {
		return RebuildRequest{}, ErrNoOpenCycle
	}
	attempt, try, again, err := l.nextRequest(ctx, cycle)
	if err != nil {
		return RebuildRequest{}, err
	}
	if !again {
		return RebuildRequest{}, ErrRequestInFlight
	}
	lineage := IntentLineage{SourceContext: "communication", EventType: "communication.rebuild_requested_again",
		EventID: actor, EventTime: l.clock.Now()}
	in, asked, err := l.ask(ctx, lineage, cycle, attempt, try)
	if err != nil {
		return RebuildRequest{}, err
	}
	if !asked {
		return RebuildRequest{}, ErrRebuildHeld
	}
	return l.requests.RequestByIntent(ctx, in.ID)
}

// Stop closes the Release's open cycle on a person's word. No further request is made in it;
// what was already sent is not taken back.
func (l *RebuildLoop) Stop(ctx context.Context, releaseID, actor, note string) (RebuildCycle, error) {
	if actor = strings.TrimSpace(actor); actor == "" {
		return RebuildCycle{}, ErrActorRequired
	}
	cycle, found, err := l.cycles.OpenCycle(ctx, releaseID)
	if err != nil {
		return RebuildCycle{}, err
	}
	if !found {
		return RebuildCycle{}, ErrNoOpenCycle
	}
	cycle.State, cycle.ClosedBy, cycle.ClosedNote, cycle.UpdatedAt = CycleStopped, actor, strings.TrimSpace(note), l.clock.Now()
	if err := l.cycles.UpdateCycle(ctx, cycle); err != nil {
		return RebuildCycle{}, err
	}
	return cycle, l.cycleClosed(ctx, cycle)
}

// BuildReported moves a request to build_reported when the build callback names its intent
// (M2-7, D25). An intent with no request row (the loop of M2-8) is left alone.
func (l *RebuildLoop) BuildReported(ctx context.Context, intentID string) error {
	if l.requests == nil {
		return nil
	}
	req, err := l.requests.RequestByIntent(ctx, intentID)
	if errors.Is(err, ErrRebuildRequestNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	switch req.State {
	case RequestRequested, RequestDelivered, RequestSubmitted, RequestUncertain:
	default:
		return nil
	}
	now := l.clock.Now()
	if req.DeliveredAt.IsZero() {
		req.DeliveredAt = now
	}
	req.State, req.StatusAt = RequestBuildReported, now
	return l.requests.UpdateRequest(ctx, req)
}

// SweepSilent turns delivered requests with no status call and no build callback for
// SilentRequestLimit into uncertain (D28 item 3) and tells a person. It returns how many.
func (l *RebuildLoop) SweepSilent(ctx context.Context) (int, error) {
	if l.requests == nil {
		return 0, nil
	}
	now := l.clock.Now()
	silent, err := l.requests.SilentRequests(ctx, now.Add(-SilentRequestLimit))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, req := range silent {
		req.State, req.Reason, req.StatusAt = RequestUncertain, silentReason, now
		if err := l.requests.UpdateRequest(ctx, req); err != nil {
			return n, err
		}
		if err := l.notice(ctx, req, NoticeUncertain); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// View returns what a person is shown for one Release.
func (l *RebuildLoop) View(ctx context.Context, releaseID string) (RebuildView, error) {
	if l.requests == nil {
		return RebuildView{}, ErrRebuildRequestsUnavailable
	}
	var view RebuildView
	cycle, found, err := l.cycles.LatestCycle(ctx, releaseID)
	if err != nil {
		return RebuildView{}, err
	}
	if found {
		view.Cycle = &cycle
		if view.Requests, err = l.requests.ListRequests(ctx, cycle.ID); err != nil {
			return RebuildView{}, err
		}
	}
	hold, held, err := l.requests.Hold(ctx, releaseID)
	if err != nil {
		return RebuildView{}, err
	}
	if held {
		view.Hold = &hold
	}
	return view, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ProductOfRequest names the Product of the cycle a request belongs to, so that the caller can
// check who may act on it (D22). "" when the cycle names none.
func (l *RebuildLoop) ProductOfRequest(ctx context.Context, intentID string) (string, error) {
	if l.requests == nil {
		return "", ErrRebuildRequestsUnavailable
	}
	req, err := l.requests.RequestByIntent(ctx, strings.TrimSpace(intentID))
	if err != nil {
		return "", err
	}
	cycle, _, err := l.cycles.CycleByID(ctx, req.CycleID)
	return cycle.ProductID, err
}

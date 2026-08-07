package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

const maxSaveRetries = 5

// enrichmentActorID is the recorded proposer id for the system-generated proposal raised
// when a Faultline is enriched (D6). It is ActorSystem — a proposer with no authority.
const enrichmentActorID = "knowledge-enrichment"

// vexApplicabilityActorID is the proposer id for the system not_affected Proposal raised from
// a vendor VEX statement (EDR-VEX-01 D4). Also ActorSystem — it proposes suppression; a policy
// or human still decides. vexStatusNotAffected is the VEX vocabulary value it keys on.
const (
	vexApplicabilityActorID = "vex-applicability"
	vexStatusNotAffected    = "not_affected"
)

// versionRangeActorID is the proposer id for the system not_affected Proposal raised by the
// deterministic version-range rule (EDR-TRUST-01 T5). ActorSystem — Governance's own
// automation, so policy may auto-accept it; the verdict rests on Observed evidence when the
// ranges do.
const versionRangeActorID = "version-range"

// errNoop signals that a use-case body made no persistable change (an idempotent
// re-delivery). The mutate loop treats it as success and skips the save entirely.
var errNoop = errors.New("governance: no change")

// FindingService orchestrates the Governance write use cases over its ports (BCK-0038). It
// never edits aggregate state directly — every mutation is a domain operation (DOM-0030).
type FindingService struct {
	repo     Repository
	ids      IDGenerator
	clock    Clock
	policies []domain.PolicyRule
	advisor  PositionAdvisor // optional AI seam (nil = AI disabled); set via WithAdvisor
}

// NewFindingService wires the use-case ports and the Governance-owned auto-accept policies
// (D11). A nil/empty policy set means no proposal is ever auto-accepted (all decisions are
// human).
func NewFindingService(repo Repository, ids IDGenerator, clock Clock, policies ...domain.PolicyRule) *FindingService {
	return &FindingService{repo: repo, ids: ids, clock: clock, policies: policies}
}

// WithAdvisor sets the optional Intelligence seam and returns the service for chaining.
// The disable gate (D13) is this one wiring choice: a real Intelligence client enables AI;
// a no-op advisor (or leaving it unset) disables it. The pipeline is correct either way.
func (s *FindingService) WithAdvisor(a PositionAdvisor) *FindingService {
	s.advisor = a
	return s
}

// RecommendPosition is the on-demand AI seam (D8/D13, Revision 2): a human asks for an AI
// position recommendation on a Finding. When AI is enabled it invokes the Intelligence
// Gateway and records the returned advice as an ADVISORY Governance Proposal (actor = AI,
// the capability ref as provenance) — never auto-accepted; a human still decides. AI being
// absent, unreachable, or declining is invisible: it simply produces no proposal
// (disabled ≡ unavailable), never blocking. This runs off the pipeline hot path.
func (s *FindingService) RecommendPosition(ctx context.Context, findingID domain.FindingID) (domain.ProposalID, bool, error) {
	if s.advisor == nil {
		return "", false, nil // AI not wired — disabled
	}
	f, err := s.repo.GetByID(ctx, findingID)
	if err != nil {
		return "", false, err // re-check the Finding exists before spending AI (defense in depth)
	}
	rec, produced, err := s.advisor.RecommendPosition(ctx, string(findingID))
	if err != nil || !produced {
		return "", false, nil // disabled ≡ unavailable — a safe no-proposal outcome
	}
	// Business Verification (EDR-TRUST-01 T8): before recording anything, check the claim
	// against OUR truth. The runtime's Grounding Verification proved the model reasoned only
	// from the context it was handed — but that context was supplied to it. Only the context
	// owner can confirm the claim is consistent with the system of record, which is what makes
	// a stale or forged projection useless rather than merely unlikely to be accepted.
	//
	// A failed check is a silent no-proposal, not an error: AI producing nothing usable is a
	// normal outcome and must never block a human's request (D13).
	for _, ref := range rec.Evidence {
		if !vouchesRef(f, ref) {
			return "", false, nil
		}
	}
	provenance := ""
	if rec.DecidedBy != "" {
		provenance = " [" + rec.DecidedBy + "]"
	}
	rationale := fmt.Sprintf("AI recommendation%s (confidence %.2f): %s", provenance, rec.Confidence, rec.Reasoning)
	// The caveat rides INSIDE the recorded rationale, not beside it (TRUST-8). The rationale is
	// the field a human reads when exercising the decision T4 reserves for them, and it is the
	// least-verified part of an AI proposal: its structured evidence was grounded and
	// Business-Verified above, while the narrative was not — prose cannot be. Anything stored
	// elsewhere is something a reviewer can miss; embedded, the warning cannot be read apart
	// from the sentence it qualifies, and it is preserved verbatim in the immutable Position
	// inputs if this proposal is ever accepted.
	if len(rec.RationaleWarnings) > 0 {
		rationale += fmt.Sprintf(" [UNVERIFIED MENTIONS — the reasoning above names identifiers "+
			"that were not in its grounding, so treat those specifics as unreliable: %s]",
			strings.Join(rec.RationaleWarnings, ", "))
	}
	proposer := domain.Actor{Kind: domain.ActorAI, ID: rec.Capability}
	// Inferred by definition: the output of non-deterministic reasoning. The constitutional
	// check (T4) bars it from automatic acceptance under any policy — a human decides.
	pid, err := s.RaiseProposal(ctx, findingID, proposer, domain.Stance(rec.Stance), rationale, value.TrustInferred)
	if err != nil {
		return "", false, err
	}
	return pid, true, nil
}

// OpenOrUpdateFinding find-or-creates the Finding for a (Release, Faultline) pair from a
// Knowledge ComponentMatched and absorbs the matched components (D5). It is the only birth
// path for a Finding; a new Finding starts Identified with no Position, emitting
// FindingOpened. Re-delivery is idempotent: an existing Finding absorbs only new components
// and, if nothing changed, performs no write. Retries on optimistic-concurrency conflicts.
func (s *FindingService) OpenOrUpdateFinding(ctx context.Context, releaseID, faultlineID, cve string, baseScore int, comps []domain.MatchedComponent) (domain.FindingID, error) {
	if strings.TrimSpace(releaseID) == "" || strings.TrimSpace(faultlineID) == "" {
		return "", ErrInvalidMatch
	}
	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		existing, found, err := s.repo.GetByKey(ctx, releaseID, faultlineID)
		if err != nil {
			return "", err
		}
		now := s.clock.Now()

		var (
			f       domain.Finding
			created bool
			prev    int
			notes   []OutboxNote
		)
		if found {
			f = existing
			prev = f.Version()
		} else {
			f, err = domain.NewFinding(domain.FindingID(s.ids.NewID()), releaseID, faultlineID, cve)
			if err != nil {
				return "", err
			}
			created = true
			notes = append(notes, OutboxNote{EventType: EventFindingOpened, Event: domain.NewFindingOpened(f, now), OccurredAt: now})
		}

		added := false
		for _, c := range comps {
			a, err := f.AbsorbComponent(c)
			if err != nil {
				return "", err
			}
			added = added || a
		}
		if !created && !added {
			return f.ID(), nil // idempotent re-delivery — nothing to persist
		}

		switch err := s.repo.Save(ctx, f, created, prev, notes); {
		case err == nil:
			// Stamp the CVE-intrinsic base score onto the (possibly brand-new) Finding so a
			// Finding opened on an already-enriched card is not stranded at 0 (BUG-3). Guarded
			// on >0 so a pre-enrichment match (card not yet scored) never zeroes a live score;
			// SetBaseScore joins the inbox tx, so it sees this just-saved Finding.
			if baseScore > 0 {
				if err := s.repo.SetBaseScore(ctx, faultlineID, baseScore); err != nil {
					return "", err
				}
			}
			return f.ID(), nil
		case errors.Is(err, ErrConcurrent):
			continue
		default:
			return "", err
		}
	}
	return "", ErrConcurrent
}

// EnrichmentSignal is the app-level input distilled from a Knowledge FaultlineEnriched (or
// FaultlineSuperseded) event by the inbound adapter (D6). It carries just the facts the
// re-evaluation policy needs; the raw event shape stays at the adapter boundary.
type EnrichmentSignal struct {
	FaultlineID  string
	KEV          bool
	HighSeverity bool
	Withdrawn    bool // the Faultline was superseded (CVE withdrawn / rejected upstream)
	// WithdrawnTrust is the class of the source that reported the withdrawal (TRUST-4).
	// Only meaningful when Withdrawn.
	WithdrawnTrust value.TrustClass
	Score        int  // CVE-intrinsic base priority 0–100 (C6); materialized onto the Findings.
	// Applicabilities carries the reconciled vendor VEX statements (EDR-VEX-01 D4). A
	// not_affected statement whose package matches a Finding's component raises a system
	// not_affected Proposal on that Finding (policy/human accepts — never auto-suppress).
	Applicabilities []Applicability
	// Per-field-group trust backing this signal (EDR-TRUST-01 T2/T3). Nothing consumes
	// these yet — the constitutional check (T4) and reservations (T12) arrive in later
	// groups; carrying them now means the seam does not change again.
	HeadlineTrust value.TrustClass
	RangeTrust    value.TrustClass
	SignalTrust   value.TrustClass
	// AffectedRanges is Knowledge's reconciled, backport-aware range (D3), against which the
	// deterministic version-range rule re-evaluates each Finding (EDR-TRUST-01 T5).
	AffectedRanges []string
}

// Applicability is one vendor VEX statement distilled from the enrichment event (the raw wire
// shape stays at the adapter boundary). Governance never imports Knowledge's type.
type Applicability struct {
	Package       string
	Status        string
	Justification string
}

// proposalFor maps an enrichment signal to the Governance Proposal it should raise (D6). It
// returns raise=false for a change with no decision impact (advisory priority only — the
// Enterprise Position never auto-moves). The mapping is pure and deterministic.
func proposalFor(sig EnrichmentSignal) (stance domain.Stance, rationale string, raise bool) {
	switch {
	case sig.Withdrawn:
		return domain.StanceNotAffected, "CVE withdrawn or rejected upstream (Faultline superseded)", true
	case sig.KEV || sig.HighSeverity:
		return domain.StanceAffected, "severity increased / now KEV-listed — re-prioritize", true
	default:
		return "", "", false
	}
}

// vouchesRef is Business Verification's reference check, tolerating a human-readable LABEL
// around the identifier — the same narrow tolerance the Intelligence runtime applies in its
// Grounding Verification (T8).
//
// It has to match, or the false refusal is merely RELOCATED: the runtime would accept
// `faultline b1be6f86-…` and Governance would then reject the identical string, turning a
// cosmetic problem into a mysterious one. The two checks answer different questions — is this
// anchored in what the model was given, versus is this consistent with the system of record —
// but they read the same field, so they must agree on what the field says.
//
// Exact match first; only then extract identifier tokens, each of which must still clear the
// Finding's own exact check. No substring matching: "not CVE-2024-1" must not vouch, and
// "CVE-2024-1" must not match inside "CVE-2024-10".
func vouchesRef(f domain.Finding, ref string) bool {
	if f.Vouches(ref) {
		return true
	}
	tokens := value.IdentifierTokens(ref)
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		if !f.Vouches(tok) {
			return false
		}
	}
	return true
}

// evidenceTrustFor returns the trust class of the evidence backing an enrichment-driven
// proposal (EDR-TRUST-01 T3). It folds in ONLY the field-groups that actually drove the
// stance — folding in an unset-but-irrelevant group would read as Inferred under MaxTrust
// and wrongly bar a well-evidenced proposal from policy.
func evidenceTrustFor(sig EnrichmentSignal) value.TrustClass {
	if sig.Withdrawn {
		// TRUST-4 (closed): the class now rides knowledge.faultline_superseded.v1, classified
		// by Knowledge from the source that reported the withdrawal. Governance reads it rather
		// than holding a second copy of the source→class table.
		//
		// An empty class means a payload predating the field, and it falls back to Observed —
		// which is what this code stated unconditionally before, so replay of an older event
		// behaves exactly as it did. That fallback is deliberately NOT fail-closed: the classes
		// it would fall closed to (Asserted/Inferred) would bar the withdrawn-CVE auto-accept
		// that works today, turning a wire-compatibility gap into a behaviour regression. The
		// producer always sets the field, and an unregistered source is already failed closed
		// to Asserted at classification time — so this path only ever sees genuinely old events.
		if sig.WithdrawnTrust.Valid() {
			return sig.WithdrawnTrust
		}
		return value.TrustObserved
	}
	if sig.KEV && sig.HighSeverity {
		return value.MaxTrust(sig.SignalTrust, sig.HeadlineTrust)
	}
	if sig.KEV {
		return value.MaxTrust(sig.SignalTrust)
	}
	return value.MaxTrust(sig.HeadlineTrust)
}

// ReactToEnrichment re-evaluates every Finding referencing an enriched Faultline by raising
// a single system-generated Governance Proposal against each and flagging it for review —
// it never auto-changes the Enterprise Position (D6/DOM-0026). A Governance-owned policy
// may auto-accept the raised proposal (D11); otherwise it waits for a human. The fan-out is
// many small per-aggregate transactions (D9). Re-delivery is idempotent (a proposal id
// derived from the finding + proposed stance dedups).
func (s *FindingService) ReactToEnrichment(ctx context.Context, sig EnrichmentSignal) error {
	// Materialize the CVE-intrinsic base score onto every Finding for this Faultline (C6), on
	// every enrichment — independent of whether a re-prioritize proposal is raised, so the
	// posture always reflects the current score. A superseded Faultline carries no score.
	if !sig.Withdrawn {
		if err := s.repo.SetBaseScore(ctx, sig.FaultlineID, sig.Score); err != nil {
			return err
		}
	}
	// Severity / withdrawn re-prioritization: one system proposal per Finding of the Faultline.
	if stance, rationale, raise := proposalFor(sig); raise {
		ids, err := s.repo.FindingsByFaultline(ctx, sig.FaultlineID)
		if err != nil {
			return err
		}
		proposer := domain.Actor{Kind: domain.ActorSystem, ID: enrichmentActorID}
		for _, id := range ids {
			pid := domain.ProposalID("enrich:" + string(id) + ":" + string(stance))
			if err := s.mutate(ctx, id, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
				p, err := domain.NewGovernanceProposal(pid, proposer, stance, rationale, now, evidenceTrustFor(sig))
				if err != nil {
					return nil, err
				}
				notes, err := s.raiseAndMaybeAutoAccept(f, p, now)
				if errors.Is(err, domain.ErrDuplicateProposal) {
					return nil, errNoop // already raised for this signal — idempotent
				}
				return notes, err
			}); err != nil {
				return err
			}
		}
	}
	// Vendor VEX suppression overlay (EDR-VEX-01 D4): a not_affected statement covering a
	// Finding's component raises a system not_affected Proposal on that Finding.
	if err := s.reactToApplicability(ctx, sig); err != nil {
		return err
	}
	// Deterministic version-range inference (EDR-TRUST-01 T5): re-evaluate EXISTING Findings
	// against the reconciled range. Correlation applies the same rule, but only at match
	// time — a Finding born before the range was known is never revisited by it, and until
	// now only an on-demand AI call would catch that (contradicting D13: the pipeline must be
	// correct with AI switched off).
	return s.reactToVersionRange(ctx, sig)
}

// reactToApplicability raises a system not_affected Proposal on each Finding whose matched
// component a vendor not_affected VEX statement covers (EDR-VEX-01 D4). It never auto-suppresses:
// a Governance-owned policy may auto-accept the system proposal (D11), otherwise it awaits a
// human. The vendor justification is carried into the rationale so a suppression is explainable
// (D6). Idempotent — the proposal id derives from the Finding + a path-safe hash of the covered
// package (so it never embeds the PURL's '/', which would 404 the accept/reject REST path), and a
// re-delivery dedups.
func (s *FindingService) reactToApplicability(ctx context.Context, sig EnrichmentSignal) error {
	var notAffected []Applicability
	for _, a := range sig.Applicabilities {
		if a.Status == vexStatusNotAffected && strings.TrimSpace(a.Package) != "" {
			notAffected = append(notAffected, a)
		}
	}
	if len(notAffected) == 0 {
		return nil // no vendor not_affected statement — nothing to suppress
	}
	ids, err := s.repo.FindingsByFaultline(ctx, sig.FaultlineID)
	if err != nil {
		return err
	}
	proposer := domain.Actor{Kind: domain.ActorSystem, ID: vexApplicabilityActorID}
	for _, id := range ids {
		if err := s.mutate(ctx, id, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
			covered, ok := coveringStatement(f, notAffected)
			if !ok {
				return nil, errNoop // no vendor statement covers this Finding's components
			}
			pid := domain.ProposalID("vex:" + string(id) + ":" + packageKey(covered.Package))
			// A vendor VEX statement is Asserted: the vendor is the sole authority on their own
			// build, so nothing can re-run it. Hard-coded rather than read per-statement because
			// applicabilities carry no individual class yet (TRUST-1) — every one of them today
			// originates from vendor or uploaded VEX, so they are uniformly Asserted.
			p, err := domain.NewGovernanceProposal(pid, proposer, domain.StanceNotAffected, vexRationale(covered), now, value.TrustAsserted)
			if err != nil {
				return nil, err
			}
			notes, err := s.raiseAndMaybeAutoAccept(f, p, now)
			if errors.Is(err, domain.ErrDuplicateProposal) {
				return nil, errNoop // already raised for this statement — idempotent
			}
			return notes, err
		}); err != nil {
			return err
		}
	}
	return nil
}

// reactToVersionRange raises a system not_affected Proposal on each Finding whose every
// matched component is provably outside the reconciled affected range (EDR-TRUST-01 T5).
//
// It never auto-suppresses: like the vendor-VEX overlay it travels the governed road — a
// Governance-owned policy may auto-accept the system proposal, otherwise a human decides.
// The proposal's evidence class is the RANGE group's class specifically, not the card's
// worst — a vendor statement elsewhere on the card must not downgrade a verdict computed
// purely from public ranges.
//
// Idempotent: the proposal id derives from the Finding, so a re-delivery dedups.
func (s *FindingService) reactToVersionRange(ctx context.Context, sig EnrichmentSignal) error {
	if len(sig.AffectedRanges) == 0 {
		return nil // no reconciled range to decide against
	}
	ids, err := s.repo.FindingsByFaultline(ctx, sig.FaultlineID)
	if err != nil {
		return err
	}
	proposer := domain.Actor{Kind: domain.ActorSystem, ID: versionRangeActorID}
	for _, id := range ids {
		if err := s.mutate(ctx, id, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
			if !domain.ProvablyOutOfRange(f.Components(), sig.AffectedRanges) {
				return nil, errNoop // in range, undecidable, or unreadable — defer, never suppress
			}
			pid := domain.ProposalID("range:" + string(id))
			p, err := domain.NewGovernanceProposal(pid, proposer, domain.StanceNotAffected,
				"every matched component version is outside the reconciled affected range", now, sig.RangeTrust)
			if err != nil {
				return nil, err
			}
			notes, err := s.raiseAndMaybeAutoAccept(f, p, now)
			if errors.Is(err, domain.ErrDuplicateProposal) {
				return nil, errNoop // already raised for this Finding — idempotent
			}
			return notes, err
		}); err != nil {
			return err
		}
	}
	return nil
}

// coveringStatement returns the first not_affected statement covering one of the Finding's
// matched components (EDR-VEX-01 D4).
func coveringStatement(f *domain.Finding, apps []Applicability) (Applicability, bool) {
	for _, a := range apps {
		if f.CoversPackage(a.Package) {
			return a, true
		}
	}
	return Applicability{}, false
}

// vexRationale renders the rationale for a vendor not_affected suppression, carrying the vendor
// justification through for explainability (D6).
func vexRationale(a Applicability) string {
	if strings.TrimSpace(a.Justification) == "" {
		return "vendor VEX: not_affected for " + a.Package
	}
	return "vendor VEX: not_affected for " + a.Package + " (" + a.Justification + ")"
}

// packageKey derives a short, path-safe, deterministic token from a package identifier. The vex
// proposal id embeds this instead of the raw PURL so the id never carries a '/', which would make
// the accept/reject REST path (…/proposals/{id}/accept) 404. Deterministic ⇒ the same covered
// package always folds to the same proposal id (idempotent dedup); the human-readable package is
// preserved in the proposal rationale (vexRationale), so nothing is lost for explainability.
func packageKey(pkg string) string {
	sum := sha256.Sum256([]byte(pkg))
	return hex.EncodeToString(sum[:8])
}

// RaiseProposal records a Governance Proposal against a Finding from a human or AI proposer
// (D4/D11) — the single proposer entry. It raises the proposal and flags the Finding for
// review; a Governance-owned policy never auto-accepts a non-system proposal, so a human or
// AI proposal always awaits a human decision. Returns the new proposal id.
func (s *FindingService) RaiseProposal(
	ctx context.Context, findingID domain.FindingID, proposer domain.Actor, stance domain.Stance, rationale string,
	evidenceTrust value.TrustClass,
) (domain.ProposalID, error) {
	pid := domain.ProposalID(s.ids.NewID())
	err := s.mutate(ctx, findingID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		p, err := domain.NewGovernanceProposal(pid, proposer, stance, rationale, now, evidenceTrust)
		if err != nil {
			return nil, err
		}
		return s.raiseAndMaybeAutoAccept(f, p, now)
	})
	if err != nil {
		return "", err
	}
	return pid, nil
}

// AcceptProposal is the governed decision: an authorized human (or a Governance-owned
// policy) accepts an open proposal, establishing a new Enterprise Position version and
// advancing the lifecycle in one transaction (D4/D9). AI and system actors are refused
// (ErrUnauthorized — D11).
func (s *FindingService) AcceptProposal(ctx context.Context, findingID domain.FindingID, proposalID domain.ProposalID, decider domain.Actor) error {
	if err := requireDecider(decider); err != nil {
		return err
	}
	return s.mutate(ctx, findingID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		pos, err := f.AcceptProposal(proposalID, decider, now)
		if err != nil {
			return nil, err
		}
		return []OutboxNote{
			{EventType: EventProposalAccepted, Event: domain.NewProposalAccepted(*f, proposalID, pos, now), OccurredAt: now},
			positionNote(*f, pos, now),
		}, nil
	})
}

// RejectProposal evaluates an open proposal to Rejected (retained as history — D4). Only an
// authorized human or policy may reject (D11); the Enterprise Position is unaffected.
func (s *FindingService) RejectProposal(ctx context.Context, findingID domain.FindingID, proposalID domain.ProposalID, decider domain.Actor) error {
	if err := requireDecider(decider); err != nil {
		return err
	}
	return s.mutate(ctx, findingID, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		if err := f.RejectProposal(proposalID, decider, now); err != nil {
			return nil, err
		}
		return []OutboxNote{{EventType: EventProposalRejected, Event: domain.NewProposalRejected(*f, proposalID, now), OccurredAt: now}}, nil
	})
}

// ResolveFinding closes a Finding's concern (D7). Idempotent (a no-op if already Resolved).
func (s *FindingService) ResolveFinding(ctx context.Context, id domain.FindingID) error {
	return s.lifecycle(ctx, id, (*domain.Finding).Resolve, EventFindingResolved, resolvedEvent)
}

// ReopenFinding takes the governed reopen path (D7). Idempotent-safe: an illegal reopen
// surfaces the domain error.
func (s *FindingService) ReopenFinding(ctx context.Context, id domain.FindingID) error {
	return s.lifecycle(ctx, id, (*domain.Finding).Reopen, EventFindingReopened, reopenedEvent)
}

// ArchiveFinding moves a Finding to the terminal Archived stage (D7). Idempotent.
func (s *FindingService) ArchiveFinding(ctx context.Context, id domain.FindingID) error {
	return s.lifecycle(ctx, id, (*domain.Finding).Archive, EventFindingArchived, archivedEvent)
}

// lifecycle runs a governed lifecycle transition, emitting its event only when the stage
// actually changed (an idempotent no-op emits nothing and performs no write).
func (s *FindingService) lifecycle(ctx context.Context, id domain.FindingID, op func(*domain.Finding) error, eventType string, build func(domain.Finding, time.Time) any) error {
	return s.mutate(ctx, id, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		before := f.Stage()
		if err := op(f); err != nil {
			return nil, err
		}
		if f.Stage() == before {
			return nil, errNoop // idempotent — nothing changed
		}
		return []OutboxNote{{EventType: eventType, Event: build(*f, now), OccurredAt: now}}, nil
	})
}

// mutate loads a Finding by id, applies fn, and saves under optimistic concurrency,
// retrying on conflict. fn returning errNoop means "no change" — the save is skipped and
// the call succeeds (idempotency).
func (s *FindingService) mutate(ctx context.Context, id domain.FindingID, fn func(*domain.Finding, time.Time) ([]OutboxNote, error)) error {
	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		f, err := s.repo.GetByID(ctx, id)
		if err != nil {
			return err
		}
		prev := f.Version()
		now := s.clock.Now()

		notes, err := fn(&f, now)
		if errors.Is(err, errNoop) {
			return nil
		}
		if err != nil {
			return err
		}

		switch err := s.repo.Save(ctx, f, false, prev, notes); {
		case err == nil:
			return nil
		case errors.Is(err, ErrConcurrent):
			continue
		default:
			return err
		}
	}
	return ErrConcurrent
}

// raiseAndMaybeAutoAccept raises a proposal and, if a Governance-owned policy matches (only
// system proposals are eligible — D11), accepts it in the same transaction, appending the
// accept + Position events. It returns the outbox notes for the mutation.
func (s *FindingService) raiseAndMaybeAutoAccept(f *domain.Finding, p domain.GovernanceProposal, now time.Time) ([]OutboxNote, error) {
	if err := f.RaiseProposal(p); err != nil {
		return nil, err
	}
	notes := []OutboxNote{{EventType: EventProposalRaised, Event: domain.NewProposalRaised(*f, p, now), OccurredAt: now}}
	// Stage 1 — the constitutional check (EDR-TRUST-01 T6). Fixed, non-configurable, and
	// evaluated BEFORE any policy: a proposal resting on Inferred evidence is ineligible for
	// automatic acceptance no matter how policy is configured. Failing it is not an error —
	// the proposal simply stays open for a human.
	if !domain.ConstitutionallyAutoAcceptable(p) {
		return notes, nil
	}
	// Stage 2 — the configurable, Governance-owned policy.
	for _, rule := range s.policies {
		if ok, by := rule.Evaluate(p); ok {
			pos, err := f.AcceptProposal(p.ID(), by, now)
			if err != nil {
				return nil, err
			}
			notes = append(notes,
				OutboxNote{EventType: EventProposalAccepted, Event: domain.NewProposalAccepted(*f, p.ID(), pos, now), OccurredAt: now},
				positionNote(*f, pos, now),
			)
			break
		}
	}
	return notes, nil
}

// positionNote builds the correct outbound Position event note for a newly established
// version — Established for v1, Revised for v2+ (D8).
func positionNote(f domain.Finding, pos domain.Position, now time.Time) OutboxNote {
	est, rev := domain.NewPositionEvent(f, pos, now)
	if est != nil {
		return OutboxNote{EventType: EventPositionEstablished, Event: *est, OccurredAt: now}
	}
	return OutboxNote{EventType: EventPositionRevised, Event: *rev, OccurredAt: now}
}

// requireDecider enforces the ADR-fixed authority line (D11): only an authorized human or a
// Governance-owned policy may accept/reject; AI and system may propose only.
func requireDecider(a domain.Actor) error {
	if a.Kind != domain.ActorHuman && a.Kind != domain.ActorPolicy {
		return ErrUnauthorized
	}
	return nil
}

// Lifecycle event builders (adapt the typed domain constructors to the mutate signature).
func resolvedEvent(f domain.Finding, at time.Time) any { return domain.NewFindingResolved(f, at) }
func reopenedEvent(f domain.Finding, at time.Time) any { return domain.NewFindingReopened(f, at) }
func archivedEvent(f domain.Finding, at time.Time) any { return domain.NewFindingArchived(f, at) }

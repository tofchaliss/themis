package domain

import (
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Knowledge events are completed business facts published on an actual Faultline state
// change — never on the mere arrival of a Proposal (D8; DOM-0033). Payloads are thin
// (mirroring Evidence D6): consumers fetch detail via the read API.

// FaultlineCreated announces that a new card exists.
type FaultlineCreated struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// FaultlineEnriched announces that the enterprise view changed. It carries a coarse
// headline (severity + exploit signals) so Governance can re-evaluate (EDR-GOVERNANCE-01
// D6) without fetching the whole card.
type FaultlineEnriched struct {
	FaultlineID   FaultlineID
	CVE           string
	Severity      value.Severity
	KEV           bool
	ExploitPublic bool
	// Score is the CVE-intrinsic composite priority (0–100), snapshotted so Governance can
	// apply its release-scoped blast multiplier without refetching the card (C6 → C2).
	Score int
	// EPSS is the reconciled exploitation probability (0.0–1.0). Carried so Governance can detect
	// DRIFT against what a suppressing decision was taken with (GOV-14b) — KEV and ExploitPublic
	// already ride here, and EPSS is the third signal D14 names. Additive/omitempty: a pre-change
	// payload stays byte-identical and reads as 0, which is the conservative direction (any later
	// rise looks like drift and re-surfaces the Finding).
	EPSS float64 `json:"EPSS,omitempty"`
	// Priority is the reconciled EXPLOITABILITY band (critical | high+ | high | elevated |
	// informational). Carried so a Governance rollup can answer "which of these are critical?"
	// without one Knowledge call per Faultline (DASH-2) — measured: rendering one posture table
	// cost ~460 calls, and every one of them was for this field and the fix list below.
	//
	// The band is Knowledge's to compute: it is exploitability-aware rather than raw CVSS, and a
	// second implementation in Governance would be a second policy that eventually disagrees.
	Priority string `json:"Priority,omitempty"`
	// Fixes are the reconciled fix versions WITH the package each applies to (KN-FIX-1). Governance
	// selects the ones matching a Finding's components and stamps them, so a release-scoped view
	// can say what to upgrade to without a per-Finding read (PLAN-3).
	Fixes []FixedVersion `json:"Fixes,omitempty"`
	// Applicabilities carries the reconciled vendor VEX statements (EDR-VEX-01 D5) so Governance
	// can raise a system not_affected Proposal on the affected Findings without fetching the card.
	// Optional/additive (omitempty): a card with no vendor statement keeps the frozen v1 wire
	// byte-identical (EVENTBUS D9 — additive, non-breaking).
	Applicabilities []Applicability `json:"Applicabilities,omitempty"`
	// AffectedRanges is the reconciled, backport-aware affected range (D3), carried so
	// Governance can re-evaluate an EXISTING Finding against it (EDR-TRUST-01 T5) — the case
	// correlation's own range gate cannot reach, because that gate only runs at match time,
	// so a Finding born before the range was known is never revisited.
	AffectedRanges []string `json:"AffectedRanges,omitempty"`
	// Trust classes for the reconciled view's field-groups (EDR-TRUST-01 T2/T3), so
	// Governance can apply the constitutional check (T4) and derive reservations (T12)
	// without refetching the card.
	//
	// These must ride the wire rather than being re-derived downstream: re-derivation
	// would require Governance to hold a **second copy** of the source→class policy, and
	// two copies of a trust policy will eventually disagree. Knowledge owns the table, so
	// Knowledge ships the verdict.
	//
	// Additive and optional (omitempty), like Score and Applicabilities before them: a
	// payload from before this change stays byte-identical, and an older consumer ignores
	// them (EVENTBUS D9 — additive, non-breaking, no schema version bump).
	HeadlineTrust value.TrustClass `json:"HeadlineTrust,omitempty"`
	RangeTrust    value.TrustClass `json:"RangeTrust,omitempty"`
	SignalTrust   value.TrustClass `json:"SignalTrust,omitempty"`
	OccurredAt    time.Time
}

// FaultlineMatured announces the card reached the Mature stage.
type FaultlineMatured struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// FaultlineSuperseded announces the card reached the terminal Superseded stage.
type FaultlineSuperseded struct {
	FaultlineID FaultlineID
	CVE         string
	// Trust is the class of the evidence that drove the supersession (EDR-TRUST-01 T2/T3),
	// taken from the trust policy's entry for the source that reported the withdrawal.
	//
	// It rides the wire for the same reason the enriched event's classes do: Governance must
	// not hold a second copy of the source→class table. Governance previously *stated* that a
	// withdrawal is Observed — true for NVD, but an assumption rather than a fact, and one that
	// would silently misclassify a withdrawal reported by an Asserted source.
	//
	// Additive and optional (omitempty): a payload from before this change stays byte-identical
	// and an older consumer ignores it (EVENTBUS D9 — no schema version bump).
	Trust      value.TrustClass `json:"Trust,omitempty"`
	OccurredAt time.Time
}

// MatchedComponent is one release component that matched a card during correlation.
type MatchedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	// Source is the upstream SOURCE-package name for distro components (python3-pyyaml →
	// PyYAML); "" for non-distro, where the binary name is the only name.
	//
	// It rides the wire because it is the ONLY key that joins a component to its published fix:
	// vulnerability feeds attribute fixes to the source package, a PURL carries the binary one,
	// and `python3-pyyaml → PyYAML` follows no derivable rule. Without it a consumer holding a
	// Finding can only compare against the flat cross-package union — which is how a
	// recommendation came to cite another package's version as this component's fix
	// (AI-GROUND-1).
	//
	// Additive and optional (omitempty): a pre-change payload stays byte-identical and an older
	// consumer ignores it (EVENTBUS D9 — no schema version bump).
	Source string `json:"Source,omitempty"`
	// ClaimClass says WHY this component matched: `carrier` (evidence says it carries the flaw),
	// `scope` (it was in an advisory's rebuild set with no such evidence), or empty/unknown
	// (nobody has said). EDR-CORRELATION-01 D3/D5.
	//
	// It is decided HERE, at correlation, because that is where the match is made and where the
	// card's carrier products are in hand. Deriving it downstream would put a second copy of the
	// attribution policy in Governance, and two copies of a policy eventually disagree — the same
	// reasoning that put trust classes on the wire rather than re-deriving them.
	//
	// Additive/omitempty: an older payload decodes to unknown, which every consumer treats as
	// carrier — the pre-change behaviour exactly.
	ClaimClass ClaimClass `json:"ClaimClass,omitempty"`
	// DetectionOrigin says WHICH ENGINE produced this match: `discovery` (feed correlation
	// against the inventory, including the re-discovery sweep) or `scanner/<name>` (an uploaded
	// scanner report; bare `scanner` when the report names no engine). Display provenance ONLY
	// (KN-SCAN-2): it never carries authority — the source tier taxonomy does — and it is not
	// the proposal source, which stays a closed vocabulary so the trust/precedence tables remain
	// enumerable (TRUST-2). Matches are first-wins (ON CONFLICT DO NOTHING), so one match has
	// exactly one origin: whoever found it first.
	//
	// Additive/omitempty: an older payload decodes to "", which a consumer shows as unknown.
	DetectionOrigin string `json:"DetectionOrigin,omitempty"`
	// The occurrence verdict (EDR-VERDICT-01 D2/D5): what the fixed-verdict machinery concluded
	// about THIS occurrence, with the evidence grade and plain-language premise. Additive /
	// omitempty: an older payload decodes to "", which every consumer reads as open — the
	// fail-safe direction.
	VerdictState  VerdictState `json:"VerdictState,omitempty"`
	VerdictGrade  VerdictGrade `json:"VerdictGrade,omitempty"`
	VerdictReason string       `json:"VerdictReason,omitempty"`
}

// ComponentMatched is the correlation output (D3/D8): a release's component matches a
// card. Governance consumes it to create a Finding (EDR-GOVERNANCE-01 D5). It is a
// Proposal, not truth, and never mutates the card.
type ComponentMatched struct {
	FaultlineID FaultlineID
	CVE         string
	ReleaseID   string
	Components  []MatchedComponent
	// Score is the card's CVE-intrinsic composite score (0–100) at match time (C6). Carried so
	// Governance can stamp base_score at finding-open — otherwise a Finding born on an
	// already-enriched card is stranded at 0 until the next enrichment event (BUG-3).
	Score int
	// Priority and Fixes ride here for exactly the reason Score does, and their absence was the
	// same defect one field later (BUG-3b). DASH-2 delivered the band and the fix list on
	// FaultlineEnriched ALONE, so a Finding opened AFTER its card's last enrichment never
	// received either — the enrichment handler looks up the card's Findings and finds none.
	//
	// "The next enrichment repairs it" is not a fallback that can be relied on: enrichment is
	// relevance-bounded, and KN-PROPOSAL-BLOAT-1 now drops a source's verbatim restatement, so a
	// card nothing new is said about emits NO further event. Measured on a clean estate: of 120
	// Findings, the one CVE that no later feed touched (CVE-2026-59949 — enriched at bus seq 12,
	// its Finding opened at seq 205) had a band on its card and none on its Finding, permanently.
	//
	// Additive + omitempty (EVENTBUS D9): an older payload stays byte-identical and reads empty,
	// which is the pre-change behaviour.
	Priority   string         `json:"Priority,omitempty"`
	Fixes      []FixedVersion `json:"Fixes,omitempty"`
	OccurredAt time.Time
}

// ComponentVerdictChanged records that an EXISTING occurrence's verdict state changed — a
// later re-judgement (new fix bounds folding onto the card, the catch-up sweep) reached a
// different conclusion than the one on record (EDR-VERDICT-01 D5/D6). It is emitted only on a
// real state change, never on a re-judgement that confirms what is already recorded, and it
// never deletes anything: Governance mirrors the new state onto its component row and
// re-derives queue membership.
type ComponentVerdictChanged struct {
	FaultlineID FaultlineID
	CVE         string
	ReleaseID   string
	Component   MatchedComponent
	OccurredAt  time.Time
}

// ComponentRetired announces that a recorded occurrence does NOT denote an additional component
// and has been withdrawn from the active projection (KN-SCAN-4(b)).
//
// The measured fact it carries is narrow and worth stating exactly: *this identity does not
// represent an additional component on this release*. It deliberately does NOT name what the
// component duplicates. Encoding `superseded_by` would assert a lifecycle relationship the
// evidence does not need — the canonical row already exists independently, recorded by its own
// path, and it needs no pointer back to a row that never denoted a distinct thing.
//
// Retirement is a PROJECTION change, not an erasure: the row stays stored, so the audit trail
// keeps every occurrence Themis ever recorded, and "we retired this" stays distinguishable from
// "this never happened". Consumers exclude retired components from active queries.
//
// Idempotent by construction: it asserts a state, not a transition, so re-delivery re-asserts
// the same state and changes nothing.
type ComponentRetired struct {
	FaultlineID FaultlineID
	CVE         string
	ReleaseID   string
	// PURL identifies the exact row being retired — the one thing a consumer needs.
	PURL string
	// Reason is operator-facing audit text, never a decision input; nothing branches on it.
	Reason     string
	OccurredAt time.Time
}

// NewComponentRetired builds the retirement event for one recorded occurrence.
func NewComponentRetired(f Faultline, releaseID, purl, reason string, at time.Time) ComponentRetired {
	return ComponentRetired{
		FaultlineID: f.ID(), CVE: f.CVE().String(), ReleaseID: releaseID,
		PURL: purl, Reason: reason, OccurredAt: at.UTC(),
	}
}

// RetiredDuplicateIdentity is the only reason KN-SCAN-4(b) emits: the row's identity is a raw
// scanner string whose canonical twin is already recorded on the same release and card.
const RetiredDuplicateIdentity = "duplicate_identity"

// NewFaultlineCreated builds the event for a newly created card.
func NewFaultlineCreated(f Faultline, at time.Time) FaultlineCreated {
	return FaultlineCreated{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewFaultlineEnriched builds the view-change event, snapshotting the current headline and the
// reconciled vendor applicability statements (D5).
func NewFaultlineEnriched(f Faultline, at time.Time) FaultlineEnriched {
	v := f.View()
	return FaultlineEnriched{
		FaultlineID:     f.ID(),
		CVE:             f.CVE().String(),
		Severity:        v.Severity,
		KEV:             v.KEV,
		ExploitPublic:   v.ExploitPublic,
		Score:           v.Score(),
		EPSS:            v.EPSS,
		Priority:        v.Priority(),
		Fixes:           append([]FixedVersion(nil), v.Fixes...),
		Applicabilities: append([]Applicability(nil), v.Applicabilities...),
		AffectedRanges:  append([]string(nil), v.AffectedRanges...),
		HeadlineTrust:   v.HeadlineTrust,
		RangeTrust:      v.RangeTrust,
		SignalTrust:     v.SignalTrust,
		OccurredAt:      at.UTC(),
	}
}

// NewFaultlineMatured builds the Mature-stage event.
func NewFaultlineMatured(f Faultline, at time.Time) FaultlineMatured {
	return FaultlineMatured{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewFaultlineSuperseded builds the Superseded-stage event, carrying the trust class of the
// source that reported the withdrawal.
func NewFaultlineSuperseded(f Faultline, trust value.TrustClass, at time.Time) FaultlineSuperseded {
	return FaultlineSuperseded{FaultlineID: f.ID(), CVE: f.CVE().String(), Trust: trust, OccurredAt: at.UTC()}
}

// DiscoveryCause names WHY a correlation run happened, and it is a closed two-value
// vocabulary (EDR-DELIVERY-01 M2-3). The producer knows the reason; a consumer that had to
// infer it from "did the SBOM id change" would be guessing, and a wrong guess silently spends
// the rebuild loop's attempt budget on a feed update nobody asked for.
const (
	// CauseNewSBOM — correlation ran because an SBOM was uploaded for the release.
	CauseNewSBOM = "new_sbom"
	// CauseRediscovery — correlation re-ran from the re-discovery sweep (KN-RECOR-1). A real
	// posture change, but nothing was built, so the loop must ignore it.
	CauseRediscovery = "rediscovery"
)

// ValidDiscoveryCause reports whether cause is one of the two causes the contract admits.
// An unknown cause is a programming error, not an input to tolerate: it would reach
// Governance as a third value and leave every consumer's switch without a case.
func ValidDiscoveryCause(cause string) bool {
	return cause == CauseNewSBOM || cause == CauseRediscovery
}

// ReleaseCorrelationCompleted announces that Knowledge has finished correlating ONE SBOM —
// the signal Governance turns into `governance.release_evaluated.v1` (EDR-DELIVERY-01 M2-1).
//
// It is published ONCE per SBOM and appended to the outbox AFTER every other Knowledge event
// raised for that SBOM, so by the time a consumer handles it, every earlier fact for that SBOM
// has already been delivered (the bus drains in `seq` order per source context). That ordering
// is the whole reason the signal is an event appended last rather than a timer or a
// quiet-for-N-seconds heuristic: a heuristic answers "probably finished", and a posture read
// from a probably-finished correlation lists a subset and reads as truth.
//
// An SBOM with no matched vulnerabilities still publishes it. Suppressing the event when there
// is nothing to report would make silence ambiguous — "evaluated, clean" would be
// indistinguishable from "not evaluated yet" and from "the pipeline is broken".
//
// Knowledge says only "I am done with this SBOM"; it deliberately states nothing about WHAT
// the posture is, because the counts are Governance's Findings over Governance's own
// projection (M2-1). For the same reason it names no PRODUCT and no PROJECT (M2a-1): identity
// lives in Registry and Knowledge holds no seam to it, so those two ids ride
// governance.release_evaluated.v1, which Governance — already reading Registry, already owning
// the counts — can state in full. The body is snake_case, unlike the older Knowledge events
// which marshal Go field names, because it is the shape M2-2 fixes for this pair of events.
type ReleaseCorrelationCompleted struct {
	ReleaseID string `json:"release_id"`
	// SBOMID is the Evidence id of the SBOM that was correlated, carried verbatim as TEXT and
	// never parsed — the same rule every foreign id in this flow follows.
	SBOMID string `json:"sbom_id"`
	Cause  string `json:"cause"`
	// OccurredAt rides IN the body as well as on the envelope: the consumer that stores these
	// events (N-M2d) keeps the body, and a stored fact that cannot say when it happened without
	// its transport metadata is incomplete.
	OccurredAt time.Time `json:"occurred_at"`
}

// NewReleaseCorrelationCompleted builds the per-SBOM completion fact.
func NewReleaseCorrelationCompleted(releaseID, sbomID, cause string, at time.Time) ReleaseCorrelationCompleted {
	return ReleaseCorrelationCompleted{
		ReleaseID: releaseID, SBOMID: sbomID, Cause: cause, OccurredAt: at.UTC(),
	}
}

// NewComponentMatched builds the correlation event for a release's matched components.
func NewComponentMatched(f Faultline, releaseID string, components []MatchedComponent, at time.Time) ComponentMatched {
	return ComponentMatched{
		FaultlineID: f.ID(),
		CVE:         f.CVE().String(),
		ReleaseID:   releaseID,
		Components:  append([]MatchedComponent(nil), components...),
		Score:       f.View().Score(),
		Priority:    f.View().Priority(),
		Fixes:       append([]FixedVersion(nil), f.View().Fixes...),
		OccurredAt:  at.UTC(),
	}
}

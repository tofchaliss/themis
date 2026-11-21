package domain

import (
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Per-component CVSS selection (EDR-SCORING-01 4.1-4.4, S4, shadow).
//
// SelectComponentScore runs the nine selection steps of EDR 4.1 for ONE component of a Finding
// and returns the complete candidate evaluation (EDR 8.1): every candidate publication with
// exactly one disposition and, where 4.1b requires it, one reason; the identity roles; the
// outcome, conditions, diagnostic flags and score status; and the three scores. It is pure and
// deterministic: the same inputs give the same result whatever order the candidates arrive in.
// Nothing here reads priority or changes a Finding (EDR 8.6).

// Policy versions recorded on every result. A change to any table below is a new version and a
// `selection_policy_changed` / `classification_changed` / `temporal_policy_changed` trigger.
const (
	// ScoreSelectionPolicyVersion covers steps 1-9, the dispositions and the representative rule.
	ScoreSelectionPolicyVersion = "select-1"
	// ScoreClassPolicyVersion covers the class table, the vendor map and the CNA source. The
	// assessor-pair precedence table is empty in this version.
	ScoreClassPolicyVersion = "class-1"
	// ScoreApplicabilityPolicyVersion covers how an effective context is read against a component
	// and the context order used for specificity.
	ScoreApplicabilityPolicyVersion = "applicability-1"
	// ScoreTemporalPolicyVersion is the day-one temporal policy: it accepts only the RL:O row (a
	// published fix applicable to this component). KEV E:F is mapped but only proposed (D22).
	ScoreTemporalPolicyVersion = "temporal-1"
	// ScoreCalculatorVersion names the kernel calculator the scores come from.
	ScoreCalculatorVersion = "kernel-cvss3-1"
)

// CVEOrgCNAPublisher is the publisher value of a rating found in a CVE.org record's CNA
// container. Its assessor is the CVE's CNA (EDR 4.1 relationship table).
const CVEOrgCNAPublisher = "cve.org/cna"

// SelectionClass is the class of one publication for one component (EDR 4.1 step 3).
type SelectionClass string

// The six classes, highest first.
const (
	ClassVendorPlatform SelectionClass = "vendor_platform"
	ClassCNA            SelectionClass = "cna"
	ClassADP            SelectionClass = "adp"
	ClassNVDAnalyst     SelectionClass = "nvd_analyst"
	ClassOtherAssessor  SelectionClass = "other_assessor"
	ClassUnattributed   SelectionClass = "unattributed"
)

var classOrder = []SelectionClass{ClassVendorPlatform, ClassCNA, ClassADP, ClassNVDAnalyst, ClassOtherAssessor, ClassUnattributed}

func classRank(c SelectionClass) int {
	for i, x := range classOrder {
		if x == c {
			return i
		}
	}
	return len(classOrder)
}

// vendorMap is the class policy's distro family -> assessor table. Nothing is guessed from
// names: a family not listed has no vendor_platform rating.
var vendorMap = map[string][]string{
	value.FamilyEnterpriseLinux: {"redhat"},
}

// The assessor keys the class table names (Knowledge's normalised assessor).
const (
	assessorADP = "cisa-adp"
	assessorNVD = "nvd"
)

// Applicability of a publication's effective context to a component (step 2).
type Applicability string

// The three outcomes.
const (
	Applies      Applicability = "applies"
	DoesNotApply Applicability = "does_not_apply"
	Unresolved   Applicability = "unresolved"
)

// Calculability of a candidate's vector.
const (
	CalcCalculable  = "calculable"
	CalcUnsupported = "unsupported"
	CalcInvalid     = "invalid"
	CalcNoVector    = "no_vector"
)

// Outcomes, conditions, flags, statuses and unscored reasons (EDR 4.1a, 5 item 6).
const (
	OutcomeSelected   = "selected"
	OutcomeContested  = "contested"
	OutcomeUnresolved = "unresolved"

	CondIndependentDisagreement = "independent_assessor_disagreement"
	CondSelfInconsistency       = "assessor_self_inconsistency"
	CondUnscorablePeer          = "unscorable_peer_assessment"
	CondHigherClassUnresolved   = "higher_class_unresolved"
	CondSameClassUnresolved     = "same_class_unresolved"

	FlagPeerRatingInvalid = "peer_rating_invalid"
	FlagContextAmbiguity  = "context_ambiguity"

	ScoreFinal       = "final"
	ScoreProvisional = "provisional"
	ScoreUnavailable = "unavailable"

	UnscoredUnsupported       = "unsupported_cvss_version"
	UnscoredInvalid           = "invalid_vector"
	UnscoredNoCalculable      = "no_calculable_rating"
	UnscoredNoVector          = "no_vector"
	UnscoredNoApplicable      = "no_applicable_rating"
	UnscoredApplicabilityOpen = "rating_applicability_unresolved"
)

// Identity roles and publication dispositions (EDR 4.1b).
const (
	RoleSelected    = "selected"
	RoleAgreeing    = "agreeing"
	RoleConcurring  = "concurring"
	RoleCompeting   = "competing"
	RoleNotSelected = "not_selected"
	RoleNotCompared = "not_compared"
	RoleUnresolved  = "unresolved"

	DispReference            = "reference"
	DispSupporting           = "supporting"
	DispCompeting            = "competing"
	DispUnresolved           = "unresolved"
	DispAvailableNotSelected = "available_not_selected"
	DispAvailableNotCompared = "available_not_compared"
	DispNotSelected          = "not_selected"
	DispRejected             = "rejected"

	ReasonSameIdentity               = "same_identity"
	ReasonHigherClass                = "higher_class"
	ReasonSameClass                  = "same_class"
	ReasonDiffersFromCompeting       = "differs_from_competing_vectors"
	ReasonCannotAffect               = "cannot_affect"
	ReasonSameVectorAsCompeting      = "same_vector_as_competing_identity"
	ReasonLowerVersionUnresolved     = "lower_supported_version_unresolved"
	ReasonLowerClass                 = "lower_class"
	ReasonUnsupportedPeer            = "unsupported_peer"
	ReasonUnsupportedSameAssessor    = "unsupported_same_assessor"
	ReasonUnsupportedOnly            = "unsupported_only"
	ReasonUnsupportedLowerClass      = "unsupported_lower_class"
	ReasonInvalidPeer                = "invalid_peer"
	ReasonInvalidVector              = "invalid_vector"
	ReasonInvalidLowerClass          = "invalid_lower_class"
	ReasonLessSpecificSameAssessor   = "less_specific_same_assessor"
	ReasonLowerSupportedVersion      = "lower_supported_version"
	ReasonInactive                   = "inactive"
	ReasonDoesNotApply               = "does_not_apply"
	RelationIndependentAgreement     = "independent_agreement"
	RelationSameAssessorIncomparable = "same_assessor_incomparable_context"
)

// ScoreCandidate is one source publication of the CVE, as Knowledge's ratings API states it.
type ScoreCandidate struct {
	RatingID string
	// Source, DocumentRef and Revision make the canonical publication key (step 7). Revision is
	// the observation's source revision, or its content fingerprint when the source states none.
	Source      string
	DocumentRef string
	Revision    string
	Feed        string
	Publisher   string
	// Assessor is Knowledge's normalised assessor key; empty = unknown.
	Assessor         string
	NVDType          string
	Version          string
	Vector           string
	AssertedContext  string
	InheritedContext string
	// Active is false once the publication was superseded or withdrawn (EDR 3.4).
	Active bool
	// Validation is Knowledge's RatingValidation result (valid | invalid_vector |
	// unsupported_cvss_version); empty when none was read, and then derived here.
	Validation       string
	ValidationReason string
	// IdentityKey is the AssessmentIdentity under Knowledge's latest grouping.
	IdentityKey string
	// SourceUpdatedAt is the normalised UTC source time; zero = missing or unparseable.
	SourceUpdatedAt time.Time
}

// ScoreComponent is the component being assessed.
type ScoreComponent struct {
	PURL    string
	Name    string
	Version string
	// SourcePackage is the source package the component was built from, when known.
	SourcePackage string
	ClaimClass    string
	VerdictState  string
	// FixApplicable is true when a published fix is attributable to this open component (the
	// RL:O evidence of EDR 4.3).
	FixApplicable bool
}

// RequirementValue is one of CR / IR / AR with the level it resolved from (EDR 4.4).
type RequirementValue struct {
	Value string `json:"value"`
	Level string `json:"level"`
}

// ScoreRequirements are the release's resolved security requirements.
type ScoreRequirements struct {
	CR RequirementValue `json:"cr"`
	IR RequirementValue `json:"ir"`
	AR RequirementValue `json:"ar"`
}

// ScoreInput is everything one selection reads.
type ScoreInput struct {
	CVE          string
	Candidates   []ScoreCandidate
	Requirements ScoreRequirements
	// KEV is true when the CVE is in CISA KEV: E:F is proposed, never used under temporal-1.
	KEV bool
}

// TemporalMetric is one temporal metric's state (EDR 4.3: evidence, proposal and value used are
// separate fields).
type TemporalMetric struct {
	Metric   string `json:"metric"`
	Evidence string `json:"evidence,omitempty"`
	Proposed string `json:"proposed,omitempty"`
	// State is not_defined | proposed | accepted_by_policy | accepted_by_user.
	State string `json:"state"`
	Used  string `json:"used"`
}

// Temporal metric states.
const (
	MetricNotDefined       = "not_defined"
	MetricProposed         = "proposed"
	MetricAcceptedByPolicy = "accepted_by_policy"
)

// Scores are the three CVSS scores of one vector.
type Scores struct {
	Base          float64 `json:"base"`
	Temporal      float64 `json:"temporal"`
	Environmental float64 `json:"environmental"`
}

// CandidateEvaluation is one candidate publication's complete evaluation (EDR 8.1).
type CandidateEvaluation struct {
	RatingID         string         `json:"rating_id"`
	IdentityKey      string         `json:"identity_key"`
	Assessor         string         `json:"assessor,omitempty"`
	Publisher        string         `json:"publisher,omitempty"`
	Feed             string         `json:"feed,omitempty"`
	Source           string         `json:"source,omitempty"`
	DocumentRef      string         `json:"document_ref,omitempty"`
	Revision         string         `json:"revision,omitempty"`
	Version          string         `json:"cvss_version,omitempty"`
	Vector           string         `json:"vector,omitempty"`
	EffectiveContext string         `json:"effective_context,omitempty"`
	ContextInherited bool           `json:"context_inherited,omitempty"`
	Applicability    Applicability  `json:"applicability,omitempty"`
	Class            SelectionClass `json:"class,omitempty"`
	ClassBasis       string         `json:"class_basis,omitempty"`
	Calculability    string         `json:"calculability"`
	ValidationReason string         `json:"validation_reason,omitempty"`
	Disposition      string         `json:"disposition"`
	Reason           string         `json:"reason,omitempty"`
	// CannotAffect names which D14 exception applied (a or b) when Reason is cannot_affect.
	CannotAffect string `json:"cannot_affect,omitempty"`
	// AssessmentVector is the vector scored for this component: the source's Base metrics plus
	// the assessment's temporal and environmental values. Empty when not calculable.
	AssessmentVector string  `json:"assessment_vector,omitempty"`
	Scores           *Scores `json:"scores,omitempty"`
	// Contribution is the value this candidate put into the score's maximum, or nil.
	Contribution *float64 `json:"contribution,omitempty"`
}

// IdentityEvaluation is one assessment identity's role in the deciding class.
type IdentityEvaluation struct {
	IdentityKey    string `json:"identity_key"`
	Assessor       string `json:"assessor,omitempty"`
	Role           string `json:"role"`
	Representative bool   `json:"representative,omitempty"`
	// Reference is the identity's reference publication when it is a contributor.
	Reference string `json:"reference,omitempty"`
}

// ContributorRelation is one pair of contributing identities.
type ContributorRelation struct {
	A    string `json:"a"`
	B    string `json:"b"`
	Kind string `json:"kind"`
}

// ComponentScore is one component's complete assessment result (EDR 8.1 snapshot, minus the
// revision bookkeeping the app ring adds).
type ComponentScore struct {
	PURL         string `json:"purl"`
	ClaimClass   string `json:"claim_class,omitempty"`
	VerdictState string `json:"verdict_state,omitempty"`
	// Eligible is false for a scope-class component: calculated and shown, never in the roll-up.
	Eligible bool `json:"eligible"`
	// Open is false for a cleared occurrence (EDR 5 item 3).
	Open bool `json:"open"`

	DecidingClass           SelectionClass        `json:"deciding_class,omitempty"`
	Outcome                 string                `json:"outcome,omitempty"`
	ConflictConditions      []string              `json:"conflict_conditions"`
	ApplicabilityConditions []string              `json:"applicability_conditions"`
	Flags                   []string              `json:"flags"`
	Status                  string                `json:"score_status"`
	UnscoredReason          string                `json:"unscored_reason,omitempty"`
	Scores                  *Scores               `json:"scores,omitempty"`
	AssessmentVector        string                `json:"assessment_vector,omitempty"`
	ScoreFrom               string                `json:"score_from,omitempty"`
	Contributing            []string              `json:"contributing_identities"`
	Competing               []string              `json:"competing_identities"`
	Relations               []ContributorRelation `json:"contributor_relations"`
	Representative          string                `json:"representative,omitempty"`
	RepresentativeRating    string                `json:"representative_publication,omitempty"`
	Identities              []IdentityEvaluation  `json:"identities"`
	Candidates              []CandidateEvaluation `json:"candidates"`
	Temporal                []TemporalMetric      `json:"temporal"`
	Requirements            ScoreRequirements     `json:"requirements"`

	CalculatorVersion   string `json:"calculator_version"`
	SelectionPolicy     string `json:"selection_policy"`
	ClassPolicy         string `json:"class_policy"`
	ApplicabilityPolicy string `json:"applicability_policy"`
	TemporalPolicy      string `json:"temporal_policy"`
}

// candidate is the working state of one publication during selection.
type candidate struct {
	in       ScoreCandidate
	eval     CandidateEvaluation
	identity string
	calc     string
	version  value.CVSS3Version
	normVec  string
	env      float64
	applied  applyResult
	done     bool // disposition decided
}

func (c *candidate) set(disposition, reason string) {
	c.eval.Disposition, c.eval.Reason, c.done = disposition, reason, true
}

func (c *candidate) contribute(v float64) {
	x := v
	c.eval.Contribution = &x
}

func (c *candidate) applicable() bool { return c.eval.Applicability == Applies }
func (c *candidate) unresolved() bool { return c.eval.Applicability == Unresolved }
func (c *candidate) calculable() bool { return c.calc == CalcCalculable }

// SelectComponentScore runs EDR 4.1 steps 1-9 for one component.
func SelectComponentScore(comp ScoreComponent, in ScoreInput) ComponentScore {
	out := ComponentScore{
		PURL: comp.PURL, ClaimClass: comp.ClaimClass, VerdictState: comp.VerdictState,
		Eligible: comp.ClaimClass != ClaimScope, Open: comp.VerdictState != "cleared_vendor_fix",
		ConflictConditions: []string{}, ApplicabilityConditions: []string{}, Flags: []string{},
		Contributing: []string{}, Competing: []string{}, Relations: []ContributorRelation{},
		Identities: []IdentityEvaluation{}, Candidates: []CandidateEvaluation{},
		Requirements: in.Requirements, CalculatorVersion: ScoreCalculatorVersion,
		SelectionPolicy: ScoreSelectionPolicyVersion, ClassPolicy: ScoreClassPolicyVersion,
		ApplicabilityPolicy: ScoreApplicabilityPolicyVersion, TemporalPolicy: ScoreTemporalPolicyVersion,
	}
	out.Temporal = temporalMetrics(comp, in.KEV)
	suffix := assessmentSuffix(out.Temporal, in.Requirements)

	cands := prepare(comp, in, suffix)
	s := &selection{comp: comp, out: &out, cands: cands}
	s.run(in)
	for _, c := range cands {
		out.Candidates = append(out.Candidates, c.eval)
	}
	return out
}

// prepare builds the working candidates in canonical order and runs steps 1-3.
func prepare(comp ScoreComponent, in ScoreInput, suffix string) []*candidate {
	cna := map[string]string{}
	for _, c := range in.Candidates {
		if c.Publisher == CVEOrgCNAPublisher && c.Assessor != "" {
			if prev, ok := cna[c.Assessor]; !ok || c.RatingID < prev {
				cna[c.Assessor] = c.RatingID
			}
		}
	}
	family := value.ScopeFromComponent(comp.PURL, comp.Version).Family
	out := make([]*candidate, 0, len(in.Candidates))
	for _, r := range in.Candidates {
		c := &candidate{in: r, identity: r.IdentityKey}
		if c.identity == "" {
			c.identity = "rating:" + r.RatingID
		}
		c.calc, c.version, c.normVec = calculability(r)
		c.eval = CandidateEvaluation{
			RatingID: r.RatingID, IdentityKey: c.identity, Assessor: r.Assessor, Publisher: r.Publisher,
			Feed: r.Feed, Source: r.Source, DocumentRef: r.DocumentRef, Revision: r.Revision,
			Version: r.Version, Vector: r.Vector, Calculability: c.calc, ValidationReason: r.ValidationReason,
		}
		if c.calc == CalcCalculable {
			vec := baseVector(c.normVec) + suffix
			sc := mustScores(vec)
			c.eval.AssessmentVector, c.eval.Scores, c.env = vec, &sc, sc.Environmental
		}
		out = append(out, c)
		// Step 1.
		if !r.Active {
			c.set(DispRejected, ReasonInactive)
			continue
		}
		// Step 2, from the effective context (D12).
		ctx := r.AssertedContext
		if strings.TrimSpace(ctx) == "" {
			ctx, c.eval.ContextInherited = r.InheritedContext, strings.TrimSpace(r.InheritedContext) != ""
		}
		c.eval.EffectiveContext = ctx
		c.applied = applyContext(ctx, strings.TrimSpace(r.AssertedContext) != "", comp, family)
		c.eval.Applicability = c.applied.result
		if c.applied.result == DoesNotApply {
			c.set(DispRejected, ReasonDoesNotApply)
			continue
		}
		// Step 3.
		c.eval.Class, c.eval.ClassBasis = classify(r, c.applied, strings.TrimSpace(r.AssertedContext) != "", family, cna)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].in.RatingID < out[j].in.RatingID })
	return out
}

// calculability derives whether a candidate's vector can be scored (EDR 3.5, 4.1a "calculable").
// Knowledge's RatingValidation decides when present; otherwise the kernel parser does.
func calculability(r ScoreCandidate) (string, value.CVSS3Version, string) {
	vec := strings.TrimSpace(r.Vector)
	if vec == "" {
		return CalcNoVector, "", ""
	}
	parsed, err := value.ParseCVSS3(vec)
	switch r.Validation {
	case "unsupported_cvss_version":
		return CalcUnsupported, "", vec
	case "invalid_vector":
		return CalcInvalid, "", vec
	}
	if err == nil {
		return CalcCalculable, parsed.Version(), parsed.String()
	}
	if strings.HasPrefix(vec, "CVSS:3.") || strings.HasPrefix(strings.TrimSpace(r.Version), "3") {
		return CalcInvalid, "", vec
	}
	return CalcUnsupported, "", vec
}

// classify is step 3. vendor_platform needs the context to name the platform, or to ASSERT the
// package: a product list the publication inherited (an NVD copy of a vendor rating) names a
// product, not the vendor's platform statement, so the copy is classed by its other relations
// (EDR 4.1 step 6 example: the NVD copy is cna).
func classify(r ScoreCandidate, a applyResult, asserted bool, family string, cna map[string]string) (SelectionClass, string) {
	if family != "" && (a.platformNamed || (asserted && a.packageNamed)) {
		for _, v := range vendorMap[family] {
			if v == r.Assessor {
				return ClassVendorPlatform, "assessor " + r.Assessor + " = vendor of family " + family + " per vendor map " + ScoreClassPolicyVersion
			}
		}
	}
	if id, ok := cna[r.Assessor]; ok {
		return ClassCNA, "assessor " + r.Assessor + " = CNA per CVE.org CNA container publication " + id
	}
	switch {
	case r.Assessor == assessorADP:
		return ClassADP, "assessor " + r.Assessor + " = CISA ADP"
	case r.Assessor == assessorNVD:
		return ClassNVDAnalyst, "assessor " + r.Assessor + " = NVD"
	case r.Assessor != "":
		return ClassOtherAssessor, "assessor " + r.Assessor + " known, no higher class"
	}
	return ClassUnattributed, "assessor unknown"
}

// selection carries one run of steps 4-9.
type selection struct {
	comp  ScoreComponent
	out   *ComponentScore
	cands []*candidate
}

func (s *selection) run(in ScoreInput) {
	// Step 4: the deciding class.
	deciding := SelectionClass("")
	for _, c := range s.cands {
		if c.done {
			continue
		}
		if deciding == "" || classRank(c.eval.Class) < classRank(deciding) {
			deciding = c.eval.Class
		}
	}
	if deciding == "" {
		// Step 8.
		s.noOutcome(noCandidateReason(in.Candidates))
		return
	}
	s.out.DecidingClass = deciding
	var class, lower []*candidate
	defer s.remainingRoles(&class)
	for _, c := range s.cands {
		switch {
		case c.done:
		case c.eval.Class == deciding:
			class = append(class, c)
		default:
			lower = append(lower, c)
		}
	}
	for _, c := range lower {
		switch {
		case c.unresolved():
			c.set(DispUnresolved, ReasonLowerClass)
		case c.calculable():
			c.set(DispAvailableNotSelected, ReasonLowerClass)
		case c.calc == CalcUnsupported:
			c.set(DispAvailableNotCompared, ReasonUnsupportedLowerClass)
		default:
			c.set(DispAvailableNotCompared, ReasonInvalidLowerClass)
		}
	}

	// Step 5: version inside one assessor (D27), then step 5a.
	s.lowerSupportedVersion(class)
	var scoring, unresolved, notCalc []*candidate
	scoringAssessors := map[string]bool{}
	for _, c := range class {
		switch {
		case c.done:
		case c.unresolved():
			unresolved = append(unresolved, c)
		case c.calculable():
			scoring = append(scoring, c)
			scoringAssessors[c.in.Assessor] = true
		default:
			notCalc = append(notCalc, c)
		}
	}
	if len(scoring) == 0 {
		s.noScoring(unresolved, notCalc, lower)
		return
	}
	for _, c := range notCalc {
		switch {
		case c.calc == CalcUnsupported && scoringAssessors[c.in.Assessor]:
			c.set(DispAvailableNotCompared, ReasonUnsupportedSameAssessor)
		case c.calc == CalcUnsupported:
			c.set(DispAvailableNotCompared, ReasonUnsupportedPeer)
			s.out.ConflictConditions = addOnce(s.out.ConflictConditions, CondUnscorablePeer)
		case scoringAssessors[c.in.Assessor]:
			c.set(DispAvailableNotCompared, ReasonInvalidVector)
		default:
			c.set(DispAvailableNotCompared, ReasonInvalidPeer)
			s.out.Flags = addOnce(s.out.Flags, FlagPeerRatingInvalid)
		}
	}
	s.compete(scoring, unresolved)
}

// remainingRoles gives the identities of the deciding class that hold no contributing,
// competing or not_selected role theirs: not_compared before unresolved.
func (s *selection) remainingRoles(class *[]*candidate) {
	for _, want := range []string{DispAvailableNotCompared, DispUnresolved} {
		for _, c := range *class {
			if c.eval.Disposition != want {
				continue
			}
			role := RoleUnresolved
			if want == DispAvailableNotCompared {
				role = RoleNotCompared
			}
			s.role(c.identity, c.in.Assessor, role)
		}
	}
}

// lowerSupportedVersion is D27: an assessor's applicable, calculable 3.1 identities in the
// deciding class set its 3.0 ones aside.
func (s *selection) lowerSupportedVersion(class []*candidate) {
	has31 := map[string]bool{}
	for _, c := range class {
		if c.applicable() && c.calculable() && c.version == value.CVSS31 {
			has31[c.in.Assessor] = true
		}
	}
	for _, c := range class {
		if !has31[c.in.Assessor] || c.version != value.CVSS30 {
			continue
		}
		switch {
		case c.applicable():
			c.set(DispNotSelected, ReasonLowerSupportedVersion)
			s.role(c.identity, c.in.Assessor, RoleNotSelected)
		case c.unresolved():
			c.set(DispUnresolved, ReasonLowerVersionUnresolved)
		}
	}
}

// noScoring handles step 5a's last two rows: outcome unresolved, or no outcome.
func (s *selection) noScoring(unresolved, notCalc, lower []*candidate) {
	if len(unresolved) == 0 {
		unsupported, invalid := 0, 0
		for _, c := range notCalc {
			if c.calc == CalcUnsupported {
				unsupported++
				c.set(DispAvailableNotCompared, ReasonUnsupportedOnly)
			} else {
				invalid++
				c.set(DispAvailableNotCompared, ReasonInvalidVector)
			}
		}
		switch {
		case invalid == 0:
			s.noOutcome(UnscoredUnsupported)
		case unsupported == 0:
			s.noOutcome(UnscoredInvalid)
		default:
			s.noOutcome(UnscoredNoCalculable)
		}
		return
	}
	s.out.Outcome = OutcomeUnresolved
	s.out.ApplicabilityConditions = addOnce(s.out.ApplicabilityConditions, CondHigherClassUnresolved)
	for _, c := range notCalc {
		if c.calc == CalcUnsupported {
			c.set(DispAvailableNotCompared, ReasonUnsupportedOnly)
		} else {
			c.set(DispAvailableNotCompared, ReasonInvalidVector)
		}
	}
	var best *candidate
	for _, c := range unresolved {
		c.set(DispUnresolved, ReasonHigherClass)
		if c.calculable() {
			c.contribute(c.env)
			best = higher(best, c)
		}
	}
	if best == nil {
		// D4: nothing unresolved is calculable; the lower class is not used.
		s.unavailable(UnscoredApplicabilityOpen)
		return
	}
	for _, c := range lower {
		if c.applicable() && c.calculable() {
			c.contribute(c.env)
			best = higher(best, c)
		}
	}
	s.score(best, ScoreProvisional)
}

// compete runs step 6 on the scoring candidates and classifies the unresolved ones.
func (s *selection) compete(scoring, unresolved []*candidate) {
	ids := groupIdentities(scoring)
	// Step 6.2: specificity inside one assessor, among comparable asserted contexts.
	var remaining []*identity
	for _, id := range ids {
		dominated := false
		for _, other := range ids {
			if other != id && other.assessor == id.assessor && moreSpecific(other.context, id.context) {
				dominated = true
				break
			}
		}
		if dominated {
			s.role(id.key, id.assessor, RoleNotSelected)
			for _, c := range id.pubs {
				c.set(DispNotSelected, ReasonLessSpecificSameAssessor)
			}
			continue
		}
		remaining = append(remaining, id)
	}
	vectors := map[string]bool{}
	for _, id := range remaining {
		vectors[id.vector] = true
	}
	if len(vectors) > 1 {
		s.contested(remaining, unresolved)
		return
	}
	s.selected(remaining, unresolved)
}

func (s *selection) contested(competing []*identity, unresolved []*candidate) {
	s.out.Outcome = OutcomeContested
	competingKeys := map[string]bool{}
	competingVec := map[string]bool{}
	var best *candidate
	for _, id := range competing {
		competingKeys[id.key] = true
		competingVec[id.vector] = true
		s.out.Competing = append(s.out.Competing, id.key)
		s.role(id.key, id.assessor, RoleCompeting)
		reason := CondSelfInconsistency
		for _, other := range competing {
			if other.assessor != id.assessor && other.vector != id.vector {
				reason = CondIndependentDisagreement
			}
		}
		for _, other := range competing {
			if other != id && other.vector != id.vector {
				if other.assessor == id.assessor {
					s.out.ConflictConditions = addOnce(s.out.ConflictConditions, CondSelfInconsistency)
				} else {
					s.out.ConflictConditions = addOnce(s.out.ConflictConditions, CondIndependentDisagreement)
				}
			}
		}
		for _, c := range id.pubs {
			c.set(DispCompeting, reason)
			c.contribute(c.env)
			best = higher(best, c)
		}
	}
	// D26 rule 6 and D28.
	for _, u := range unresolved {
		switch {
		case competingKeys[u.identity], u.calculable() && competingVec[u.normVec]:
			u.set(DispUnresolved, ReasonSameVectorAsCompeting)
		case u.calculable():
			u.set(DispUnresolved, ReasonDiffersFromCompeting)
			u.contribute(u.env)
			best = higher(best, u)
			s.out.ApplicabilityConditions = addOnce(s.out.ApplicabilityConditions, CondSameClassUnresolved)
		default:
			u.set(DispUnresolved, ReasonSameClass)
			s.out.ApplicabilityConditions = addOnce(s.out.ApplicabilityConditions, CondSameClassUnresolved)
		}
	}
	sort.Strings(s.out.Competing)
	s.score(best, ScoreProvisional)
}

func (s *selection) selected(contributing []*identity, unresolved []*candidate) {
	s.out.Outcome = OutcomeSelected
	assessors := map[string]bool{}
	for _, id := range contributing {
		assessors[id.assessor] = true
	}
	role := RoleSelected
	switch {
	case len(contributing) > 1 && len(assessors) > 1:
		role = RoleAgreeing
	case len(contributing) > 1:
		role = RoleConcurring
	}
	keys := map[string]bool{}
	for _, id := range contributing {
		keys[id.key] = true
		s.out.Contributing = append(s.out.Contributing, id.key)
		r := referenceOf(id.pubs)
		for _, c := range id.pubs {
			if c == r {
				c.set(DispReference, "")
			} else {
				c.set(DispSupporting, ReasonSameIdentity)
			}
		}
		s.role(id.key, id.assessor, role)
		s.setReference(id.key, r.in.RatingID)
	}
	sort.Strings(s.out.Contributing)
	// Representative (D24): smallest canonical identity key.
	rep := contributing[0]
	for _, id := range contributing[1:] {
		if id.canonicalKey() < rep.canonicalKey() {
			rep = id
		}
	}
	s.out.Representative = rep.key
	s.out.RepresentativeRating = referenceOf(rep.pubs).in.RatingID
	for i := range s.out.Identities {
		if s.out.Identities[i].IdentityKey == rep.key {
			s.out.Identities[i].Representative = true
		}
	}
	// Contributor relations.
	for i := 0; i < len(contributing); i++ {
		for j := i + 1; j < len(contributing); j++ {
			a, b := contributing[i], contributing[j]
			kind := RelationIndependentAgreement
			if a.assessor == b.assessor {
				kind = RelationSameAssessorIncomparable
				s.out.Flags = addOnce(s.out.Flags, FlagContextAmbiguity)
			}
			// contributing is sorted by key, so a.key < b.key.
			s.out.Relations = append(s.out.Relations, ContributorRelation{A: a.key, B: b.key, Kind: kind})
		}
	}
	sort.Slice(s.out.Relations, func(i, j int) bool {
		if s.out.Relations[i].A != s.out.Relations[j].A {
			return s.out.Relations[i].A < s.out.Relations[j].A
		}
		return s.out.Relations[i].B < s.out.Relations[j].B
	})
	vector := contributing[0].vector
	repRef := referenceOf(rep.pubs)
	best := repRef
	// D10 / D14 for the unresolved candidates of the deciding class.
	for _, u := range unresolved {
		if keys[u.identity] || (u.calculable() && u.normVec == vector) {
			u.set(DispUnresolved, ReasonCannotAffect)
			u.eval.CannotAffect = "a"
			continue
		}
		if exceptionB(u, contributing) {
			u.set(DispUnresolved, ReasonCannotAffect)
			u.eval.CannotAffect = "b"
			continue
		}
		u.set(DispUnresolved, ReasonSameClass)
		s.out.ApplicabilityConditions = addOnce(s.out.ApplicabilityConditions, CondSameClassUnresolved)
		if u.calculable() {
			u.contribute(u.env)
			if u.env > best.env {
				best = u
			}
		}
	}
	status := ScoreFinal
	if len(s.out.ConflictConditions)+len(s.out.ApplicabilityConditions) > 0 {
		status = ScoreProvisional
		repRef.contribute(repRef.env)
	}
	s.score(best, status)
}

// exceptionB is D21: same assessor, both contexts asserted, the selected one strictly more
// specific and comparable.
func exceptionB(u *candidate, contributing []*identity) bool {
	uctx := strings.TrimSpace(u.in.AssertedContext)
	if uctx == "" {
		return false
	}
	for _, id := range contributing {
		if id.assessor == u.in.Assessor && id.context != "" && moreSpecific(id.context, NormaliseScoreContext(uctx)) {
			return true
		}
	}
	return false
}

func (s *selection) setReference(identityKey, ratingID string) {
	for i := range s.out.Identities {
		if s.out.Identities[i].IdentityKey == identityKey {
			s.out.Identities[i].Reference = ratingID
		}
	}
}

// role records an identity role once; the first role given wins (contributing and competing
// roles are given before unresolved ones).
func (s *selection) role(key, assessor, role string) {
	for _, id := range s.out.Identities {
		if id.IdentityKey == key {
			return
		}
	}
	s.out.Identities = append(s.out.Identities, IdentityEvaluation{IdentityKey: key, Assessor: assessor, Role: role})
	sort.Slice(s.out.Identities, func(i, j int) bool { return s.out.Identities[i].IdentityKey < s.out.Identities[j].IdentityKey })
}

func (s *selection) noOutcome(reason string) {
	s.out.Outcome = ""
	s.unavailable(reason)
}

func (s *selection) unavailable(reason string) {
	s.out.Status, s.out.UnscoredReason = ScoreUnavailable, reason
}

func (s *selection) score(from *candidate, status string) {
	sc := *from.eval.Scores
	s.out.Scores, s.out.AssessmentVector, s.out.ScoreFrom, s.out.Status = &sc, from.eval.AssessmentVector, from.in.RatingID, status
}

func higher(best, c *candidate) *candidate {
	if best == nil || c.env > best.env {
		return c
	}
	return best
}

func noCandidateReason(all []ScoreCandidate) string {
	for _, c := range all {
		if strings.TrimSpace(c.Vector) != "" {
			return UnscoredNoApplicable
		}
	}
	return UnscoredNoVector
}

func addOnce(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// identity is one assessment identity's scoring candidates in the deciding class.
type identity struct {
	key      string
	assessor string
	version  string
	vector   string
	context  string // normalised asserted context; "" = unstated
	pubs     []*candidate
}

// canonicalKey is the representative rule (D24): assessor, version, vector, context as bytes.
func (id *identity) canonicalKey() string {
	return id.assessor + "\x00" + id.version + "\x00" + id.vector + "\x00" + id.context
}

func groupIdentities(scoring []*candidate) []*identity {
	byKey := map[string]*identity{}
	var out []*identity
	for _, c := range scoring {
		id, ok := byKey[c.identity]
		if !ok {
			id = &identity{key: c.identity, assessor: c.in.Assessor, version: string(c.version), vector: c.normVec}
			byKey[c.identity] = id
			out = append(out, id)
		}
		if ctx := strings.TrimSpace(c.in.AssertedContext); ctx != "" && id.context == "" {
			id.context = NormaliseScoreContext(ctx)
		}
		id.pubs = append(id.pubs, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// referenceOf is step 7: asserted over inherited, own publication over a copy, newest source
// time (known before missing), then the canonical publication key.
func referenceOf(pubs []*candidate) *candidate {
	best := pubs[0]
	for _, c := range pubs[1:] {
		if referenceBefore(c, best) {
			best = c
		}
	}
	return best
}

func referenceBefore(a, b *candidate) bool {
	aa, ba := strings.TrimSpace(a.in.AssertedContext) != "", strings.TrimSpace(b.in.AssertedContext) != ""
	if aa != ba {
		return aa
	}
	ao, bo := a.in.Publisher != "" && a.in.Publisher == a.in.Assessor, b.in.Publisher != "" && b.in.Publisher == b.in.Assessor
	if ao != bo {
		return ao
	}
	at, bt := a.in.SourceUpdatedAt, b.in.SourceUpdatedAt
	if at.IsZero() != bt.IsZero() {
		return !at.IsZero()
	}
	if !at.Equal(bt) {
		return at.After(bt)
	}
	return publicationKey(a.in) < publicationKey(b.in)
}

func publicationKey(c ScoreCandidate) string {
	return c.Source + "\x00" + c.DocumentRef + "\x00" + c.Revision + "\x00" + c.RatingID
}

// ScoreBand is the CVSS 3.x qualitative rating of a score.
func ScoreBand(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}

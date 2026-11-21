package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Source ratings (EDR-SCORING-01 section 3, S2).
//
// This file is source truth only: what a source published, when Themis saw it, and what Themis
// can compute from a rating on its own. It selects nothing and decides nothing; selection is
// Governance's (EDR 4.1). Every record here is immutable. Lifecycle (superseded / withdrawn) and
// identity grouping are separate append-only records, and the current status of a rating is
// derived from them, never stored on the rating.

// SourceTimeInterpretation says how Themis read a source's own "updated at" value (EDR 3.1).
type SourceTimeInterpretation string

// The interpretations. An empty interpretation means the source gave no value at all.
const (
	TimeZoneStated     SourceTimeInterpretation = "zone_stated"
	TimeZoneAssumedUTC SourceTimeInterpretation = "zone_assumed_utc"
	TimeUnparseable    SourceTimeInterpretation = "unparseable"
)

// SourceTime is a source's own timestamp kept as three values: the original text, the UTC
// instant (zero when there is no valid interpretation), and how the instant was obtained. The
// instant is never presented as the source's own assertion.
type SourceTime struct {
	Original       string
	Instant        time.Time
	Interpretation SourceTimeInterpretation
}

var (
	zonedLayouts    = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999-0700", "2006-01-02T15:04:05-0700"}
	zonelessLayouts = []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"}
)

// ParseSourceTime applies the ingestion contract "a zone-less value is UTC": a value with a zone
// is zone_stated, one without is zone_assumed_utc, anything else is unparseable (no instant).
func ParseSourceTime(original string) SourceTime {
	s := strings.TrimSpace(original)
	if s == "" {
		return SourceTime{}
	}
	for _, l := range zonedLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return SourceTime{Original: original, Instant: t.UTC(), Interpretation: TimeZoneStated}
		}
	}
	for _, l := range zonelessLayouts {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			return SourceTime{Original: original, Instant: t, Interpretation: TimeZoneAssumedUTC}
		}
	}
	return SourceTime{Original: original, Interpretation: TimeUnparseable}
}

// PublishedRating is one CVSS assessment as a source carried it, before Themis records it.
type PublishedRating struct {
	// Assessor is who produced the rating (the CNA, NVD, the vendor). Publisher is where it was
	// published, and the observation's Feed is how Themis collected it; the three stay separate.
	Assessor  string
	Publisher string
	// NVDType is Primary or Secondary when the rating came from NVD, else empty.
	NVDType string
	// Version is the CVSS version: "2.0", "3.0", "3.1" or "4.0".
	Version string
	Vector  string
	// StatedScore is the source's own number; HasStatedScore is false when it gave none.
	StatedScore    float64
	HasStatedScore bool
	SeverityWord   string
	// AssertedContext is the product / package this publication itself says the rating is
	// for. Empty means unstated.
	AssertedContext string
}

// ObservationInput is one source revision as a feed adapter parsed it.
type ObservationInput struct {
	Source      string
	Feed        string
	DocumentRef string
	Revision    string
	UpdatedAt   SourceTime
	// Complete is true only for a successfully fetched, parsed and complete revision. Only a
	// complete revision can withdraw or supersede a rating (EDR 3.4 items 2, 3 and 7).
	Complete      bool
	Applicability []string
	// SeverityWord is a document-level severity without a score (Rocky, EDR O1). Metadata only.
	SeverityWord string
	Ratings      []PublishedRating
	Fetch        FetchMeta
}

// FetchMeta is the transport detail of one fetch. It is recorded on the seen event and never
// part of the observation's fingerprint.
type FetchMeta struct {
	Endpoint     string
	HTTPStatus   int
	ETag         string
	LastModified string
}

// Validate refuses an input that cannot be recorded.
func (in ObservationInput) Validate() error {
	switch {
	case strings.TrimSpace(in.Source) == "":
		return errors.New("rating observation: empty source")
	case strings.TrimSpace(in.DocumentRef) == "":
		return errors.New("rating observation: empty document reference")
	}
	for i, r := range in.Ratings {
		if strings.TrimSpace(r.Assessor) == "" || strings.TrimSpace(r.Vector) == "" {
			return fmt.Errorf("rating observation: rating %d needs an assessor and a vector", i)
		}
	}
	return nil
}

// Fingerprint hashes the canonical form of the fields that carry meaning, so a reformatted but
// identical document is not a new revision (EDR 3.1). Fetch metadata is left out; ratings and
// applicability are sorted; text is trimmed.
func (in ObservationInput) Fingerprint() string {
	keys := make([]string, 0, len(in.Ratings))
	for _, r := range in.Ratings {
		keys = append(keys, r.ContentKey())
	}
	sort.Strings(keys)
	apps := normalisedSet(in.Applicability)
	canon := struct {
		Source, Feed, Doc, Revision, Updated, Word string
		Complete                                   bool
		Applicability, Ratings                     []string
	}{
		Source: strings.TrimSpace(in.Source), Feed: strings.TrimSpace(in.Feed),
		Doc: strings.TrimSpace(in.DocumentRef), Revision: strings.TrimSpace(in.Revision),
		Updated: strings.TrimSpace(in.UpdatedAt.Original), Word: strings.TrimSpace(in.SeverityWord),
		Complete: in.Complete, Applicability: apps, Ratings: keys,
	}
	b, _ := json.Marshal(canon) // a struct of strings and bools always marshals
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalisedSet(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if _, dup := seen[s]; s == "" || dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (r PublishedRating) contentKeyParts() []string {
	score := ""
	if r.HasStatedScore {
		score = fmt.Sprintf("%.1f", r.StatedScore)
	}
	return []string{
		strings.TrimSpace(r.Assessor), strings.TrimSpace(r.Publisher), strings.TrimSpace(r.NVDType),
		strings.TrimSpace(r.Version), strings.TrimSpace(r.Vector), score,
		strings.TrimSpace(r.SeverityWord), strings.TrimSpace(r.AssertedContext),
	}
}

// ContentKey is everything a source published about this rating. Two ratings with the same key
// in the same document are the same publication.
func (r PublishedRating) ContentKey() string { return strings.Join(r.contentKeyParts(), "\x1f") }

// LineageKey is assessor + CVSS version + asserted context (unstated is a value of its own). A
// rating replaced by a different one in the same lineage is superseded, not withdrawn (EDR 3.4
// item 5a).
func (r PublishedRating) LineageKey() string {
	return strings.Join([]string{
		NormaliseAssessor(r.Assessor), strings.TrimSpace(r.Version), NormaliseContext(r.AssertedContext),
	}, "\x1f")
}

// assessorAliases maps the names one assessor goes by in different publishers onto one key:
// NVD names an assessor by its contact address or UUID, CVE.org by its short name. Part of
// LinkPolicyVersion. An assessor not listed keeps its own name, so two names are never merged
// by guess (EDR 3.2: when in doubt, stay distinct).
var assessorAliases = map[string]string{
	"nvd@nist.gov":                         "nvd",
	"secalert@redhat.com":                  "redhat",
	"redhat":                               "redhat",
	"134c704f-9b21-4f2e-91b3-4a467353bcc0": "cisa-adp",
	"cisa-adp":                             "cisa-adp",
	"security-advisories@github.com":       "github_m",
	"github_m":                             "github_m",
	"cve@mitre.org":                        "mitre",
	"mitre":                                "mitre",
}

// NormaliseAssessor folds case and surrounding space, then applies the alias table. It never
// merges two assessors the table does not name.
func NormaliseAssessor(s string) string {
	k := strings.ToLower(strings.TrimSpace(s))
	if a, ok := assessorAliases[k]; ok {
		return a
	}
	return k
}

// NormaliseContext is linking policy LinkPolicyVersion: case and surrounding space folded, the
// ecosystem part of an "ecosystem:package" pair canonicalised. When in doubt two contexts stay
// distinct (EDR 3.2).
func NormaliseContext(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if eco, pkg, ok := strings.Cut(s, ":"); ok && !strings.HasPrefix(s, "cpe:") {
		return value.CanonicalEcosystem(eco) + ":" + pkg
	}
	return s
}

// NormaliseVector returns the canonical vector for a parseable 3.x vector and the trimmed text
// for anything else, so the same assessment written in another metric order links.
func NormaliseVector(vector string) string {
	if v, err := value.ParseCVSS3(vector); err == nil {
		return v.String()
	}
	return strings.TrimSpace(vector)
}

// SourceObservation is one recorded source revision (EDR 3.1). Immutable.
type SourceObservation struct {
	ID              string
	CVE             string
	Source          string
	Feed            string
	DocumentRef     string
	Revision        string
	UpdatedAt       SourceTime
	Fingerprint     string
	Complete        bool
	Applicability   []string
	SeverityWord    string
	FirstObservedAt time.Time
}

// SeenOutcome is the outcome of one fetch.
type SeenOutcome string

// Fetch outcomes recorded today. A failed fetch is a feed-health event (the feed_health table)
// and changes no rating state.
const (
	SeenNewRevision SeenOutcome = "success_new_revision"
	SeenUnchanged   SeenOutcome = "success_unchanged"
)

// SeenEvent is one fetch of a source document (append-only). ObservationID names the revision
// the fetch produced or confirmed.
type SeenEvent struct {
	ObservationID string
	Source        string
	DocumentRef   string
	FetchedAt     time.Time
	Outcome       SeenOutcome
	Fetch         FetchMeta
}

// SourceRating is one publication: a CVSS assessment as carried by one observation. Immutable.
type SourceRating struct {
	ID            string
	ObservationID string
	CVE           string
	Source        string
	DocumentRef   string
	Feed          string
	PublishedRating
	// InheritedContext is the observation's applicability, copied only when the publication
	// asserts none (D12). It is for filtering, never for identity.
	InheritedContext string
	RecordedAt       time.Time
}

// EffectiveContext is the asserted context if present, else the inherited one (EDR 3.2).
func (r SourceRating) EffectiveContext() string {
	if strings.TrimSpace(r.AssertedContext) != "" {
		return r.AssertedContext
	}
	return r.InheritedContext
}

// RatingEventKind is a terminal lifecycle event of one publication.
type RatingEventKind string

// The two terminal kinds (EDR 3.4).
const (
	RatingSuperseded RatingEventKind = "superseded"
	RatingWithdrawn  RatingEventKind = "withdrawn"
)

// RatingStatus is the derived current status of a publication.
type RatingStatus string

// Statuses: no terminal event is active, otherwise the event's kind.
const (
	RatingActive           RatingStatus = "active"
	RatingStatusSuperseded RatingStatus = "superseded"
	RatingStatusWithdrawn  RatingStatus = "withdrawn"
)

// RatingEvent is the one terminal event of a publication (append-only, at most one each).
type RatingEvent struct {
	RatingID string
	Kind     RatingEventKind
	// CausedBy is the observation whose complete revision caused it; ReplacedBy the new
	// publication when superseded.
	CausedBy   string
	ReplacedBy string
	SourceTime SourceTime
	LearnedAt  time.Time
}

// StatusOf derives a publication's current status from its terminal event, if any.
func StatusOf(ev *RatingEvent) RatingStatus {
	switch {
	case ev == nil:
		return RatingActive
	case ev.Kind == RatingSuperseded:
		return RatingStatusSuperseded
	default:
		return RatingStatusWithdrawn
	}
}

// RevisionPlan is what recording one new revision of a document produces: the publications
// to create (new content) and the terminal events on earlier publications.
type RevisionPlan struct {
	New    []PublishedRating
	Events []PlannedEvent
}

// PlannedEvent is a terminal event decided before IDs exist. ReplacedByIndex points into
// RevisionPlan.New; -1 when withdrawn.
type PlannedEvent struct {
	RatingID        string
	Kind            RatingEventKind
	ReplacedByIndex int
}

// PlanRevision applies the lifecycle rules of EDR 3.4 to one new revision of a document.
//
// active are the document's publications with no terminal event. A rating in the revision
// whose content equals an active publication IS that publication, still carried: nothing new is
// recorded for it. Every other rating in the revision is a new publication (also one identical to
// an earlier terminal publication: the old terminal event stands). When the revision is complete,
// an active publication it no longer carries is superseded by a new rating of its lineage, or
// withdrawn when there is none. An incomplete revision changes no lifecycle.
func PlanRevision(active []SourceRating, revision []PublishedRating, complete bool) RevisionPlan {
	carried := map[string]bool{}
	activeKeys := map[string]bool{}
	for _, a := range active {
		activeKeys[a.ContentKey()] = true
	}
	var plan RevisionPlan
	seenNew := map[string]bool{}
	for _, r := range revision {
		k := r.ContentKey()
		if activeKeys[k] {
			carried[k] = true
			continue
		}
		if seenNew[k] {
			continue
		}
		seenNew[k] = true
		plan.New = append(plan.New, r)
	}
	if !complete {
		return plan
	}
	sortedActive := append([]SourceRating(nil), active...)
	sort.Slice(sortedActive, func(i, j int) bool { return sortedActive[i].ID < sortedActive[j].ID })
	for _, a := range sortedActive {
		if carried[a.ContentKey()] {
			continue
		}
		ev := PlannedEvent{RatingID: a.ID, Kind: RatingWithdrawn, ReplacedByIndex: -1}
		for i, n := range plan.New {
			if n.LineageKey() == a.LineageKey() {
				ev.Kind, ev.ReplacedByIndex = RatingSuperseded, i
				break
			}
		}
		plan.Events = append(plan.Events, ev)
	}
	return plan
}

// --- RatingValidation (EDR 3.5) ---------------------------------------------------------------

// CalculatorVersion names the kernel calculator a validation used. A new calculator version
// creates new validations; old ones are never edited.
const CalculatorVersion = "kernel-cvss3-1"

// ValidationResult is the outcome of validating one rating.
type ValidationResult string

// The three results.
const (
	ValidationValid       ValidationResult = "valid"
	ValidationInvalid     ValidationResult = "invalid_vector"
	ValidationUnsupported ValidationResult = "unsupported_cvss_version"
)

// StatedComparison compares the source's number with the computed Base.
type StatedComparison string

// Comparisons. not_stated when the source gave no number; empty when nothing was computed.
const (
	StatedEqual     StatedComparison = "equal"
	StatedDiffers   StatedComparison = "differs"
	StatedNotStated StatedComparison = "not_stated"
)

// RatingValidation is what Themis computes about one publication on its own. Immutable and
// reproducible from the rating plus CalculatorVersion.
type RatingValidation struct {
	RatingID          string
	CalculatorVersion string
	SpecVersion       string
	Result            ValidationResult
	Reason            string
	Base              float64
	// Temporal is computed only from temporal metrics the source itself put in its vector;
	// HasTemporal is false when it put none.
	Temporal    float64
	HasTemporal bool
	Stated      StatedComparison
	ValidatedAt time.Time
}

// ValidateRating validates one publication with the kernel calculator.
func ValidateRating(r SourceRating, at time.Time) RatingValidation {
	out := RatingValidation{RatingID: r.ID, CalculatorVersion: CalculatorVersion, ValidatedAt: at}
	declared := value.CVSSVectorVersion(r.Vector)
	out.SpecVersion = declared
	if declared != "3.0" && declared != "3.1" {
		out.SpecVersion = strings.TrimSpace(r.Version)
		out.Result = ValidationUnsupported
		out.Reason = "CVSS version " + firstNonEmpty(out.SpecVersion, "unknown") + " has no calculator yet"
		return out
	}
	v, err := value.ParseCVSS3(r.Vector)
	if err != nil {
		out.Result = ValidationInvalid
		out.Reason = err.Error()
		return out
	}
	s := v.Scores()
	out.Result, out.Base = ValidationValid, s.Base
	if v.Metric("E") != "X" || v.Metric("RL") != "X" || v.Metric("RC") != "X" {
		out.Temporal, out.HasTemporal = s.Temporal, true
	}
	switch {
	case !r.HasStatedScore:
		out.Stated = StatedNotStated
	case math.Abs(r.StatedScore-s.Base) < 0.05:
		out.Stated = StatedEqual
	default:
		out.Stated = StatedDiffers
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// --- Identity linking (EDR 3.2, 3.2a) --------------------------------------------------------

// LinkPolicyVersion versions normalisation and the linking rule. A change recomputes every set.
const LinkPolicyVersion = "link-1"

const unstatedContext = "<unstated>"

// IdentityMember is one publication as the linking rule sees it.
type IdentityMember struct {
	RatingID        string
	Assessor        string
	Version         string
	Vector          string
	AssertedContext string
	// Active is false once the publication is terminal; it then still belongs to its
	// identity but no longer keeps an identity viable as a link target (D11).
	Active bool
}

// MemberOf builds the linking view of a publication.
func MemberOf(r SourceRating, status RatingStatus) IdentityMember {
	return IdentityMember{
		RatingID: r.ID, Assessor: r.Assessor, Version: r.Version, Vector: r.Vector,
		AssertedContext: r.AssertedContext, Active: status == RatingActive,
	}
}

// SetKey names the set a member is linked within: assessor + version + normalised vector.
func (m IdentityMember) SetKey() string {
	return strings.Join([]string{NormaliseAssessor(m.Assessor), strings.TrimSpace(m.Version), NormaliseVector(m.Vector)}, "|")
}

// GroupingEntry places one publication in an identity.
type GroupingEntry struct {
	RatingID    string `json:"rating_id"`
	IdentityKey string `json:"identity_key"`
	// Linked is true when an unstated publication joined an asserted identity.
	Linked    bool `json:"linked,omitempty"`
	Ambiguous bool `json:"ambiguous_link,omitempty"`
}

// Grouping is the complete grouping of one set, sorted by rating id.
type Grouping []GroupingEntry

// LinkChange is the readable difference between two groupings for one publication.
type LinkChange struct {
	RatingID string `json:"rating_id"`
	Change   string `json:"change"`
}

// Link change names (EDR 3.2a item 3).
const (
	ChangeLinked            = "linked"
	ChangeUnlinked          = "unlinked"
	ChangeMarkedAmbiguous   = "marked_ambiguous"
	ChangeAmbiguityResolved = "ambiguity_resolved"
)

// AssessmentLink is one append-only grouping event for one set.
type AssessmentLink struct {
	CVE           string
	SetKey        string
	Grouping      Grouping
	Changes       []LinkChange
	PolicyVersion string
	Cause         string
	At            time.Time
}

// GroupSet computes the grouping of one set (same assessor, version, normalised vector). It is a
// pure function of the set: arrival order does not matter.
//
// Each asserted context is its own identity. An unstated publication links to the one viable
// asserted identity when there is exactly one; with none it stays in the unstated identity; with
// several it stays there too, flagged ambiguous_link. An identity is viable while at least one of
// its asserted publications is active.
func GroupSet(members []IdentityMember) Grouping {
	if len(members) == 0 {
		return nil
	}
	base := members[0].SetKey()
	viable := map[string]bool{}
	for _, m := range members {
		if ctx := NormaliseContext(m.AssertedContext); ctx != "" && m.Active {
			viable[ctx] = true
		}
	}
	var only string
	for ctx := range viable {
		only = ctx
	}
	out := make(Grouping, 0, len(members))
	for _, m := range members {
		ctx := NormaliseContext(m.AssertedContext)
		e := GroupingEntry{RatingID: m.RatingID}
		switch {
		case ctx != "":
			e.IdentityKey = base + "|" + ctx
		case len(viable) == 1:
			e.IdentityKey, e.Linked = base+"|"+only, true
		default:
			e.IdentityKey = base + "|" + unstatedContext
			e.Ambiguous = len(viable) > 1
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RatingID < out[j].RatingID })
	return out
}

// GroupAll splits publications into sets and groups each, keyed by set key.
func GroupAll(members []IdentityMember) map[string]Grouping {
	sets := map[string][]IdentityMember{}
	for _, m := range members {
		sets[m.SetKey()] = append(sets[m.SetKey()], m)
	}
	out := make(map[string]Grouping, len(sets))
	for k, ms := range sets {
		out[k] = GroupSet(ms)
	}
	return out
}

// Equal reports whether two groupings are the same.
func (g Grouping) Equal(other Grouping) bool {
	if len(g) != len(other) {
		return false
	}
	for i := range g {
		if g[i] != other[i] {
			return false
		}
	}
	return true
}

// DiffGrouping names what changed for each publication between prev and next (EDR 3.2a item
// 3). A publication new to the set reports "linked" or "marked_ambiguous" when it arrives that
// way, and nothing when it is its own identity.
func DiffGrouping(prev, next Grouping) []LinkChange {
	before := map[string]GroupingEntry{}
	for _, e := range prev {
		before[e.RatingID] = e
	}
	var out []LinkChange
	add := func(id string, changes ...string) {
		for _, c := range changes {
			out = append(out, LinkChange{RatingID: id, Change: c})
		}
	}
	for _, e := range next {
		p, had := before[e.RatingID]
		if !had {
			p = GroupingEntry{RatingID: e.RatingID, IdentityKey: e.IdentityKey}
			if e.Linked || e.Ambiguous {
				p.IdentityKey = "" // arrived linked or ambiguous: report it
			}
		}
		if p == e {
			continue
		}
		switch {
		case p.Ambiguous && e.Linked:
			add(e.RatingID, ChangeAmbiguityResolved, ChangeLinked)
		case p.Ambiguous:
			add(e.RatingID, ChangeAmbiguityResolved)
		case e.Ambiguous && p.Linked:
			add(e.RatingID, ChangeUnlinked, ChangeMarkedAmbiguous)
		case e.Ambiguous:
			add(e.RatingID, ChangeMarkedAmbiguous)
		case p.Linked && e.Linked:
			add(e.RatingID, ChangeUnlinked, ChangeLinked)
		case p.Linked:
			add(e.RatingID, ChangeUnlinked)
		default:
			add(e.RatingID, ChangeLinked)
		}
	}
	return out
}

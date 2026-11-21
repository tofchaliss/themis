package domain

import (
	"strings"
	"testing"
	"time"
)

// Selection cases from EDR-SCORING-01 section 11. Scores: v65 = 6.5, v91 = 9.1, v81 = 8.1,
// v55 = 5.5, v75 = 7.5, v30 = 9.8 (CVSS 3.0), v68 = 6.8.
const (
	v65  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
	v91  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
	v81  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
	v55  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
	v75  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	v30  = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v68  = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H"
	v40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	vBad = "CVSS:3.1/AV:N/AC:Z/PR:N/UI:N/S:U/C:H/I:H/A:N"

	rhel9   = "cpe:/o:redhat:enterprise_linux:9"
	rhel8   = "cpe:/o:redhat:enterprise_linux:8"
	pkgName = "openssl"
)

var rpm = ScoreComponent{PURL: "pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64", Name: "openssl", Version: "3.0.7-27.el9"}

// cb builds one candidate. Defaults: active, inherited context naming the package (applies).
type cb struct{ c ScoreCandidate }

func cand(id, assessor, vector string) *cb {
	return &cb{c: ScoreCandidate{
		RatingID: id, Source: "src-" + id, DocumentRef: "doc-" + id, Revision: "r1", Assessor: assessor,
		Publisher: "feed", Vector: vector, Version: versionOf(vector), InheritedContext: pkgName, Active: true,
	}}
}

func versionOf(v string) string {
	if strings.HasPrefix(v, "CVSS:") {
		return strings.SplitN(v[5:], "/", 2)[0]
	}
	return ""
}

func (b *cb) unres() *cb              { b.c.InheritedContext = ""; return b }
func (b *cb) inherit(ctx string) *cb  { b.c.InheritedContext = ctx; return b }
func (b *cb) assert(ctx string) *cb   { b.c.AssertedContext = ctx; return b }
func (b *cb) pub(p string) *cb        { b.c.Publisher = p; return b }
func (b *cb) ident(k string) *cb      { b.c.IdentityKey = k; return b }
func (b *cb) inactive() *cb           { b.c.Active = false; return b }
func (b *cb) validation(v string) *cb { b.c.Validation = v; return b }
func (b *cb) at(t time.Time) *cb      { b.c.SourceUpdatedAt = t; return b }
func (b *cb) src(s, doc, rev string) *cb {
	b.c.Source, b.c.DocumentRef, b.c.Revision = s, doc, rev
	return b
}

// vendor is a Red Hat rating for the RHEL 9 platform (vendor_platform for rpm).
func vendor(id, vector string) *cb { return cand(id, "redhat", vector).inherit(rhel9) }

// cna is a rating by the CVE's CNA (its CVE.org CNA container publication).
func cnaOf(id, assessor, vector string) *cb {
	return cand(id, assessor, vector).pub(CVEOrgCNAPublisher)
}

func run(comp ScoreComponent, cs ...*cb) ComponentScore {
	in := ScoreInput{CVE: "CVE-2026-0001"}
	for _, c := range cs {
		in.Candidates = append(in.Candidates, c.c)
	}
	return SelectComponentScore(comp, in)
}

func evalOf(t *testing.T, out ComponentScore, id string) CandidateEvaluation {
	t.Helper()
	for _, c := range out.Candidates {
		if c.RatingID == id {
			return c
		}
	}
	t.Fatalf("no candidate %s", id)
	return CandidateEvaluation{}
}

func wantDisp(t *testing.T, out ComponentScore, id, disp, reason string) {
	t.Helper()
	e := evalOf(t, out, id)
	if e.Disposition != disp || e.Reason != reason {
		t.Errorf("%s: got %s/%s, want %s/%s", id, e.Disposition, e.Reason, disp, reason)
	}
}

func roleOf(out ComponentScore, key string) IdentityEvaluation {
	for _, id := range out.Identities {
		if id.IdentityKey == key {
			return id
		}
	}
	return IdentityEvaluation{}
}

func wantScore(t *testing.T, out ComponentScore, outcome, status string, env float64, from string) {
	t.Helper()
	if out.Outcome != outcome || out.Status != status {
		t.Fatalf("outcome/status = %q/%q, want %q/%q (reason %q)", out.Outcome, out.Status, outcome, status, out.UnscoredReason)
	}
	if status == ScoreUnavailable {
		if out.Scores != nil {
			t.Errorf("unavailable carries scores %v", out.Scores)
		}
		return
	}
	if out.Scores == nil || out.Scores.Environmental != env {
		t.Fatalf("score = %v, want %v", out.Scores, env)
	}
	if from != "" && out.ScoreFrom != from {
		t.Errorf("score from %s, want %s", out.ScoreFrom, from)
	}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func wantConds(t *testing.T, out ComponentScore, conds ...string) {
	t.Helper()
	all := append(append([]string{}, out.ConflictConditions...), out.ApplicabilityConditions...)
	if len(all) != len(conds) {
		t.Fatalf("conditions = %v, want %v", all, conds)
	}
	for _, c := range conds {
		if !has(all, c) {
			t.Fatalf("conditions = %v, want %v", all, conds)
		}
	}
}

// Every candidate has exactly one disposition, with a reason where 4.1b needs one (D15).
func checkDispositions(t *testing.T, out ComponentScore) {
	t.Helper()
	for _, c := range out.Candidates {
		if c.Disposition == "" {
			t.Errorf("%s has no disposition", c.RatingID)
		}
		if c.Disposition != DispReference && c.Reason == "" {
			t.Errorf("%s (%s) has no reason", c.RatingID, c.Disposition)
		}
	}
}

func TestContestedIndependentAssessors(t *testing.T) {
	out := run(rpm, cand("a", "x", v65), cand("b", "y", v81))
	wantScore(t, out, OutcomeContested, ScoreProvisional, 8.1, "b")
	wantConds(t, out, CondIndependentDisagreement)
	wantDisp(t, out, "a", DispCompeting, CondIndependentDisagreement)
	if len(out.Contributing) != 0 || out.Representative != "" || len(out.Competing) != 2 {
		t.Errorf("contested must have no contributors or representative: %+v", out)
	}
	if c := evalOf(t, out, "b"); c.Contribution == nil || *c.Contribution != 8.1 {
		t.Errorf("contribution not recorded: %+v", c)
	}
	checkDispositions(t, out)
}

func TestAgreementSelectsFinal(t *testing.T) {
	out := run(rpm, cand("a", "y", v65), cand("b", "x", v65))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "")
	if len(out.Contributing) != 2 || roleOf(out, "rating:a").Role != RoleAgreeing || roleOf(out, "rating:b").Role != RoleAgreeing {
		t.Fatalf("agreeing identities: %+v", out.Identities)
	}
	// Representative = smallest canonical identity key: assessor x.
	if out.Representative != "rating:b" || out.RepresentativeRating != "b" || !roleOf(out, "rating:b").Representative {
		t.Errorf("representative = %s", out.Representative)
	}
	if len(out.Relations) != 1 || out.Relations[0].Kind != RelationIndependentAgreement {
		t.Errorf("relations = %+v", out.Relations)
	}
	wantDisp(t, out, "a", DispReference, "")
	// Reversed org-id order: only the representative moves.
	rev := run(rpm, cand("a", "x", v65), cand("b", "y", v65))
	if rev.Representative != "rating:a" || rev.Scores.Environmental != 6.5 || rev.Status != ScoreFinal {
		t.Errorf("reversed: %+v", rev)
	}
}

// vendorNamed is a vendor rating whose context names the package only.
func vendorNamed(id, vector string) *cb { return cand(id, "redhat", vector) }

func TestUnresolvedOutcome(t *testing.T) {
	cases := []struct {
		name   string
		cands  []*cb
		status string
		env    float64
		from   string
	}{
		{"vendor 9.1 unresolved, cna 6.5", []*cb{vendorU("v", v91), cnaOf("c", "x", v65)}, ScoreProvisional, 9.1, "v"},
		{"vendor 5.5 unresolved, cna 6.5", []*cb{vendorU("v", v55), cnaOf("c", "x", v65)}, ScoreProvisional, 6.5, "c"},
		{"vendor no vector, cna 6.5", []*cb{vendorU("v", ""), cnaOf("c", "x", v65)}, ScoreUnavailable, 0, ""},
		{"D17 all lower classes", []*cb{vendorU("v", v65), cnaOf("c", "x", v75), cand("n", "nvd", v81), cand("o", "o", v55)}, ScoreProvisional, 8.1, "n"},
		{"D17 lower 4.0 never contributes", []*cb{vendorU("v", v65), cnaOf("c", "x", v75), cand("n", "nvd", v40)}, ScoreProvisional, 7.5, "c"},
		{"D17 lower invalid never contributes", []*cb{vendorU("v", v65), cnaOf("c", "x", vBad)}, ScoreProvisional, 6.5, "v"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := run(rpm, tc.cands...)
			wantScore(t, out, OutcomeUnresolved, tc.status, tc.env, tc.from)
			wantConds(t, out, CondHigherClassUnresolved)
			wantDisp(t, out, "v", DispUnresolved, ReasonHigherClass)
			if tc.status == ScoreUnavailable && out.UnscoredReason != UnscoredApplicabilityOpen {
				t.Errorf("reason %s", out.UnscoredReason)
			}
			checkDispositions(t, out)
		})
	}
	out := run(rpm, vendorU("v", v65), cnaOf("c", "x", v75), cand("n", "nvd", v40), cnaOf("i", "x", vBad))
	wantDisp(t, out, "c", DispAvailableNotSelected, ReasonLowerClass)
	wantDisp(t, out, "n", DispAvailableNotCompared, ReasonUnsupportedLowerClass)
	wantDisp(t, out, "i", DispAvailableNotCompared, ReasonInvalidLowerClass)
	if evalOf(t, out, "n").Contribution != nil {
		t.Error("unsupported lower candidate contributed")
	}
	// D4: lower class not used when nothing unresolved is calculable.
	out = run(rpm, vendorU("v", ""), cnaOf("c", "x", v65))
	if evalOf(t, out, "c").Contribution != nil {
		t.Error("D4: lower class used")
	}
}

// vendorU is a vendor_platform rating left unresolved: its context names the platform family
// (RHEL 8, not this RHEL 9 component) beside a product CPE that cannot be placed.
func vendorU(id, vector string) *cb {
	return cand(id, "redhat", vector).inherit(rhel8 + ",cpe:/a:redhat:openshift")
}

func TestStep5SameAssessorVersions(t *testing.T) {
	// cna 3.1 and cna 4.0 from the same assessor: 4.0 set aside, 3.1 final.
	out := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "x", v40))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "a")
	wantDisp(t, out, "b", DispAvailableNotCompared, ReasonUnsupportedSameAssessor)
	// cna 4.0 only; nvd 3.1: no fallback.
	out = run(rpm, cnaOf("a", "x", v40), cand("n", "nvd", v65))
	wantScore(t, out, "", ScoreUnavailable, 0, "")
	if out.UnscoredReason != UnscoredUnsupported {
		t.Errorf("reason %s", out.UnscoredReason)
	}
	wantDisp(t, out, "a", DispAvailableNotCompared, ReasonUnsupportedOnly)
	wantDisp(t, out, "n", DispAvailableNotSelected, ReasonLowerClass)
	if roleOf(out, "rating:a").Role != RoleNotCompared {
		t.Errorf("role %+v", out.Identities)
	}
	// Two 4.0 only.
	out = run(rpm, cnaOf("a", "x", v40), cnaOf("b", "y", v40), cand("n", "nvd", v65))
	if out.UnscoredReason != UnscoredUnsupported || out.Outcome != "" {
		t.Errorf("got %+v", out)
	}
}

func TestUnscorablePeer(t *testing.T) {
	// cna: A 4.0 only, B 3.1 7.5 -> selected B, provisional (D9).
	out := run(rpm, cnaOf("a", "x", v40), cnaOf("b", "y", v75))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 7.5, "b")
	wantConds(t, out, CondUnscorablePeer)
	wantDisp(t, out, "a", DispAvailableNotCompared, ReasonUnsupportedPeer)
	// X: 3.1 6.5 + 4.0; Y: 4.0 only.
	out = run(rpm, cnaOf("a", "x", v65), cnaOf("a2", "x", v40), cnaOf("y", "y", v40))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 6.5, "a")
	wantDisp(t, out, "a2", DispAvailableNotCompared, ReasonUnsupportedSameAssessor)
	wantDisp(t, out, "y", DispAvailableNotCompared, ReasonUnsupportedPeer)
	if c := evalOf(t, out, "a"); c.Contribution == nil {
		t.Error("provisional selected score records no contribution")
	}
}

func TestInvalidPeer(t *testing.T) {
	out := run(rpm, cnaOf("x", "x", v75), cnaOf("y", "y", vBad))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 7.5, "x")
	wantDisp(t, out, "y", DispAvailableNotCompared, ReasonInvalidPeer)
	if !has(out.Flags, FlagPeerRatingInvalid) {
		t.Errorf("flags %v", out.Flags)
	}
	// X 7.5; Y 4.0; Z invalid.
	out = run(rpm, cnaOf("x", "x", v75), cnaOf("y", "y", v40), cnaOf("z", "z", vBad))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 7.5, "x")
	wantConds(t, out, CondUnscorablePeer)
	// Contested + invalid peer.
	out = run(rpm, cnaOf("x", "x", v75), cnaOf("y", "y", v65), cnaOf("z", "z", vBad))
	wantScore(t, out, OutcomeContested, ScoreProvisional, 7.5, "x")
	wantConds(t, out, CondIndependentDisagreement)
	// Contested + unscorable peer.
	out = run(rpm, cnaOf("x", "x", v75), cnaOf("y", "y", v65), cnaOf("z", "z", v40))
	wantConds(t, out, CondIndependentDisagreement, CondUnscorablePeer)
	// Same assessor invalid beside a valid one.
	out = run(rpm, cnaOf("x", "x", v75), cnaOf("x2", "x", vBad))
	wantDisp(t, out, "x2", DispAvailableNotCompared, ReasonInvalidVector)
	if len(out.Flags) != 0 {
		t.Errorf("flags %v", out.Flags)
	}
}

func TestNoOutcome(t *testing.T) {
	out := run(rpm)
	wantScore(t, out, "", ScoreUnavailable, 0, "")
	if out.UnscoredReason != UnscoredNoVector {
		t.Errorf("reason %s", out.UnscoredReason)
	}
	out = run(rpm, cand("a", "x", v65).inherit(rhel8))
	if out.UnscoredReason != UnscoredNoApplicable {
		t.Errorf("reason %s", out.UnscoredReason)
	}
	wantDisp(t, out, "a", DispRejected, ReasonDoesNotApply)
	out = run(rpm, cand("a", "x", v65).inactive())
	wantDisp(t, out, "a", DispRejected, ReasonInactive)
	// Knowledge's RatingValidation decides over the local parser.
	out = run(rpm, cnaOf("a", "x", v65).validation("invalid_vector"))
	if out.UnscoredReason != UnscoredInvalid {
		t.Errorf("validation ignored: %s", out.UnscoredReason)
	}
	// Only invalid.
	out = run(rpm, cnaOf("a", "x", vBad))
	if out.UnscoredReason != UnscoredInvalid {
		t.Errorf("reason %s", out.UnscoredReason)
	}
	// Unsupported + invalid mixed.
	out = run(rpm, cnaOf("a", "x", vBad), cnaOf("b", "y", v40))
	if out.UnscoredReason != UnscoredNoCalculable {
		t.Errorf("reason %s", out.UnscoredReason)
	}
	wantDisp(t, out, "a", DispAvailableNotCompared, ReasonInvalidVector)
	wantDisp(t, out, "b", DispAvailableNotCompared, ReasonUnsupportedOnly)
	// Vendor invalid, cna 7.5: no fallback.
	out = run(rpm, vendor("v", vBad), cnaOf("c", "x", v75))
	if out.UnscoredReason != UnscoredInvalid || out.Outcome != "" {
		t.Errorf("got %+v", out)
	}
	wantDisp(t, out, "c", DispAvailableNotSelected, ReasonLowerClass)
}

func TestD13VendorUnsupportedAndUnresolved(t *testing.T) {
	out := run(rpm, vendor("a", v40), vendorU("b", v91), cnaOf("c", "x", v75))
	wantScore(t, out, OutcomeUnresolved, ScoreProvisional, 9.1, "b")
	wantConds(t, out, CondHigherClassUnresolved)
	wantDisp(t, out, "a", DispAvailableNotCompared, ReasonUnsupportedOnly)
	wantDisp(t, out, "c", DispAvailableNotSelected, ReasonLowerClass)
	out = run(rpm, vendor("a", v40), vendorU("b", v55), cnaOf("c", "x", v75))
	wantScore(t, out, OutcomeUnresolved, ScoreProvisional, 7.5, "c")
	out = run(rpm, vendor("a", v40), vendorU("b", ""), cnaOf("c", "x", v75))
	wantScore(t, out, OutcomeUnresolved, ScoreUnavailable, 0, "")
	// Invalid in an unresolved outcome is recorded only.
	out = run(rpm, vendor("a", vBad), vendorU("b", v55))
	wantDisp(t, out, "a", DispAvailableNotCompared, ReasonInvalidVector)
	// Vendor 4.0 only, cna 7.5: no outcome, no fallback.
	out = run(rpm, vendor("a", v40), cnaOf("c", "x", v75))
	if out.Outcome != "" || out.UnscoredReason != UnscoredUnsupported {
		t.Errorf("got %+v", out)
	}
}

func TestSameClassUnresolved(t *testing.T) {
	cases := []struct {
		name   string
		u      *cb
		status string
		env    float64
		from   string
		reason string
	}{
		{"unresolved higher", vendorU("b", v91), ScoreProvisional, 9.1, "b", ReasonSameClass},
		{"unresolved lower", vendorU("b", v55), ScoreProvisional, 6.5, "a", ReasonSameClass},
		{"unresolved no vector", vendorU("b", ""), ScoreProvisional, 6.5, "a", ReasonSameClass},
		{"unresolved same vector (a)", vendorU("b", v65), ScoreFinal, 6.5, "a", ReasonCannotAffect},
		{"unresolved 4.0", vendorU("b", v40), ScoreProvisional, 6.5, "a", ReasonSameClass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := run(rpm, vendor("a", v65), tc.u.assert("").ident("U-"+tc.name))
			wantScore(t, out, OutcomeSelected, tc.status, tc.env, tc.from)
			wantDisp(t, out, "b", DispUnresolved, tc.reason)
			if tc.status == ScoreProvisional {
				wantConds(t, out, CondSameClassUnresolved)
			}
			checkDispositions(t, out)
		})
	}
	// Same identity as the selected one -> cannot affect (a).
	out := run(rpm, vendor("a", v65).ident("I"), vendorU("b", v91).ident("I"))
	wantDisp(t, out, "b", DispUnresolved, ReasonCannotAffect)
	if evalOf(t, out, "b").CannotAffect != "a" {
		t.Error("exception a not named")
	}
}

func TestD14Specificity(t *testing.T) {
	// Package P asserted applies 6.5; ecosystem asserted unresolved 9.1 (same assessor): b holds.
	comp := ScoreComponent{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20"}
	pkg := func(id, v string) *cb { return cnaOf(id, "x", v).assert("npm:lodash") }
	out := run(comp, pkg("p", v65), unresolvedAsserted("e", "x", v91, "npm"))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "p")
	wantDisp(t, out, "e", DispUnresolved, ReasonCannotAffect)
	if evalOf(t, out, "e").CannotAffect != "b" {
		t.Error("exception b not named")
	}
	// Package P applies only through an inherited context: b fails.
	out = run(comp, cnaOf("p", "x", v65).inherit("lodash"), unresolvedAsserted("e", "x", v91, "npm"))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 9.1, "e")
	// U context inherited (unstated asserted): b fails.
	out = run(comp, pkg("p", v65), cnaOf("e", "x", v91).inherit("npm-products"))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 9.1, "e")
	// U a CPE product with no mapping to P: incomparable, could affect.
	out = run(comp, pkg("p", v65), unresolvedAsserted("e", "x", v91, "cpe:/a:vendor:other"))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 9.1, "e")
	// U from another assessor: specificity never crosses assessors.
	out = run(comp, pkg("p", v65), unresolvedAsserted("e", "y", v91, "npm"))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 9.1, "e")
	// An unstated rating applies 6.5, an asserted one is unresolved 9.1: could win.
	out = run(comp, cnaOf("p", "x", v65).inherit("lodash"), unresolvedAsserted("e", "x", v91, "cpe:/a:lodash:lodash-x"))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 9.1, "e")
	// Asserted ecosystem of another ecosystem does not apply.
	out = run(comp, unresolvedAsserted("e", "x", v91, "pypi"))
	wantDisp(t, out, "e", DispRejected, ReasonDoesNotApply)
	out = run(comp, unresolvedAsserted("e", "x", v91, "pypi:lodash"))
	wantDisp(t, out, "e", DispRejected, ReasonDoesNotApply)
}

// unresolvedAsserted is a candidate whose asserted context cannot be decided for the component
// because it is a multi-item asserted list naming nothing the component is.
func unresolvedAsserted(id, assessor, vector, ctx string) *cb {
	b := cnaOf(id, assessor, vector).assert(ctx)
	b.c.InheritedContext = ""
	return &cb{c: b.c}
}

func TestSpecificityComparable(t *testing.T) {
	comp := ScoreComponent{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20"}
	// Asserted package beats an unstated (inherited) one of the same assessor.
	out := run(comp, cnaOf("p", "x", v65).assert("npm:lodash"), cnaOf("u", "x", v91).inherit("lodash"))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "p")
	wantDisp(t, out, "u", DispNotSelected, ReasonLessSpecificSameAssessor)
	if roleOf(out, "rating:u").Role != RoleNotSelected {
		t.Errorf("role %+v", out.Identities)
	}
}

func TestSelfInconsistencyAndConcurring(t *testing.T) {
	comp := ScoreComponent{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20"}
	// Two incomparable asserted contexts, different vectors: contested, self inconsistency.
	out := run(comp, cnaOf("p", "x", v65).assert("npm:lodash"), cnaOf("q", "x", v81).assert("cpe:2.3:a:lodash:lodash:*"))
	wantScore(t, out, OutcomeContested, ScoreProvisional, 8.1, "q")
	wantConds(t, out, CondSelfInconsistency)
	wantDisp(t, out, "p", DispCompeting, CondSelfInconsistency)
	// Identical vectors: both concurring, final, context_ambiguity.
	out = run(comp, cnaOf("p", "x", v65).assert("npm:lodash"), cnaOf("q", "x", v65).assert("cpe:2.3:a:lodash:lodash:*"))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "")
	if roleOf(out, "rating:p").Role != RoleConcurring || roleOf(out, "rating:q").Role != RoleConcurring {
		t.Errorf("roles %+v", out.Identities)
	}
	if !has(out.Flags, FlagContextAmbiguity) || out.Relations[0].Kind != RelationSameAssessorIncomparable {
		t.Errorf("flags %v relations %+v", out.Flags, out.Relations)
	}
	// Mixed: X1, X2 incomparable + Y, all V1: all agreeing, three relations.
	out = run(comp, cnaOf("p", "x", v65).assert("npm:lodash"), cnaOf("q", "x", v65).assert("cpe:2.3:a:lodash:lodash:*"), cnaOf("y", "y", v65).inherit("lodash"))
	for _, k := range []string{"rating:p", "rating:q", "rating:y"} {
		if roleOf(out, k).Role != RoleAgreeing {
			t.Errorf("%s role %+v", k, roleOf(out, k))
		}
	}
	if len(out.Relations) != 3 || !has(out.Flags, FlagContextAmbiguity) {
		t.Errorf("relations %+v", out.Relations)
	}
	// Mixed independent + self disagreement: both conditions.
	out = run(comp, cnaOf("p", "x", v65).assert("npm:lodash"), cnaOf("q", "x", v81).assert("cpe:2.3:a:lodash:lodash:*"), cnaOf("y", "y", v65).inherit("lodash"))
	wantConds(t, out, CondSelfInconsistency, CondIndependentDisagreement)
}

func TestD25ThreeIdentities(t *testing.T) {
	out := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v65), cnaOf("c", "z", v81))
	wantScore(t, out, OutcomeContested, ScoreProvisional, 8.1, "c")
	if len(out.Competing) != 3 {
		t.Errorf("competing %v", out.Competing)
	}
	for _, id := range []string{"a", "b", "c"} {
		wantDisp(t, out, id, DispCompeting, CondIndependentDisagreement)
	}
}

func TestD26AndD28(t *testing.T) {
	// Test A: identity I has P1 applies V1 and P2 unresolved; Y applies V2.
	out := run(rpm, cnaOf("p1", "x", v65).ident("I"), cnaOf("p2", "x", v65).inherit("cpe:/a:redhat:openshift").ident("I"), cnaOf("q1", "y", v81))
	wantScore(t, out, OutcomeContested, ScoreProvisional, 8.1, "q1")
	wantDisp(t, out, "p1", DispCompeting, CondIndependentDisagreement)
	wantDisp(t, out, "p2", DispUnresolved, ReasonSameVectorAsCompeting)
	if roleOf(out, "I").Role != RoleCompeting {
		t.Errorf("role %+v", out.Identities)
	}
	cases := []struct {
		name   string
		u      *cb
		env    float64
		reason string
		cond   bool
	}{
		{"c differs higher", cnaOf("u", "z", v91).unres(), 9.1, ReasonDiffersFromCompeting, true},
		{"c differs lower", cnaOf("u", "z", v55).unres(), 8.1, ReasonDiffersFromCompeting, true},
		{"b same as competing", cnaOf("u", "z", v81).unres(), 8.1, ReasonSameVectorAsCompeting, false},
		{"d no vector", cnaOf("u", "z", "").unres(), 8.1, ReasonSameClass, true},
		{"a same identity", cnaOf("u", "x", v65).unres().ident("rating:a"), 8.1, ReasonSameVectorAsCompeting, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v81), tc.u)
			wantScore(t, out, OutcomeContested, ScoreProvisional, tc.env, "")
			wantDisp(t, out, "u", DispUnresolved, tc.reason)
			if has(out.ApplicabilityConditions, CondSameClassUnresolved) != tc.cond {
				t.Errorf("conditions %v", out.ApplicabilityConditions)
			}
			if has(out.Competing, "rating:u") {
				t.Error("unresolved entered the competing set")
			}
			checkDispositions(t, out)
		})
	}
}

func TestD27LowerSupportedVersion(t *testing.T) {
	out := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "x", v30))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "a")
	wantDisp(t, out, "b", DispNotSelected, ReasonLowerSupportedVersion)
	if roleOf(out, "rating:b").Role != RoleNotSelected || evalOf(t, out, "b").Contribution != nil {
		t.Errorf("3.0 identity %+v", roleOf(out, "rating:b"))
	}
	// Another assessor's 3.0 still competes.
	out = run(rpm, cnaOf("a", "x", v30), cnaOf("b", "y", v81))
	if out.Outcome != OutcomeContested {
		t.Errorf("outcome %s", out.Outcome)
	}
	// 3.0 identity J: P2 applies, P3 unresolved.
	out = run(rpm, cnaOf("p1", "x", v65), cnaOf("p2", "x", v30).ident("J"), cnaOf("p3", "x", v30).unres().ident("J"))
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "p1")
	wantDisp(t, out, "p2", DispNotSelected, ReasonLowerSupportedVersion)
	wantDisp(t, out, "p3", DispUnresolved, ReasonLowerVersionUnresolved)
	// 3.0 invalid: invalid_vector, not not_selected.
	out = run(rpm, cnaOf("a", "x", v65), cnaOf("b", "x", "CVSS:3.0/AV:N/AC:Z"))
	wantDisp(t, out, "b", DispAvailableNotCompared, ReasonInvalidVector)
	// 3.1 unresolved only: D27 does nothing.
	out = run(rpm, cnaOf("a", "x", v91).unres(), cnaOf("b", "x", v30))
	wantScore(t, out, OutcomeSelected, ScoreProvisional, 9.8, "b")
	wantDisp(t, out, "a", DispUnresolved, ReasonSameClass)
}

func TestReferencePublication(t *testing.T) {
	now := time.Date(2026, 11, 10, 4, 30, 0, 0, time.UTC)
	// Asserted over inherited.
	out := run(rpm, cnaOf("a1", "x", v65).ident("A"), cnaOf("a2", "x", v65).ident("A").assert("openssl"))
	wantDisp(t, out, "a2", DispReference, "")
	wantDisp(t, out, "a1", DispSupporting, ReasonSameIdentity)
	if roleOf(out, "A").Reference != "a2" {
		t.Errorf("reference %+v", roleOf(out, "A"))
	}
	// Own over copy.
	out = run(rpm, cand("a1", "x", v65).ident("A").pub("nvd"), cand("a2", "x", v65).ident("A").pub("x"))
	wantDisp(t, out, "a2", DispReference, "")
	// Known time before missing; newer first.
	out = run(rpm, cand("a1", "x", v65).ident("A"), cand("a2", "x", v65).ident("A").at(now))
	wantDisp(t, out, "a2", DispReference, "")
	out = run(rpm, cand("a1", "x", v65).ident("A").at(now.Add(time.Hour)), cand("a2", "x", v65).ident("A").at(now))
	wantDisp(t, out, "a1", DispReference, "")
	// Same instant (different zones normalised upstream): canonical key decides, both orders.
	in1 := []*cb{cand("a1", "x", v65).ident("A").at(now).src("s", "d", "2"), cand("a2", "x", v65).ident("A").at(now).src("s", "d", "1")}
	out = run(rpm, in1...)
	wantDisp(t, out, "a2", DispReference, "")
	out = run(rpm, in1[1], in1[0])
	wantDisp(t, out, "a2", DispReference, "")
	// Agreement: each identity keeps its own reference.
	out = run(rpm, cand("a1", "x", v65).ident("A"), cand("a2", "x", v65).ident("A").at(now), cand("b1", "y", v65).ident("B"))
	wantDisp(t, out, "b1", DispReference, "")
	if roleOf(out, "B").Reference != "b1" || roleOf(out, "A").Reference != "a2" {
		t.Errorf("references %+v", out.Identities)
	}
}

func TestVendorLinkedCopyAndWithdrawal(t *testing.T) {
	// Vendor publication (vendor_platform) linked to the NVD copy in cna.
	vend := vendor("v", v65).ident("I").pub("redhat")
	copyNVD := cnaOf("n", "redhat", v65).ident("I").inherit(pkgName)
	out := run(rpm, vend, copyNVD)
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "v")
	wantDisp(t, out, "n", DispAvailableNotSelected, ReasonLowerClass)
	// Vendor withdrawn: the copy is selected in cna.
	out = run(rpm, vendor("v", v65).ident("I").inactive(), copyNVD)
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "n")
	if out.DecidingClass != ClassCNA {
		t.Errorf("class %s", out.DecidingClass)
	}
}

func TestClassBasis(t *testing.T) {
	out := run(rpm, cand("adp", "cisa-adp", v65), cand("nvd", "nvd", v65), cand("o", "other", v65), cand("u", "", v65), vendor("v", v65), cnaOf("c", "mitre", v65))
	want := map[string]SelectionClass{"adp": ClassADP, "nvd": ClassNVDAnalyst, "o": ClassOtherAssessor, "u": ClassUnattributed, "v": ClassVendorPlatform, "c": ClassCNA}
	for id, cls := range want {
		if e := evalOf(t, out, id); e.Class != cls || e.ClassBasis == "" {
			t.Errorf("%s class %s basis %q", id, e.Class, e.ClassBasis)
		}
	}
	// A vector from the CNA, seen through another publisher, is still cna.
	out = run(rpm, cnaOf("c", "mitre", v65), cand("osv", "mitre", v81).pub("osv"))
	if evalOf(t, out, "osv").Class != ClassCNA {
		t.Errorf("feed set the class")
	}
	// Unknown CNA: other_assessor.
	out = run(rpm, cand("x", "mitre", v65))
	if evalOf(t, out, "x").Class != ClassOtherAssessor {
		t.Error("unknown CNA must be other_assessor")
	}
	// No vendor for an npm component.
	npm := ScoreComponent{PURL: "pkg:npm/openssl@1.0.0", Name: "openssl", Version: "1.0.0"}
	out = run(npm, vendorNamed("v", v65))
	if evalOf(t, out, "v").Class == ClassVendorPlatform {
		t.Error("vendor class without a platform")
	}
}

func TestApplicability(t *testing.T) {
	alpine := ScoreComponent{PURL: "pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.20.2", Name: "openssl", Version: "3.1.4-r5"}
	cases := []struct {
		name     string
		ctx      string
		asserted bool
		comp     ScoreComponent
		want     Applicability
	}{
		{"empty", "", false, rpm, Unresolved},
		{"rhel9 on rhel9", rhel9, false, rpm, Applies},
		{"rhel8 on rhel9", rhel8, false, rpm, DoesNotApply},
		{"rhel cpe on alpine", rhel9, false, alpine, DoesNotApply},
		{"rhel cpe on npm", rhel9, false, ScoreComponent{PURL: "pkg:npm/x@1", Name: "x"}, Unresolved},
		{"unplaced cpe naming package", "cpe:/a:openssl:openssl", false, rpm, Applies},
		{"unplaced cpe 2.3", "cpe:2.3:a:openssl:openssl:*:*", false, rpm, Applies},
		{"unplaced cpe other", "cpe:/a:redhat:openshift", false, rpm, Unresolved},
		{"bad cpe", "cpe:/a", false, rpm, Unresolved},
		{"bad cpe prefix", "cpe:x", false, rpm, Unresolved},
		{"product list naming it", "curl,openssl", false, rpm, Applies},
		{"product list not naming it", "curl,wget", false, rpm, Unresolved},
		{"asserted other package", "curl", true, rpm, DoesNotApply},
		{"asserted list not naming it", "curl,wget", true, rpm, Unresolved},
		{"cveorg vendor:product", "openssl:openssl", false, rpm, Applies},
		{"mixed dna and unresolved", rhel8 + ",cpe:/a:redhat:openshift", false, rpm, Unresolved},
		{"source package", "openssl-src", false, ScoreComponent{PURL: "pkg:rpm/redhat/openssl-libs@1-1.el9", Name: "openssl-libs", Version: "1-1.el9", SourcePackage: "openssl-src"}, Applies},
		{"purl name", "zlib", false, ScoreComponent{PURL: "pkg:npm/zlib@1"}, Applies},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyContext(tc.ctx, tc.asserted, tc.comp, "x")
			if got.result != tc.want {
				t.Errorf("got %s want %s", got.result, tc.want)
			}
		})
	}
	// D12: observation applicability never widens an asserted context.
	out := run(rpm, cand("a", "x", v65).assert("curl").inherit("curl,openssl"))
	wantDisp(t, out, "a", DispRejected, ReasonDoesNotApply)
	if nameMatches("  ", rpm) {
		t.Error("blank matched")
	}
	if cpeProduct("x") != "" {
		t.Error("non-cpe product")
	}
}

func TestContextOrder(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"npm:lodash", "npm", true},
		{"npm", "", true},
		{"npm:lodash", "", true},
		{"npm", "npm:lodash", false},
		{"npm:lodash", "npm:lodash", false},
		{"npm:lodash", "pypi", false},
		{"lodash", "npm", false},
		{"npm:lodash", "a,b", false},
		{"cpe:/o:redhat:enterprise_linux:9", "", true},
		{"cpe:/a:lodash:lodash", "npm", false},
		{"cpe:/o:redhat:enterprise_linux:9", "rpm", false},
	}
	for _, tc := range cases {
		if got := moreSpecific(NormaliseScoreContext(tc.a), NormaliseScoreContext(tc.b)); got != tc.want {
			t.Errorf("moreSpecific(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
	if NormaliseScoreContext(" RHEL:Openssl ") != "rpm:openssl" {
		t.Errorf("normalise = %q", NormaliseScoreContext(" RHEL:Openssl "))
	}
}

func TestTemporalAndRequirements(t *testing.T) {
	comp := rpm
	comp.FixApplicable = true
	in := ScoreInput{KEV: true, Candidates: []ScoreCandidate{cand("a", "x", v68).c},
		Requirements: ScoreRequirements{CR: RequirementValue{"H", "release"}, IR: RequirementValue{"M", "product"}, AR: RequirementValue{"H", "project"}}}
	out := SelectComponentScore(comp, in)
	if out.Scores == nil || out.Scores.Base != 6.8 || out.Scores.Temporal != 6.5 || out.Scores.Environmental != 7.2 {
		t.Fatalf("scores %+v", out.Scores)
	}
	if out.AssessmentVector != "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/RL:O/CR:H/IR:M/AR:H" {
		t.Errorf("vector %s", out.AssessmentVector)
	}
	e := out.Temporal[0]
	if e.State != MetricProposed || e.Proposed != "F" || e.Used != "X" {
		t.Errorf("KEV must stay proposed: %+v", e)
	}
	if out.Temporal[1].State != MetricAcceptedByPolicy {
		t.Errorf("RL %+v", out.Temporal[1])
	}
	// A cleared component gets no RL:O; a source vector's own temporal metrics are not used.
	comp.VerdictState = "cleared_vendor_fix"
	in = ScoreInput{Candidates: []ScoreCandidate{cand("a", "x", v68+"/E:U/RL:W").c}}
	out = SelectComponentScore(comp, in)
	if out.Scores.Environmental != 6.8 || out.Open || out.Temporal[1].State != MetricNotDefined {
		t.Errorf("got %+v %+v", out.Scores, out.Temporal)
	}
	// A bad requirement value is X.
	if assessmentSuffix(nil, ScoreRequirements{CR: RequirementValue{Value: "Q"}}) != "" {
		t.Error("bad requirement used")
	}
}

func TestCalculability(t *testing.T) {
	cases := []struct {
		r    ScoreCandidate
		want string
	}{
		{ScoreCandidate{Vector: ""}, CalcNoVector},
		{ScoreCandidate{Vector: v65}, CalcCalculable},
		{ScoreCandidate{Vector: v65, Validation: "invalid_vector"}, CalcInvalid},
		{ScoreCandidate{Vector: v65, Validation: "unsupported_cvss_version"}, CalcUnsupported},
		{ScoreCandidate{Vector: vBad}, CalcInvalid},
		{ScoreCandidate{Vector: "AV:N/AC:L", Version: "3.x"}, CalcInvalid},
		{ScoreCandidate{Vector: "AV:N/AC:L/Au:N", Version: "2.0"}, CalcUnsupported},
		{ScoreCandidate{Vector: v40, Version: "4.0"}, CalcUnsupported},
	}
	for _, tc := range cases {
		if got, _, _ := calculability(tc.r); got != tc.want {
			t.Errorf("%q: got %s want %s", tc.r.Vector, got, tc.want)
		}
	}
}

func TestDeterministicOrder(t *testing.T) {
	a := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v65), cnaOf("c", "z", v91).unres())
	b := run(rpm, cnaOf("c", "z", v91).unres(), cnaOf("b", "y", v65), cnaOf("a", "x", v65))
	if ContentFingerprint(a) != ContentFingerprint(b) {
		t.Error("arrival order changed the result")
	}
	wantConds(t, a, CondSameClassUnresolved)
}

func TestScoreBand(t *testing.T) {
	for score, want := range map[float64]string{0: "none", 3.9: "low", 4: "medium", 7: "high", 9: "critical"} {
		if got := ScoreBand(score); got != want {
			t.Errorf("%v: %s", score, got)
		}
	}
	if classRank("nope") != len(classOrder) {
		t.Error("unknown class rank")
	}
}

func TestLowerClassNeverConditions(t *testing.T) {
	// Deciding class selected final; a lower class has a disagreement and an unresolved one.
	out := run(rpm, cnaOf("c", "x", v65), cand("o1", "o", v81), cand("o2", "p", v91), cand("o3", "q", v91).unres())
	wantScore(t, out, OutcomeSelected, ScoreFinal, 6.5, "c")
	wantConds(t, out)
	wantDisp(t, out, "o3", DispUnresolved, ReasonLowerClass)
	wantDisp(t, out, "o1", DispAvailableNotSelected, ReasonLowerClass)
	if purlType("npm/x") != "" {
		t.Error("purl type of a non-purl")
	}
}

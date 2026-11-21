package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestParseSourceTime(t *testing.T) {
	cases := []struct {
		in     string
		interp domain.SourceTimeInterpretation
		want   time.Time
	}{
		{"", "", time.Time{}},
		{"2024-03-01T10:00:00Z", domain.TimeZoneStated, time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"2024-03-01T12:00:00+02:00", domain.TimeZoneStated, time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"2024-03-01T12:00:00+0200", domain.TimeZoneStated, time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"2024-03-01T10:00:00.123", domain.TimeZoneAssumedUTC, time.Date(2024, 3, 1, 10, 0, 0, 123000000, time.UTC)},
		{"2024-03-01", domain.TimeZoneAssumedUTC, time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"yesterday", domain.TimeUnparseable, time.Time{}},
	}
	for _, c := range cases {
		got := domain.ParseSourceTime(c.in)
		if got.Interpretation != c.interp || !got.Instant.Equal(c.want) || (c.in != "" && got.Original != c.in) {
			t.Errorf("ParseSourceTime(%q) = %+v, want %s %v", c.in, got, c.interp, c.want)
		}
	}
}

func rating(assessor, version, vector, ctx string) domain.PublishedRating {
	return domain.PublishedRating{Assessor: assessor, Publisher: "p", Version: version, Vector: vector, AssertedContext: ctx}
}

const (
	vecA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vecB = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

func TestObservationInputValidateAndFingerprint(t *testing.T) {
	ok := domain.ObservationInput{Source: "nvd", DocumentRef: "nvd:CVE-1", Ratings: []domain.PublishedRating{rating("a", "3.1", vecA, "")}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []domain.ObservationInput{
		{DocumentRef: "d"},
		{Source: "s"},
		{Source: "s", DocumentRef: "d", Ratings: []domain.PublishedRating{{Assessor: "a"}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	a := domain.ObservationInput{Source: "s", DocumentRef: "d", Applicability: []string{"y", "x", " x ", ""},
		Ratings: []domain.PublishedRating{rating("a", "3.1", vecA, ""), rating("b", "3.1", vecB, "")},
		Fetch:   domain.FetchMeta{ETag: "1"}}
	b := domain.ObservationInput{Source: "s", DocumentRef: "d", Applicability: []string{"x", "y"},
		Ratings: []domain.PublishedRating{rating("b", "3.1", vecB, ""), rating("a", "3.1", vecA, "")},
		Fetch:   domain.FetchMeta{ETag: "2"}}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("order, duplicates and fetch metadata must not change the fingerprint")
	}
	b.Ratings[0].StatedScore, b.Ratings[0].HasStatedScore = 7.5, true
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("a stated score is content")
	}
}

func TestNormalisation(t *testing.T) {
	if domain.NormaliseAssessor(" secalert@redhat.com ") != "redhat" || domain.NormaliseAssessor("Other") != "other" {
		t.Error("assessor alias")
	}
	if domain.NormaliseContext(" Golang:Foo ") != "go:foo" || domain.NormaliseContext("cpe:/o:redhat:x") != "cpe:/o:redhat:x" ||
		domain.NormaliseContext("Pkg") != "pkg" {
		t.Errorf("context: %q", domain.NormaliseContext(" Golang:Foo "))
	}
	if domain.NormaliseVector("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N") != vecA || domain.NormaliseVector(" AV:N ") != "AV:N" {
		t.Error("vector")
	}
	r := domain.SourceRating{InheritedContext: "inh"}
	if r.EffectiveContext() != "inh" {
		t.Error("inherited")
	}
	r.AssertedContext = "own"
	if r.EffectiveContext() != "own" {
		t.Error("asserted wins")
	}
}

func TestStatusOf(t *testing.T) {
	if domain.StatusOf(nil) != domain.RatingActive ||
		domain.StatusOf(&domain.RatingEvent{Kind: domain.RatingSuperseded}) != domain.RatingStatusSuperseded ||
		domain.StatusOf(&domain.RatingEvent{Kind: domain.RatingWithdrawn}) != domain.RatingStatusWithdrawn {
		t.Error("status")
	}
}

func stored(id string, r domain.PublishedRating) domain.SourceRating {
	return domain.SourceRating{ID: id, PublishedRating: r}
}

func TestPlanRevision(t *testing.T) {
	a := rating("cna", "3.1", vecA, "")
	b := rating("cna", "3.1", vecB, "")
	other := rating("vendor", "3.1", vecA, "")
	active := []domain.SourceRating{stored("r2", other), stored("r1", a)}

	// Carried unchanged: nothing new, nothing terminal.
	p := domain.PlanRevision(active, []domain.PublishedRating{a, other}, true)
	if len(p.New) != 0 || len(p.Events) != 0 {
		t.Errorf("carried: %+v", p)
	}
	// Correction in the same lineage supersedes; a lineage gone is withdrawn; a duplicate in
	// the revision is one new publication.
	p = domain.PlanRevision(active, []domain.PublishedRating{b, b}, true)
	if len(p.New) != 1 || len(p.Events) != 2 {
		t.Fatalf("complete: %+v", p)
	}
	if p.Events[0] != (domain.PlannedEvent{RatingID: "r1", Kind: domain.RatingSuperseded, ReplacedByIndex: 0}) ||
		p.Events[1] != (domain.PlannedEvent{RatingID: "r2", Kind: domain.RatingWithdrawn, ReplacedByIndex: -1}) {
		t.Errorf("events: %+v", p.Events)
	}
	// An incomplete revision changes no lifecycle.
	p = domain.PlanRevision(active, []domain.PublishedRating{b}, false)
	if len(p.New) != 1 || len(p.Events) != 0 {
		t.Errorf("incomplete: %+v", p)
	}
	// Republishing content identical to a terminal publication is a new publication.
	p = domain.PlanRevision(nil, []domain.PublishedRating{a}, true)
	if len(p.New) != 1 || len(p.Events) != 0 {
		t.Errorf("republish: %+v", p)
	}
	if a.LineageKey() != b.LineageKey() || a.ContentKey() == b.ContentKey() {
		t.Error("keys")
	}
}

func TestValidateRating(t *testing.T) {
	at := time.Unix(1, 0)
	r := domain.SourceRating{ID: "r", PublishedRating: domain.PublishedRating{Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}
	if v := domain.ValidateRating(r, at); v.Result != domain.ValidationUnsupported || v.SpecVersion != "2.0" || v.CalculatorVersion != domain.CalculatorVersion {
		t.Errorf("v2: %+v", v)
	}
	r.Version, r.Vector = "", "garbage"
	if v := domain.ValidateRating(r, at); v.Result != domain.ValidationUnsupported || !strings.Contains(v.Reason, "unknown") {
		t.Errorf("unknown: %+v", v)
	}
	r.Vector = "CVSS:3.1/AV:N"
	if v := domain.ValidateRating(r, at); v.Result != domain.ValidationInvalid || v.Reason == "" {
		t.Errorf("invalid: %+v", v)
	}
	r.Vector = vecA
	if v := domain.ValidateRating(r, at); v.Result != domain.ValidationValid || v.Base != 9.8 || v.HasTemporal || v.Stated != domain.StatedNotStated {
		t.Errorf("valid: %+v", v)
	}
	r.Vector, r.StatedScore, r.HasStatedScore = vecA+"/E:U", 9.8, true
	if v := domain.ValidateRating(r, at); !v.HasTemporal || v.Temporal != 9.0 || v.Stated != domain.StatedEqual {
		t.Errorf("temporal: %+v", v)
	}
	r.StatedScore = 7.0
	if v := domain.ValidateRating(r, at); v.Stated != domain.StatedDiffers {
		t.Errorf("differs: %+v", v)
	}
}

func member(id, assessor, ctx string, active bool) domain.IdentityMember {
	return domain.IdentityMember{RatingID: id, Assessor: assessor, Version: "3.1", Vector: vecA, AssertedContext: ctx, Active: active}
}

func TestGroupSetLinksInEitherOrder(t *testing.T) {
	vendor := member("v1", "redhat", "rpm:openssl", true)
	nvdCopy := member("n1", "secalert@redhat.com", "", true)
	a := domain.GroupSet([]domain.IdentityMember{vendor, nvdCopy})
	b := domain.GroupSet([]domain.IdentityMember{nvdCopy, vendor})
	if !a.Equal(b) || !a[0].Linked || a[0].IdentityKey != a[1].IdentityKey {
		t.Fatalf("grouping: %+v vs %+v", a, b)
	}
	// Alone, the NVD copy is its own unstated identity; adding the vendor links it.
	alone := domain.GroupSet([]domain.IdentityMember{nvdCopy})
	if ch := domain.DiffGrouping(alone, a); len(ch) != 1 || ch[0] != (domain.LinkChange{RatingID: "n1", Change: domain.ChangeLinked}) {
		t.Errorf("changes: %+v", ch)
	}
	if domain.GroupSet(nil) != nil {
		t.Error("empty")
	}
}

func TestGroupSetAmbiguityAndViability(t *testing.T) {
	a1 := member("a1", "x", "pkg-a", true)
	a2 := member("a2", "x", "pkg-a", true)
	b1 := member("b1", "x", "pkg-b", true)
	u := member("u", "x", "", true)
	g := domain.GroupSet([]domain.IdentityMember{a1, a2, b1, u})
	if e := entry(g, "u"); !e.Ambiguous || e.Linked {
		t.Fatalf("ambiguous: %+v", e)
	}
	// D11: A1 withdrawn, A2 active: A stays viable, u stays ambiguous.
	a1.Active = false
	g2 := domain.GroupSet([]domain.IdentityMember{a1, a2, b1, u})
	if !entry(g2, "u").Ambiguous || !g.Equal(g2) {
		t.Errorf("still ambiguous: %+v", g2)
	}
	// Only when A2 is terminal too does u link to B.
	a2.Active = false
	g3 := domain.GroupSet([]domain.IdentityMember{a1, a2, b1, u})
	if e := entry(g3, "u"); e.Ambiguous || !e.Linked || !strings.HasSuffix(e.IdentityKey, "|pkg-b") {
		t.Errorf("resolved: %+v", e)
	}
	if ch := domain.DiffGrouping(g2, g3); len(ch) != 2 || ch[0].Change != domain.ChangeAmbiguityResolved || ch[1].Change != domain.ChangeLinked {
		t.Errorf("resolve changes: %+v", ch)
	}
	if g.Equal(g3) || g.Equal(g3[:1]) {
		t.Error("Equal")
	}
	all := domain.GroupAll([]domain.IdentityMember{a1, b1, member("z", "other", "", true)})
	if len(all) != 2 {
		t.Errorf("sets: %v", all)
	}
}

func entry(g domain.Grouping, id string) domain.GroupingEntry {
	for _, e := range g {
		if e.RatingID == id {
			return e
		}
	}
	return domain.GroupingEntry{}
}

func TestDiffGroupingTransitions(t *testing.T) {
	own := domain.GroupingEntry{RatingID: "r", IdentityKey: "k|<unstated>"}
	linked := domain.GroupingEntry{RatingID: "r", IdentityKey: "k|a", Linked: true}
	linkedB := domain.GroupingEntry{RatingID: "r", IdentityKey: "k|b", Linked: true}
	amb := domain.GroupingEntry{RatingID: "r", IdentityKey: "k|<unstated>", Ambiguous: true}
	cases := []struct {
		name       string
		prev, next domain.Grouping
		want       []string
	}{
		{"new own", nil, domain.Grouping{own}, nil},
		{"new linked", nil, domain.Grouping{linked}, []string{domain.ChangeLinked}},
		{"new ambiguous", nil, domain.Grouping{amb}, []string{domain.ChangeMarkedAmbiguous}},
		{"same", domain.Grouping{linked}, domain.Grouping{linked}, nil},
		{"amb to own", domain.Grouping{amb}, domain.Grouping{own}, []string{domain.ChangeAmbiguityResolved}},
		{"linked to amb", domain.Grouping{linked}, domain.Grouping{amb}, []string{domain.ChangeUnlinked, domain.ChangeMarkedAmbiguous}},
		{"own to amb", domain.Grouping{own}, domain.Grouping{amb}, []string{domain.ChangeMarkedAmbiguous}},
		{"relinked", domain.Grouping{linked}, domain.Grouping{linkedB}, []string{domain.ChangeUnlinked, domain.ChangeLinked}},
		{"unlinked", domain.Grouping{linked}, domain.Grouping{own}, []string{domain.ChangeUnlinked}},
		{"own to linked", domain.Grouping{own}, domain.Grouping{linked}, []string{domain.ChangeLinked}},
	}
	for _, c := range cases {
		var got []string
		for _, ch := range domain.DiffGrouping(c.prev, c.next) {
			got = append(got, ch.Change)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMemberOf(t *testing.T) {
	r := domain.SourceRating{ID: "r", PublishedRating: rating("a", "3.1", vecA, "ctx")}
	m := domain.MemberOf(r, domain.RatingStatusWithdrawn)
	if m.Active || m.RatingID != "r" || m.SetKey() != "a|3.1|"+vecA {
		t.Errorf("member: %+v %s", m, m.SetKey())
	}
}

func TestProposalCarriesObservation(t *testing.T) {
	p, err := domain.NewExploitSignalProposal("epss", time.Unix(1, 0), domain.ExploitSignal{EPSS: 0.1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Observation(); ok {
		t.Fatal("no observation by default")
	}
	in := domain.ObservationInput{Source: "s", Ratings: []domain.PublishedRating{rating("a", "3.1", vecA, "")}, Applicability: []string{"x"}}
	q := p.WithObservation(in)
	in.Ratings[0].Assessor, in.Applicability[0] = "mutated", "mutated"
	got, ok := q.Observation()
	if !ok || got.Ratings[0].Assessor != "a" || got.Applicability[0] != "x" {
		t.Errorf("observation: %+v", got)
	}
}

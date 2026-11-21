package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// memRatings is an in-memory app.RatingStore that applies writes the way the Postgres store
// does, so a sequence of revisions can be followed end to end.
type memRatings struct {
	latest   map[string][2]string // source|doc -> {id, fingerprint}
	ratings  []domain.SourceRating
	events   map[string]domain.RatingEvent
	vals     map[string]domain.RatingValidation
	links    []domain.AssessmentLink
	seen     []domain.SeenEvent
	observed []domain.SourceObservation
	err      error
	readErr  error
}

func newMemRatings() *memRatings {
	return &memRatings{latest: map[string][2]string{}, events: map[string]domain.RatingEvent{}, vals: map[string]domain.RatingValidation{}}
}

func (m *memRatings) RecordRevision(_ context.Context, key app.RatingKey, build func(app.RatingPrior) (app.RatingWrite, error)) error {
	if m.err != nil {
		return m.err
	}
	l := m.latest[key.Source+"|"+key.DocumentRef]
	prior := app.RatingPrior{LatestObservationID: l[0], LatestFingerprint: l[1], Groupings: map[string]domain.Grouping{}}
	for _, r := range m.ratings {
		_, term := m.events[r.ID]
		st := domain.RatingActive
		if term {
			st = domain.RatingStatusWithdrawn
		}
		prior.Members = append(prior.Members, domain.MemberOf(r, st))
		if !term && r.Source == key.Source && r.DocumentRef == key.DocumentRef {
			prior.Active = append(prior.Active, r)
		}
	}
	for _, l := range m.links {
		prior.Groupings[l.SetKey] = l.Grouping
	}
	w, err := build(prior)
	if err != nil {
		return err
	}
	if w.Observation != nil {
		m.latest[key.Source+"|"+key.DocumentRef] = [2]string{w.Observation.ID, key.Fingerprint}
		m.observed = append(m.observed, *w.Observation)
	}
	m.seen = append(m.seen, w.Seen)
	m.ratings = append(m.ratings, w.Ratings...)
	for _, e := range w.Events {
		m.events[e.RatingID] = e
	}
	for _, v := range w.Validations {
		m.vals[v.RatingID] = v
	}
	m.links = append(m.links, w.Links...)
	return nil
}

func (m *memRatings) RatingsForCVE(_ context.Context, cve string) (app.RatingsSnapshot, error) {
	if m.readErr != nil {
		return app.RatingsSnapshot{}, m.readErr
	}
	snap := app.RatingsSnapshot{Observations: m.observed, Events: m.events, Validations: m.vals, Groupings: map[string]domain.Grouping{}}
	for _, r := range m.ratings {
		if r.CVE == cve {
			snap.Ratings = append(snap.Ratings, r)
		}
	}
	for _, l := range m.links {
		snap.Groupings[l.SetKey] = l.Grouping
	}
	return snap, nil
}

type countIDs struct{ n int }

func (c *countIDs) NewID() string { c.n++; return fmt.Sprintf("id-%02d", c.n) }

const (
	vecHigh = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vecLow  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
)

func vendorDoc(complete bool, ratings ...domain.PublishedRating) domain.ObservationInput {
	return domain.ObservationInput{Source: "redhat", Feed: "f", DocumentRef: "redhat:CVE-2024-0001", Complete: complete,
		Applicability: []string{"cpe:/o:redhat:enterprise_linux:9"}, Ratings: ratings}
}

func TestRatingServiceRecordsLifecycleAndLinks(t *testing.T) {
	ctx := context.Background()
	st := newMemRatings()
	svc := app.NewRatingService(st, &countIDs{}, fixedClock{})
	id := cve(t, "CVE-2024-0001")
	vendor := domain.PublishedRating{Assessor: "redhat", Version: "3.1", Vector: vecHigh, StatedScore: 9.8, HasStatedScore: true}

	// 1. The NVD copy of the CNA rating arrives first: its own unstated identity.
	nvd := domain.ObservationInput{Source: "nvd", DocumentRef: "nvd:CVE-2024-0001", Complete: true,
		Ratings: []domain.PublishedRating{{Assessor: "secalert@redhat.com", NVDType: "Secondary", Version: "3.1", Vector: vecHigh}}}
	if err := svc.Record(ctx, id, nvd); err != nil {
		t.Fatal(err)
	}
	// 2. The vendor document: same assessor, vector and version, asserting no context either.
	if err := svc.Record(ctx, id, vendorDoc(true, vendor)); err != nil {
		t.Fatal(err)
	}
	if len(st.ratings) != 2 || st.ratings[1].InheritedContext != "cpe:/o:redhat:enterprise_linux:9" {
		t.Fatalf("ratings: %+v", st.ratings)
	}
	if v := st.vals[st.ratings[1].ID]; v.Result != domain.ValidationValid || v.Stated != domain.StatedEqual {
		t.Errorf("validation: %+v", v)
	}
	// 3. Same revision again: a seen event only (R-S7).
	if err := svc.Record(ctx, id, vendorDoc(true, vendor)); err != nil {
		t.Fatal(err)
	}
	if len(st.observed) != 2 || st.seen[2].Outcome != domain.SeenUnchanged || len(st.ratings) != 2 {
		t.Fatalf("unchanged revision created records: %d obs, %+v", len(st.observed), st.seen)
	}
	// 4. A complete revision without cvss3 withdraws the vendor publication only (EDR 3.4 2a).
	linksBefore := len(st.links)
	if err := svc.Record(ctx, id, vendorDoc(true)); err != nil {
		t.Fatal(err)
	}
	ev, ok := st.events[st.ratings[1].ID]
	if !ok || ev.Kind != domain.RatingWithdrawn {
		t.Fatalf("withdrawal: %+v", st.events)
	}
	if _, nvdTerminal := st.events[st.ratings[0].ID]; nvdTerminal {
		t.Error("the NVD publication must stay active")
	}
	if len(st.links) != linksBefore {
		t.Errorf("a withdrawal between two unstated publications changes no grouping: %+v", st.links[linksBefore:])
	}
	// 5. A corrected vendor rating in the same lineage: new publication, nothing more to end.
	corrected := vendor
	corrected.Vector, corrected.StatedScore = vecLow, 3.7
	if err := svc.Record(ctx, id, vendorDoc(true, corrected)); err != nil {
		t.Fatal(err)
	}
	if len(st.ratings) != 3 {
		t.Fatalf("ratings: %d", len(st.ratings))
	}
	// 6. A later correction supersedes it.
	again := corrected
	again.Vector, again.StatedScore = vecHigh, 9.8
	if err := svc.Record(ctx, id, vendorDoc(true, again)); err != nil {
		t.Fatal(err)
	}
	if ev := st.events[st.ratings[2].ID]; ev.Kind != domain.RatingSuperseded || ev.ReplacedBy != st.ratings[3].ID {
		t.Errorf("superseded: %+v", ev)
	}

	view, err := svc.RatingsForCVE(ctx, id.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Ratings) != 4 || view.Ratings[0].Status != domain.RatingActive || view.Ratings[1].Status != domain.RatingStatusWithdrawn ||
		view.Ratings[1].Event == nil || view.Ratings[1].Validation == nil || view.Ratings[0].Identity.IdentityKey == "" {
		t.Errorf("view: %+v", view.Ratings)
	}
}

func TestRatingServiceAssertedLinking(t *testing.T) {
	ctx := context.Background()
	st := newMemRatings()
	svc := app.NewRatingService(st, &countIDs{}, fixedClock{})
	id := cve(t, "CVE-2024-0002")
	asserted := domain.ObservationInput{Source: "vendor", DocumentRef: "v:1", Complete: true,
		Ratings: []domain.PublishedRating{{Assessor: "x", Version: "3.1", Vector: vecHigh, AssertedContext: "pkg"}}}
	copyDoc := domain.ObservationInput{Source: "nvd", DocumentRef: "n:1", Complete: true,
		Ratings: []domain.PublishedRating{{Assessor: "x", Version: "3.1", Vector: vecHigh}}}
	for _, in := range []domain.ObservationInput{asserted, copyDoc} {
		if err := svc.Record(ctx, id, in); err != nil {
			t.Fatal(err)
		}
	}
	last := st.links[len(st.links)-1]
	if len(last.Changes) != 1 || last.Changes[0].Change != domain.ChangeLinked || last.PolicyVersion != domain.LinkPolicyVersion {
		t.Errorf("link: %+v", last)
	}
	// The asserted publication is withdrawn: its identity is no longer viable, the copy unlinks.
	gone := asserted
	gone.Ratings, gone.Applicability = nil, []string{"b", "a", "a", " "}
	if err := svc.Record(ctx, id, gone); err != nil {
		t.Fatal(err)
	}
	last = st.links[len(st.links)-1]
	if last.Cause != app.LinkCausePublicationTerminal || len(last.Changes) != 1 || last.Changes[0].Change != domain.ChangeUnlinked {
		t.Errorf("unlink: %+v", last)
	}
	if got := st.observed[len(st.observed)-1].Applicability; len(got) != 2 || got[0] != "a" {
		t.Errorf("applicability: %v", got)
	}
}

func TestRatingServiceRefusalsAndErrors(t *testing.T) {
	ctx := context.Background()
	st := newMemRatings()
	svc := app.NewRatingService(st, &countIDs{}, fixedClock{})
	if err := svc.Record(ctx, value.CVEID{}, vendorDoc(true)); err == nil {
		t.Error("zero cve")
	}
	if err := svc.Record(ctx, cve(t, "CVE-2024-0003"), domain.ObservationInput{}); err == nil {
		t.Error("invalid input")
	}
	st.err = errors.New("boom")
	if err := svc.Record(ctx, cve(t, "CVE-2024-0003"), vendorDoc(true)); err == nil {
		t.Error("store error")
	}
	st.readErr = errors.New("boom")
	if _, err := svc.RatingsForCVE(ctx, "CVE-2024-0003"); err == nil {
		t.Error("read error")
	}
}

type recordFunc func(context.Context, value.CVEID, domain.ObservationInput) error

func (f recordFunc) Record(ctx context.Context, c value.CVEID, in domain.ObservationInput) error {
	return f(ctx, c, in)
}

func TestFoldProposalRecordsAttachedObservation(t *testing.T) {
	ctx := context.Background()
	var got []domain.ObservationInput
	rec := recordFunc(func(_ context.Context, _ value.CVEID, in domain.ObservationInput) error {
		got = append(got, in)
		return nil
	})
	s := svc(newRepo(), &seqIDs{}).WithRatings(rec)
	p := vulnFacts(t, "nvd", value.SeverityHigh).WithObservation(vendorDoc(true))
	if _, _, err := s.FoldProposal(ctx, cve(t, "CVE-2024-0004"), p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FoldProposal(ctx, cve(t, "CVE-2024-0004"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Source != "redhat" {
		t.Errorf("recorded: %+v", got)
	}
	failing := svc(newRepo(), &seqIDs{}).WithRatings(recordFunc(func(context.Context, value.CVEID, domain.ObservationInput) error {
		return errors.New("boom")
	}))
	if _, _, err := failing.FoldProposal(ctx, cve(t, "CVE-2024-0004"), p); err == nil {
		t.Error("a rating store error must surface")
	}
}

type fakeRecordSource struct {
	obs   domain.ObservationInput
	found bool
	err   map[string]error
}

func (f fakeRecordSource) FetchRecord(_ context.Context, c value.CVEID) (domain.ObservationInput, bool, error) {
	if err := f.err[c.String()]; err != nil {
		return domain.ObservationInput{}, false, err
	}
	return f.obs, f.found, nil
}

type knownSet struct {
	set map[string]struct{}
	err error
}

func (k knownSet) KnownCVEs(context.Context) (map[string]struct{}, error) { return k.set, k.err }

func TestCVEOrgEnrichment(t *testing.T) {
	ctx := context.Background()
	obs := domain.ObservationInput{Source: "cveorg", DocumentRef: "cveorg:CVE-2024-0005", Complete: true}
	calls := 0
	rec := recordFunc(func(context.Context, value.CVEID, domain.ObservationInput) error { calls++; return nil })
	known := knownSet{set: map[string]struct{}{"CVE-2024-0005": {}, "not-a-cve": {}, "CVE-2024-0006": {}}}
	src := fakeRecordSource{obs: obs, found: true, err: map[string]error{"CVE-2024-0006": errors.New("timeout")}}
	n, err := app.NewCVEOrgEnrichmentService(src, known, rec).Enrich(ctx)
	if err != nil || n != 1 || calls != 1 {
		t.Errorf("sweep: n=%d calls=%d err=%v", n, calls, err)
	}
	if n, _ := app.NewCVEOrgEnrichmentService(fakeRecordSource{}, known, rec).Enrich(ctx); n != 0 {
		t.Error("not found records nothing")
	}
	if _, err := app.NewCVEOrgEnrichmentService(src, knownSet{err: errors.New("db")}, rec).Enrich(ctx); err == nil {
		t.Error("known error")
	}
	bad := recordFunc(func(context.Context, value.CVEID, domain.ObservationInput) error { return errors.New("db") })
	if _, err := app.NewCVEOrgEnrichmentService(src, known, bad).Enrich(ctx); err == nil {
		t.Error("store error")
	}
}

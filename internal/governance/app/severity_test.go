package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// Owner-set severity (EDR-SCORING-01 section 7.1).

var errSeverityBoom = errors.New("boom")

// memSeverity is an in-memory OwnerSeverityStore; failOn names the method that fails.
type memSeverity struct {
	originals map[domain.FindingID]app.OriginalSeverity
	history   map[domain.FindingID][]app.OwnerSeverityRecord
	failOn    string
}

func newMemSeverity() *memSeverity {
	return &memSeverity{originals: map[domain.FindingID]app.OriginalSeverity{}, history: map[domain.FindingID][]app.OwnerSeverityRecord{}}
}

func (m *memSeverity) fail(method string) error {
	if m.failOn == method {
		return errSeverityBoom
	}
	return nil
}

func (m *memSeverity) CurrentOwnerSeverities(_ context.Context, ids []domain.FindingID) (map[domain.FindingID]domain.OwnerSeverity, error) {
	if err := m.fail("current"); err != nil {
		return nil, err
	}
	out := map[domain.FindingID]domain.OwnerSeverity{}
	for _, id := range ids {
		for _, r := range m.history[id] {
			if r.EndedAt.IsZero() {
				out[id] = r.OwnerSeverity
			}
		}
	}
	return out, nil
}

func (m *memSeverity) OwnerSeverityHistory(_ context.Context, id domain.FindingID) ([]app.OwnerSeverityRecord, error) {
	return m.history[id], m.fail("history")
}

func (m *memSeverity) OriginalSeverities(_ context.Context, ids []domain.FindingID) (map[domain.FindingID]app.OriginalSeverity, error) {
	if err := m.fail("originals"); err != nil {
		return nil, err
	}
	out := map[domain.FindingID]app.OriginalSeverity{}
	for _, id := range ids {
		if o, ok := m.originals[id]; ok {
			out[id] = o
		}
	}
	return out, nil
}

func (m *memSeverity) end(id domain.FindingID, by, cause string, at time.Time) bool {
	rows := m.history[id]
	for i := range rows {
		if rows[i].EndedAt.IsZero() {
			rows[i].EndedAt, rows[i].EndedBy, rows[i].EndCause = at, by, cause
			return true
		}
	}
	return false
}

func (m *memSeverity) SaveOwnerSeverities(_ context.Context, writes []app.OwnerSeverityWrite) error {
	if err := m.fail("save"); err != nil {
		return err
	}
	for _, w := range writes {
		m.end(w.FindingID, w.Severity.Actor.ID, "replaced", w.Severity.SetAt)
		m.history[w.FindingID] = append(m.history[w.FindingID], app.OwnerSeverityRecord{OwnerSeverity: w.Severity})
	}
	return nil
}

func (m *memSeverity) EndOwnerSeverity(_ context.Context, id domain.FindingID, actorID string, at time.Time) (bool, error) {
	if err := m.fail("end"); err != nil {
		return false, err
	}
	return m.end(id, actorID, "removed", at), nil
}

func (m *memSeverity) KeepOwnerSeverity(_ context.Context, id domain.FindingID, kept domain.SeverityKept) (bool, error) {
	if err := m.fail("keep"); err != nil {
		return false, err
	}
	rows := m.history[id]
	for i := range rows {
		if rows[i].EndedAt.IsZero() {
			k := kept
			rows[i].Kept = &k
			return true, nil
		}
	}
	return false, nil
}

// fixedCandidates is the pick list seam: the given Findings, or an error.
type fixedCandidates struct {
	ids []domain.FindingID
	err error
}

func (c fixedCandidates) CopyCandidates(context.Context, domain.FindingID) ([]app.CopyCandidate, error) {
	if c.err != nil {
		return nil, c.err
	}
	var out []app.CopyCandidate
	for _, id := range c.ids {
		out = append(out, app.CopyCandidate{ScopeTarget: app.ScopeTarget{FindingID: id, ReleaseID: "rel-" + string(id), ProductID: "P1", ProjectID: "A"}})
	}
	return out, nil
}

func sevScore(v float64) *float64 { return &v }

func severityEstate(t *testing.T) (*fakeRepo, *memSeverity) {
	t.Helper()
	repo := newRepo()
	for _, id := range []string{"src", "a2", "b1"} {
		repo.seed(identified(t, id, "rel-"+id, "fl-1", "CVE-2026-1"))
	}
	st := newMemSeverity()
	st.originals["src"] = app.OriginalSeverity{Score: sevScore(9.8), Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	st.originals["a2"] = app.OriginalSeverity{Score: sevScore(5.0)}
	return repo, st
}

func severitySvc(repo *fakeRepo, st *memSeverity, c app.SeverityCandidates) *app.SeverityService {
	return app.NewSeverityService(repo, st, c, fixedClock{})
}

func TestSeveritySetByLevelOnTheFindingAndThePicks(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	svc := severitySvc(repo, st, fixedCandidates{ids: []domain.FindingID{"a2", "b1"}})

	// b1 already carries one: it is replaced and counted.
	if _, err := svc.Set(ctx, "b1", app.SetSeverityInput{Level: "low", Reason: "earlier", Actor: human}); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Set(ctx, "src", app.SetSeverityInput{
		Level: "high", Reason: "not reachable", Actor: human, ApplyTo: []domain.FindingID{"a2", "b1", "a2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 3 || res.Replaced != 1 {
		t.Fatalf("result = %+v", res)
	}
	v, err := svc.View(ctx, "src")
	if err != nil {
		t.Fatal(err)
	}
	if v.CVE != "CVE-2026-1" || v.Owner == nil || v.Owner.Score != 8.9 || v.Owner.Level != domain.SeverityHigh ||
		v.Owner.PickedFrom != "" || *v.Original.Score != 9.8 || len(v.History) != 1 {
		t.Fatalf("src view = %+v owner %+v", v, v.Owner)
	}
	// Each pick is computed from its own original score: 5.0 moves up to 7.0, no original gives 7.0.
	a2, _ := svc.View(ctx, "a2")
	if a2.Owner == nil || a2.Owner.Score != 7.0 || a2.Owner.PickedFrom != "src" || a2.Owner.Reason != "not reachable" {
		t.Fatalf("a2 owner = %+v", a2.Owner)
	}
	b1, _ := svc.View(ctx, "b1")
	if b1.Owner == nil || b1.Owner.Score != 7.0 || len(b1.History) != 2 || b1.History[0].EndCause != "replaced" {
		t.Fatalf("b1 = %+v", b1)
	}
}

func TestSeveritySetByVectorAndPreview(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	svc := severitySvc(repo, st, nil)
	vec := "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

	p, err := svc.Preview(ctx, "src", "", vec)
	if err != nil || p.Score != 8.1 || p.Level != domain.SeverityHigh || p.Vector != vec || *p.OriginalScore != 9.8 {
		t.Fatalf("preview = %+v, %v", p, err)
	}
	if v, _ := svc.View(ctx, "src"); v.Owner != nil || len(v.History) != 0 {
		t.Fatalf("a preview recorded something: %+v", v)
	}
	res, err := svc.Set(ctx, "src", app.SetSeverityInput{Vector: vec, Reason: "needs a login here", Actor: human})
	if err != nil || res.Applied != 1 || res.Replaced != 0 {
		t.Fatalf("set = %+v, %v", res, err)
	}
	v, _ := svc.View(ctx, "src")
	if v.Owner == nil || v.Owner.Kind != domain.OwnerSeverityByVector || v.Owner.Score != 8.1 || !v.Owner.SetAt.Equal(fixedClock{}.Now()) {
		t.Fatalf("owner = %+v", v.Owner)
	}
}

func TestSeverityRemoveBringsTheOriginalBack(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	svc := severitySvc(repo, st, nil)
	if err := svc.Remove(ctx, "src", human); !errors.Is(err, app.ErrNoOwnerSeverity) {
		t.Fatalf("nothing to remove: %v", err)
	}
	if _, err := svc.Set(ctx, "src", app.SetSeverityInput{Level: "low", Reason: "r", Actor: human}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Remove(ctx, "src", human); err != nil {
		t.Fatal(err)
	}
	v, _ := svc.View(ctx, "src")
	if v.Owner != nil || len(v.History) != 1 || v.History[0].EndCause != "removed" || v.History[0].EndedBy != human.ID {
		t.Fatalf("after remove = %+v", v)
	}
	if err := svc.Remove(ctx, "src", domain.Actor{Kind: domain.ActorPolicy, ID: "p"}); !errors.Is(err, domain.ErrOwnerSeverityActor) {
		t.Fatalf("a rule removed a severity: %v", err)
	}
	if err := svc.Remove(ctx, "missing", human); err == nil {
		t.Fatal("removed from a Finding that does not exist")
	}
	st.failOn = "end"
	if err := svc.Remove(ctx, "src", human); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("store failure: %v", err)
	}
}

func TestSeverityTargets(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	if _, err := severitySvc(repo, st, nil).Targets(ctx, "src"); !errors.Is(err, app.ErrSeverityTargetsUnavailable) {
		t.Fatalf("no seam: %v", err)
	}
	if _, err := severitySvc(repo, st, fixedCandidates{err: errSeverityBoom}).Targets(ctx, "src"); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("seam failure: %v", err)
	}
	svc := severitySvc(repo, st, fixedCandidates{ids: []domain.FindingID{"a2", "b1"}})
	if _, err := svc.Set(ctx, "b1", app.SetSeverityInput{Level: "low", Reason: "r", Actor: human}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Targets(ctx, "src")
	if err != nil || len(got) != 2 {
		t.Fatalf("targets = %+v, %v", got, err)
	}
	if got[0].FindingID != "a2" || got[0].Owner != nil || got[1].FindingID != "b1" || got[1].Owner == nil || got[1].Owner.Level != domain.SeverityLow {
		t.Fatalf("targets = %+v", got)
	}
	st.failOn = "current"
	if _, err := svc.Targets(ctx, "src"); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("store failure: %v", err)
	}
}

func TestSeveritySetRefusals(t *testing.T) {
	ctx := context.Background()
	ok := app.SetSeverityInput{Level: "low", Reason: "r", Actor: human}
	pick := app.SetSeverityInput{Level: "low", Reason: "r", Actor: human, ApplyTo: []domain.FindingID{"a2"}}

	repo, st := severityEstate(t)
	if _, err := severitySvc(repo, st, nil).Set(ctx, "missing", ok); err == nil {
		t.Fatal("set on a Finding that does not exist")
	}
	if _, err := severitySvc(repo, st, nil).Set(ctx, "src", pick); !errors.Is(err, app.ErrSeverityTargetsUnavailable) {
		t.Fatalf("picks with no seam: %v", err)
	}
	if _, err := severitySvc(repo, st, fixedCandidates{err: errSeverityBoom}).Set(ctx, "src", pick); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("seam failure: %v", err)
	}
	// A pick outside the list (another product, another CVE, the Finding itself) refuses everything.
	svc := severitySvc(repo, st, fixedCandidates{ids: []domain.FindingID{"a2"}})
	bad := app.SetSeverityInput{Level: "low", Reason: "r", Actor: human, ApplyTo: []domain.FindingID{"a2", "b1"}}
	if _, err := svc.Set(ctx, "src", bad); !errors.Is(err, app.ErrSeverityTargetInvalid) {
		t.Fatalf("bad pick: %v", err)
	}
	if v, _ := svc.View(ctx, "a2"); v.Owner != nil {
		t.Fatal("a refused request recorded a severity")
	}
	if _, err := svc.Set(ctx, "src", app.SetSeverityInput{Level: "low", Actor: human}); !errors.Is(err, domain.ErrOwnerSeverityReason) {
		t.Fatalf("no reason: %v", err)
	}
	for _, method := range []string{"originals", "current", "save"} {
		repo, st := severityEstate(t)
		st.failOn = method
		if _, err := severitySvc(repo, st, nil).Set(ctx, "src", ok); !errors.Is(err, errSeverityBoom) {
			t.Fatalf("%s failure: %v", method, err)
		}
	}
}

func TestSeverityViewAndPreviewFailures(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	svc := severitySvc(repo, st, nil)
	if _, err := svc.View(ctx, "missing"); err == nil {
		t.Fatal("viewed a Finding that does not exist")
	}
	if _, err := svc.Preview(ctx, "missing", "low", ""); err == nil {
		t.Fatal("previewed a Finding that does not exist")
	}
	if _, err := svc.Preview(ctx, "src", "", ""); !errors.Is(err, domain.ErrOwnerSeverityInput) {
		t.Fatalf("empty preview: %v", err)
	}
	st.failOn = "originals"
	if _, err := svc.View(ctx, "src"); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("view: %v", err)
	}
	if _, err := svc.Preview(ctx, "src", "low", ""); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("preview: %v", err)
	}
	st.failOn = "history"
	if _, err := svc.View(ctx, "src"); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("view history: %v", err)
	}
}

// OS6: a changed original flags the severity for review and never changes it; "keep" makes the
// original the person saw the new baseline.
func TestSeverityReviewAndKeep(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	svc := severitySvc(repo, st, nil)
	if err := svc.Keep(ctx, "src", human); !errors.Is(err, app.ErrNoOwnerSeverity) {
		t.Fatalf("keep with none in force: %v", err)
	}
	if _, err := svc.Set(ctx, "src", app.SetSeverityInput{Level: "medium", Reason: "r", Actor: human}); err != nil {
		t.Fatal(err)
	}
	v, _ := svc.View(ctx, "src")
	if v.Review != "" || v.Owner.OriginalVector == "" {
		t.Fatalf("fresh severity: review %q owner %+v", v.Review, v.Owner)
	}
	if err := svc.Keep(ctx, "src", human); !errors.Is(err, app.ErrNothingToReview) {
		t.Fatalf("keep with nothing changed: %v", err)
	}

	// The source corrects its rating: flagged, with what changed; the severity is untouched.
	st.originals["src"] = app.OriginalSeverity{Score: sevScore(7.5), Vector: st.originals["src"].Vector}
	v, _ = svc.View(ctx, "src")
	if v.Review != "the original score changed from 9.8 to 7.5" || v.Owner.Score != 6.9 {
		t.Fatalf("after the change: review %q owner %+v", v.Review, v.Owner)
	}
	if err := svc.Keep(ctx, "src", domain.Actor{Kind: domain.ActorSystem, ID: "s"}); !errors.Is(err, domain.ErrOwnerSeverityActor) {
		t.Fatalf("a rule kept a severity: %v", err)
	}
	st.failOn = "keep"
	if err := svc.Keep(ctx, "src", human); !errors.Is(err, errSeverityBoom) {
		t.Fatalf("store failure: %v", err)
	}
	st.failOn = ""
	if err := svc.Keep(ctx, "src", human); err != nil {
		t.Fatal(err)
	}
	v, _ = svc.View(ctx, "src")
	if v.Review != "" || v.Owner.Kept == nil || v.Owner.Kept.By != human.ID || *v.Owner.Kept.Score != 7.5 || v.Owner.Score != 6.9 || len(v.History) != 1 {
		t.Fatalf("after keep: review %q owner %+v", v.Review, v.Owner)
	}
	if err := svc.Keep(ctx, "missing", human); err == nil {
		t.Fatal("kept on a Finding that does not exist")
	}
}

// OS5: a copied decision carries the source's owner-set severity, once.
func TestCopySeverity(t *testing.T) {
	ctx := context.Background()
	repo, st := severityEstate(t)
	svc := severitySvc(repo, st, nil)
	// A source with none copies nothing and leaves the target as it is.
	if _, err := svc.Set(ctx, "a2", app.SetSeverityInput{Level: "low", Reason: "own", Actor: human}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CopySeverity(ctx, "src", "a2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.View(ctx, "a2"); v.Owner.Reason != "own" || len(v.History) != 1 {
		t.Fatalf("a source with none changed the target: %+v", v)
	}
	if _, err := svc.Set(ctx, "src", app.SetSeverityInput{Level: "high", Reason: "not reachable", Actor: human}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CopySeverity(ctx, "src", "a2"); err != nil {
		t.Fatal(err)
	}
	v, _ := svc.View(ctx, "a2")
	if v.Owner.Level != domain.SeverityHigh || v.Owner.Score != 7.0 || v.Owner.Reason != "not reachable" || v.Owner.Actor != human ||
		v.Owner.PickedFrom != "src" || len(v.History) != 2 || v.History[0].EndCause != "replaced" || v.Review != "" {
		t.Fatalf("after the copy: %+v owner %+v", v, v.Owner)
	}
	// A retried copy records nothing twice.
	if err := svc.CopySeverity(ctx, "src", "a2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.View(ctx, "a2"); len(v.History) != 2 {
		t.Fatalf("the copy was recorded twice: %+v", v.History)
	}
	for _, method := range []string{"current", "originals", "save"} {
		st.failOn = method
		if err := svc.CopySeverity(ctx, "src", "b1"); !errors.Is(err, errSeverityBoom) {
			t.Fatalf("%s failure: %v", method, err)
		}
	}
}

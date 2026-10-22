package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type fakeSLAStore struct {
	policies   []app.SLAPolicyRecord
	policyErr  error
	putErr     error
	facts      []app.SLAFacts
	factsErr   error
	running    []app.SLAFacts
	runningErr error
	recordErr  error
	recorded   map[string]bool
	notes      []app.OutboxNote
	pages      int
}

func (f *fakeSLAStore) SLAPolicies(context.Context) ([]app.SLAPolicyRecord, error) {
	return f.policies, f.policyErr
}

func (f *fakeSLAStore) PutSLAPolicy(_ context.Context, rec app.SLAPolicyRecord) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.policies = append(f.policies, rec)
	return nil
}

func (f *fakeSLAStore) SLAFactsForRelease(context.Context, string) ([]app.SLAFacts, error) {
	return f.facts, f.factsErr
}

func (f *fakeSLAStore) RunningSLAFacts(_ context.Context, after string, limit int) ([]app.SLAFacts, error) {
	f.pages++
	if f.runningErr != nil {
		return nil, f.runningErr
	}
	var out []app.SLAFacts
	for _, x := range f.running {
		if string(x.FindingID) > after {
			out = append(out, x)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeSLAStore) RecordSLABreach(_ context.Context, id domain.FindingID, period time.Time, note app.OutboxNote) (bool, error) {
	if f.recordErr != nil {
		return false, f.recordErr
	}
	if f.recorded == nil {
		f.recorded = map[string]bool{}
	}
	key := fmt.Sprintf("%s@%s", id, period.Format(time.RFC3339))
	if f.recorded[key] {
		return false, nil
	}
	f.recorded[key] = true
	f.notes = append(f.notes, note)
	return true, nil
}

type fakeProductOf struct {
	product string
	err     error
	asks    int
}

func (f *fakeProductOf) ProductAndProjectOfRelease(context.Context, string) (string, string, error) {
	f.asks++
	return f.product, "prj", f.err
}

// A Finding created `ageDays` before fixedClock's now, in bucket `bucket`.
func slaFacts(id string, bucket string, ageDays int) app.SLAFacts {
	now := fixedClock{}.Now()
	return app.SLAFacts{FindingID: domain.FindingID(id), ReleaseID: "rel-1", FaultlineID: "fl-" + id, CVE: "CVE-" + id,
		Input: domain.SLAInput{CreatedAt: now.Add(-time.Duration(ageDays) * 24 * time.Hour), Bucket: bucket, CurrentBucket: bucket}}
}

func TestSLAService_PoliciesDefaultAndOverrides(t *testing.T) {
	st := &fakeSLAStore{}
	svc := app.NewSLAService(st, nil, fixedClock{})
	set, err := svc.Policies(context.Background())
	if err != nil || set.Estate.Policy != domain.DefaultSLAPolicy() || len(set.Overrides) != 0 {
		t.Fatalf("defaults: %+v %v", set, err)
	}
	custom := domain.DefaultSLAPolicy()
	custom.Critical.Days = 3
	if _, err := svc.PutPolicy(context.Background(), "", custom, "alice"); err != nil {
		t.Fatal(err)
	}
	rec, err := svc.PutPolicy(context.Background(), " prod-1 ", domain.DefaultSLAPolicy(), "alice")
	if err != nil || rec.Scope != "prod-1" || rec.UpdatedBy != "alice" || !rec.UpdatedAt.Equal(fixedClock{}.Now()) {
		t.Fatalf("put override: %+v %v", rec, err)
	}
	set, _ = svc.Policies(context.Background())
	if set.Estate.Policy.Critical.Days != 3 || len(set.Overrides) != 1 {
		t.Fatalf("stored: %+v", set)
	}

	bad := domain.DefaultSLAPolicy()
	bad.High.Days = 0
	if _, err := svc.PutPolicy(context.Background(), "", bad, "alice"); !errors.Is(err, app.ErrInvalidSLAPolicy) {
		t.Fatalf("invalid: %v", err)
	}
	st.putErr = errors.New("db down")
	if _, err := svc.PutPolicy(context.Background(), "", custom, "alice"); err == nil {
		t.Fatal("put error swallowed")
	}
	st.policyErr = errors.New("db down")
	if _, err := svc.Policies(context.Background()); err == nil {
		t.Fatal("policy error swallowed")
	}
}

func TestSLAService_ReleaseStatusPicksProductOverride(t *testing.T) {
	strict := domain.DefaultSLAPolicy()
	strict.High.Days = 5
	st := &fakeSLAStore{
		policies: []app.SLAPolicyRecord{{Scope: "prod-strict", Policy: strict}, {Scope: "prod-other", Policy: domain.DefaultSLAPolicy()}},
		facts:    []app.SLAFacts{slaFacts("a", domain.SLABucketHigh, 10)},
	}
	ctx := context.Background()

	got, err := app.NewSLAService(st, &fakeProductOf{product: "prod-strict"}, fixedClock{}).ReleaseStatus(ctx, "rel-1")
	if err != nil || got["a"].State != domain.SLABreached {
		t.Fatalf("override: %+v %v", got, err)
	}
	// Another product, an unresolvable product, and no Registry seam: the estate's 30 days.
	for name, id := range map[string]app.ProductOfRelease{
		"no match": &fakeProductOf{product: "prod-none"},
		"down":     &fakeProductOf{err: errors.New("registry down")},
		"no seam":  nil,
	} {
		got, err := app.NewSLAService(st, id, fixedClock{}).ReleaseStatus(ctx, "rel-1")
		if err != nil || got["a"].State != domain.SLAWithin {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	// No overrides at all: Registry is never asked.
	asked := &fakeProductOf{product: "prod-strict"}
	if _, err := app.NewSLAService(&fakeSLAStore{facts: st.facts}, asked, fixedClock{}).ReleaseStatus(ctx, "rel-1"); err != nil || asked.asks != 0 {
		t.Fatalf("asked Registry without overrides: %d %v", asked.asks, err)
	}

	if _, err := app.NewSLAService(&fakeSLAStore{policyErr: errors.New("x")}, nil, fixedClock{}).ReleaseStatus(ctx, "rel-1"); err == nil {
		t.Fatal("policy error swallowed")
	}
	if _, err := app.NewSLAService(&fakeSLAStore{factsErr: errors.New("x")}, nil, fixedClock{}).ReleaseStatus(ctx, "rel-1"); err == nil {
		t.Fatal("facts error swallowed")
	}
}

// The sweep announces each breached period once, pages through the whole population, and asks
// Registry at most once per release per pass.
func TestSLAService_SweepAnnouncesOncePerPeriod(t *testing.T) {
	st := &fakeSLAStore{policies: []app.SLAPolicyRecord{{Scope: "prod-1", Policy: domain.DefaultSLAPolicy()}}}
	for i := 0; i < app.SLASweepBatch+3; i++ {
		st.running = append(st.running, slaFacts(fmt.Sprintf("f%04d", i), domain.SLABucketCritical, 1))
	}
	st.running = append(st.running, slaFacts("zz-breached", domain.SLABucketCritical, 8))
	identity := &fakeProductOf{product: "prod-1"}
	svc := app.NewSLAService(st, identity, fixedClock{})

	checked, breached, err := svc.SweepBreaches(context.Background())
	if err != nil || checked != app.SLASweepBatch+4 || breached != 1 || st.pages != 2 || identity.asks != 1 {
		t.Fatalf("sweep: checked=%d breached=%d pages=%d asks=%d err=%v", checked, breached, st.pages, identity.asks, err)
	}
	ev, ok := st.notes[0].Event.(domain.SLABreachedEvent)
	if st.notes[0].EventType != app.EventSLABreached || !ok || ev.FindingID != "zz-breached" || ev.Bucket != "critical" || ev.CVE != "CVE-zz-breached" {
		t.Fatalf("event: %+v", st.notes[0])
	}
	if _, breached, _ = svc.SweepBreaches(context.Background()); breached != 0 {
		t.Fatalf("second sweep re-announced: %d", breached)
	}
}

// S1 at the service: the breach path's only writes are the breach log and its outbox note —
// the sweep holds no Repository, so it cannot touch a Finding, a Position or a proposal.
func TestSLAService_BreachWritesOnlyTheBreachLogS1(t *testing.T) {
	st := &fakeSLAStore{running: []app.SLAFacts{slaFacts("a", domain.SLABucketCritical, 30)}}
	repo := newRepo()
	f := findingWithPositions(t)
	repo.seed(f)
	before := repo.byID["fnd-1"]
	if _, n, err := app.NewSLAService(st, nil, fixedClock{}).SweepBreaches(context.Background()); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	after := repo.byID["fnd-1"]
	if after.Version() != before.Version() || after.Stage() != before.Stage() || len(after.Positions()) != len(before.Positions()) {
		t.Fatal("a Finding changed during the breach sweep")
	}
	if len(st.notes) != 1 || st.notes[0].EventType != app.EventSLABreached {
		t.Fatalf("writes: %+v", st.notes)
	}
}

func TestSLAService_SweepErrors(t *testing.T) {
	ctx := context.Background()
	if _, _, err := app.NewSLAService(&fakeSLAStore{policyErr: errors.New("x")}, nil, fixedClock{}).SweepBreaches(ctx); err == nil {
		t.Fatal("policy error swallowed")
	}
	if _, _, err := app.NewSLAService(&fakeSLAStore{runningErr: errors.New("x")}, nil, fixedClock{}).SweepBreaches(ctx); err == nil {
		t.Fatal("list error swallowed")
	}
	st := &fakeSLAStore{running: []app.SLAFacts{slaFacts("a", domain.SLABucketCritical, 30)}, recordErr: errors.New("x")}
	if _, _, err := app.NewSLAService(st, nil, fixedClock{}).SweepBreaches(ctx); err == nil {
		t.Fatal("record error swallowed")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	st = &fakeSLAStore{running: []app.SLAFacts{slaFacts("a", domain.SLABucketCritical, 30)}}
	if _, _, err := app.NewSLAService(st, nil, fixedClock{}).SweepBreaches(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestSLAService_RunEvery(t *testing.T) {
	st := &fakeSLAStore{running: []app.SLAFacts{slaFacts("a", domain.SLABucketCritical, 30)}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	reports := 0
	go func() {
		app.NewSLAService(st, nil, fixedClock{}).RunEvery(ctx, time.Millisecond, func(_, _ int, _ error) {
			reports++
			if reports == 2 {
				cancel()
			}
		})
		close(done)
	}()
	<-done
	if reports < 2 {
		t.Fatalf("reports = %d", reports)
	}
	// A nil reporter is allowed.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel2()
	app.NewSLAService(st, nil, fixedClock{}).RunEvery(ctx2, time.Millisecond, nil)
}

func TestReadService_PostureCarriesSLA(t *testing.T) {
	proj := fakeProjection{posture: []app.PostureEntry{{FindingID: "a", BaseScore: 95}, {FindingID: "b", BaseScore: 95}}}
	st := &fakeSLAStore{facts: []app.SLAFacts{slaFacts("a", domain.SLABucketHigh, 2)}}
	rs := app.NewReadService(newRepo(), proj, nil, 0).WithSLA(app.NewSLAService(st, nil, fixedClock{}))
	got, err := rs.ReleasePosture(context.Background(), "rel-1")
	if err != nil || got[0].SLA == nil || got[0].SLA.State != domain.SLAWithin || got[1].SLA != nil {
		t.Fatalf("posture sla: %+v %v", got, err)
	}
	// An unreadable SLA table leaves rows without a deadline and the posture still answers.
	st.factsErr = errors.New("db down")
	proj.posture = []app.PostureEntry{{FindingID: "a", BaseScore: 95}}
	rs = app.NewReadService(newRepo(), proj, nil, 0).WithSLA(app.NewSLAService(st, nil, fixedClock{}))
	got, err = rs.ReleasePosture(context.Background(), "rel-1")
	if err != nil || got[0].SLA != nil {
		t.Fatalf("best effort: %+v %v", got, err)
	}
}

package app_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// fakeRebuildPolicyStore keeps the policy in force and the history of every scope in memory,
// as the real store does: the version of a scope counts from its history.
type fakeRebuildPolicyStore struct {
	cur     map[string]app.RebuildPolicyRecord
	hist    map[string][]app.RebuildPolicyRecord // oldest first
	getErr  error
	getErrs map[string]error // per scope kind
	putErr  error
	histErr error
	delErr  error
	listErr error
}

func (f *fakeRebuildPolicyStore) count() int {
	n := 0
	for _, h := range f.hist {
		n += len(h)
	}
	return n
}

func (f *fakeRebuildPolicyStore) RebuildPolicy(_ context.Context, kind, id string) (app.RebuildPolicyRecord, bool, error) {
	if f.getErr != nil {
		return app.RebuildPolicyRecord{}, false, f.getErr
	}
	if err := f.getErrs[kind]; err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	rec, ok := f.cur[kind+"/"+id]
	return rec, ok, nil
}

func (f *fakeRebuildPolicyStore) append(rec app.RebuildPolicyRecord) app.RebuildPolicyRecord {
	if f.hist == nil {
		f.cur, f.hist = map[string]app.RebuildPolicyRecord{}, map[string][]app.RebuildPolicyRecord{}
	}
	key := rec.ScopeKind + "/" + rec.ScopeID
	rec.Version = len(f.hist[key]) + 1
	f.hist[key] = append(f.hist[key], rec)
	return rec
}

func (f *fakeRebuildPolicyStore) PutRebuildPolicy(_ context.Context, rec app.RebuildPolicyRecord) (app.RebuildPolicyRecord, error) {
	if f.putErr != nil {
		return app.RebuildPolicyRecord{}, f.putErr
	}
	rec = f.append(rec)
	f.cur[rec.ScopeKind+"/"+rec.ScopeID] = rec
	return rec, nil
}

func (f *fakeRebuildPolicyStore) RemoveRebuildPolicy(_ context.Context, kind, id string, at time.Time, by string) (app.RebuildPolicyRecord, bool, error) {
	if f.delErr != nil {
		return app.RebuildPolicyRecord{}, false, f.delErr
	}
	rec, ok := f.cur[kind+"/"+id]
	if !ok {
		return app.RebuildPolicyRecord{}, false, nil
	}
	delete(f.cur, kind+"/"+id)
	rec.UpdatedAt, rec.UpdatedBy, rec.Removed = at, by, true
	return f.append(rec), true, nil
}

func (f *fakeRebuildPolicyStore) RebuildPolicyHistory(_ context.Context, kind, id string) ([]app.RebuildPolicyRecord, error) {
	if f.histErr != nil {
		return nil, f.histErr
	}
	h := f.hist[kind+"/"+id]
	out := make([]app.RebuildPolicyRecord, 0, len(h))
	for i := len(h) - 1; i >= 0; i-- {
		out = append(out, h[i])
	}
	return out, nil
}

func (f *fakeRebuildPolicyStore) RebuildPolicies(context.Context) ([]app.RebuildPolicyRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []app.RebuildPolicyRecord
	for _, kind := range []string{app.RebuildScopeInstallation, app.RebuildScopeProduct, app.RebuildScopeRelease} {
		var group []app.RebuildPolicyRecord
		for _, rec := range f.cur {
			if rec.ScopeKind == kind {
				group = append(group, rec)
			}
		}
		sort.Slice(group, func(i, j int) bool { return group[i].ScopeID < group[j].ScopeID })
		out = append(out, group...)
	}
	return out, nil
}

type rebuildClock struct{ t time.Time }

func (c rebuildClock) Now() time.Time { return c.t }

func TestRebuildPolicyDefaultsWhenNothingStored(t *testing.T) {
	svc := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{})
	rec, err := svc.Installation(context.Background())
	if err != nil {
		t.Fatalf("Installation: %v", err)
	}
	if rec.Version != 0 || rec.ScopeKind != app.RebuildScopeInstallation || rec.ScopeID != "" ||
		rec.Policy != domain.DefaultRebuildPolicy() || !rec.UpdatedAt.IsZero() || rec.UpdatedBy != "" {
		t.Fatalf("nothing stored: got %+v, want the shipped default at version 0", rec)
	}
}

func TestRebuildPolicyPutThenRead(t *testing.T) {
	st := &fakeRebuildPolicyStore{}
	// A clock in another zone: the stored time must be UTC.
	at := time.Date(2026, 11, 27, 21, 40, 0, 0, time.FixedZone("ist", 19800))
	svc := app.NewRebuildPolicyService(st, rebuildClock{at})
	ctx := context.Background()

	p := domain.DefaultRebuildPolicy()
	p.Mode, p.SeverityFloor = domain.RebuildModeAuto, domain.SLABucketCritical
	rec, err := svc.PutInstallation(ctx, p, "  alice  ")
	if err != nil {
		t.Fatalf("PutInstallation: %v", err)
	}
	if rec.Version != 1 || rec.Policy != p || rec.UpdatedBy != "alice" || !rec.UpdatedAt.Equal(at) ||
		rec.UpdatedAt.Location() != time.UTC || rec.ScopeKind != app.RebuildScopeInstallation {
		t.Fatalf("stored record = %+v", rec)
	}

	p.Mode = domain.RebuildModeOff
	if rec, err = svc.PutInstallation(ctx, p, "bob"); err != nil || rec.Version != 2 {
		t.Fatalf("second put: rec=%+v err=%v, want version 2", rec, err)
	}
	got, err := svc.Installation(ctx)
	if err != nil || got.Version != 2 || got.Policy.Mode != domain.RebuildModeOff || got.UpdatedBy != "bob" {
		t.Fatalf("read back: %+v err=%v", got, err)
	}
	hist, err := svc.InstallationHistory(ctx)
	if err != nil || len(hist) != 2 || hist[0].Version != 2 || hist[1].Version != 1 || hist[1].UpdatedBy != "alice" {
		t.Fatalf("history = %+v err=%v, want versions 2 then 1", hist, err)
	}
}

func TestRebuildPolicyPutRefusals(t *testing.T) {
	st := &fakeRebuildPolicyStore{}
	svc := app.NewRebuildPolicyService(st, rebuildClock{})
	ctx := context.Background()

	if _, err := svc.PutInstallation(ctx, domain.DefaultRebuildPolicy(), "   "); !errors.Is(err, app.ErrRebuildPolicyActorRequired) {
		t.Fatalf("no actor: err=%v, want ErrRebuildPolicyActorRequired", err)
	}
	bad := domain.DefaultRebuildPolicy()
	bad.Mode = "always"
	if _, err := svc.PutInstallation(ctx, bad, "alice"); !errors.Is(err, app.ErrInvalidRebuildPolicy) {
		t.Fatalf("bad mode: err=%v, want ErrInvalidRebuildPolicy", err)
	}
	if st.count() != 0 {
		t.Fatalf("a refused change must store nothing, got %d versions", st.count())
	}
}

func TestRebuildPolicyStoreErrorsSurface(t *testing.T) {
	boom := errors.New("db down")
	ctx := context.Background()
	if _, err := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{getErr: boom}, rebuildClock{}).Installation(ctx); !errors.Is(err, boom) {
		t.Fatalf("read error: %v", err)
	}
	if _, err := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{putErr: boom}, rebuildClock{}).PutInstallation(ctx, domain.DefaultRebuildPolicy(), "alice"); !errors.Is(err, boom) {
		t.Fatalf("write error: %v", err)
	}
	if _, err := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{histErr: boom}, rebuildClock{}).InstallationHistory(ctx); !errors.Is(err, boom) {
		t.Fatalf("history error: %v", err)
	}
}

// The database keeps microseconds. The service cuts the time before storing, so the answer to
// a change and a later read carry the same time (found in the R1 VM check, 2026-11-28).
func TestRebuildPolicyPutCutsTimeToMicrosecond(t *testing.T) {
	at := time.Date(2026, 11, 28, 5, 49, 14, 755407026, time.UTC)
	svc := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{at})
	rec, err := svc.PutInstallation(context.Background(), domain.DefaultRebuildPolicy(), "alice")
	if err != nil || !rec.UpdatedAt.Equal(time.Date(2026, 11, 28, 5, 49, 14, 755407000, time.UTC)) {
		t.Fatalf("UpdatedAt = %v err = %v, want it cut to the microsecond", rec.UpdatedAt, err)
	}
}

// releaseOwner is the Registry seam: release -> product, or an error.
type releaseOwner struct {
	product map[string]string
	err     error
}

func (r releaseOwner) ProductAndProjectOfRelease(_ context.Context, releaseID string) (string, string, error) {
	return r.product[releaseID], "proj-1", r.err
}

func policyWith(mode domain.RebuildMode, floor string) domain.RebuildPolicy {
	p := domain.DefaultRebuildPolicy()
	p.Mode, p.SeverityFloor = mode, floor
	return p
}

func TestRebuildPolicyOverridePutReadRemove(t *testing.T) {
	st := &fakeRebuildPolicyStore{}
	at := time.Date(2026, 11, 28, 6, 0, 0, 123456789, time.UTC)
	svc := app.NewRebuildPolicyService(st, rebuildClock{at})
	ctx := context.Background()

	if _, found, err := svc.Override(ctx, domain.RebuildLevelProduct, "prod-1"); err != nil || found {
		t.Fatalf("no override yet: found=%v err=%v", found, err)
	}
	p := policyWith(domain.RebuildModeOff, domain.SLABucketLow)
	rec, err := svc.PutOverride(ctx, domain.RebuildLevelProduct, " prod-1 ", p, " alice ")
	if err != nil || rec.Version != 1 || rec.ScopeKind != app.RebuildScopeProduct || rec.ScopeID != "prod-1" ||
		rec.Policy != p || rec.UpdatedBy != "alice" || rec.UpdatedAt.Nanosecond() != 123456000 {
		t.Fatalf("put override = %+v err=%v", rec, err)
	}
	// A Release policy is its own scope with its own count.
	if rec, err = svc.PutOverride(ctx, domain.RebuildLevelRelease, "rel-1", p, "bob"); err != nil || rec.Version != 1 || rec.ScopeKind != app.RebuildScopeRelease {
		t.Fatalf("release override = %+v err=%v", rec, err)
	}
	got, found, err := svc.Override(ctx, domain.RebuildLevelProduct, "prod-1")
	if err != nil || !found || got.Policy != p {
		t.Fatalf("read override = %+v found=%v err=%v", got, found, err)
	}

	removed, err := svc.RemoveOverride(ctx, domain.RebuildLevelProduct, "prod-1", " carol ")
	if err != nil || !removed.Removed || removed.Version != 2 || removed.UpdatedBy != "carol" || removed.Policy != p ||
		removed.UpdatedAt.Nanosecond() != 123456000 {
		t.Fatalf("removal = %+v err=%v", removed, err)
	}
	if _, found, _ := svc.Override(ctx, domain.RebuildLevelProduct, "prod-1"); found {
		t.Fatal("a removed override must not be in force")
	}
	if _, err := svc.RemoveOverride(ctx, domain.RebuildLevelProduct, "prod-1", "carol"); !errors.Is(err, app.ErrRebuildPolicyNotFound) {
		t.Fatalf("second removal: err=%v, want ErrRebuildPolicyNotFound", err)
	}
	// The count goes on across the removal.
	if rec, err = svc.PutOverride(ctx, domain.RebuildLevelProduct, "prod-1", p, "alice"); err != nil || rec.Version != 3 {
		t.Fatalf("put after removal = %+v err=%v, want version 3", rec, err)
	}
	hist, err := svc.OverrideHistory(ctx, domain.RebuildLevelProduct, "prod-1")
	if err != nil || len(hist) != 3 || hist[0].Version != 3 || !hist[1].Removed || hist[2].Removed {
		t.Fatalf("history = %+v err=%v", hist, err)
	}
}

func TestRebuildPolicyOverrideRefusals(t *testing.T) {
	st := &fakeRebuildPolicyStore{}
	svc := app.NewRebuildPolicyService(st, rebuildClock{})
	ctx := context.Background()
	ok := domain.DefaultRebuildPolicy()

	for name, c := range map[string]struct {
		level domain.RebuildPolicyLevel
		id    string
	}{
		"installation is not an override": {domain.RebuildLevelInstallation, "x"},
		"no project level":                {"project", "x"},
		"blank id":                        {domain.RebuildLevelProduct, "  "},
	} {
		if _, _, err := svc.Override(ctx, c.level, c.id); !errors.Is(err, app.ErrRebuildPolicyScopeInvalid) {
			t.Errorf("%s: Override err=%v", name, err)
		}
		if _, err := svc.PutOverride(ctx, c.level, c.id, ok, "alice"); !errors.Is(err, app.ErrRebuildPolicyScopeInvalid) {
			t.Errorf("%s: PutOverride err=%v", name, err)
		}
		if _, err := svc.RemoveOverride(ctx, c.level, c.id, "alice"); !errors.Is(err, app.ErrRebuildPolicyScopeInvalid) {
			t.Errorf("%s: RemoveOverride err=%v", name, err)
		}
		if _, err := svc.OverrideHistory(ctx, c.level, c.id); !errors.Is(err, app.ErrRebuildPolicyScopeInvalid) {
			t.Errorf("%s: OverrideHistory err=%v", name, err)
		}
	}
	if _, err := svc.PutOverride(ctx, domain.RebuildLevelProduct, "prod-1", ok, " "); !errors.Is(err, app.ErrRebuildPolicyActorRequired) {
		t.Errorf("put without actor: %v", err)
	}
	if _, err := svc.RemoveOverride(ctx, domain.RebuildLevelProduct, "prod-1", " "); !errors.Is(err, app.ErrRebuildPolicyActorRequired) {
		t.Errorf("remove without actor: %v", err)
	}
	bad := ok
	bad.SeverityFloor = "severe"
	if _, err := svc.PutOverride(ctx, domain.RebuildLevelRelease, "rel-1", bad, "alice"); !errors.Is(err, app.ErrInvalidRebuildPolicy) {
		t.Errorf("invalid policy: %v", err)
	}
	if st.count() != 0 {
		t.Fatalf("a refused change stored %d versions", st.count())
	}
	boom := errors.New("db down")
	if _, err := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{delErr: boom}, rebuildClock{}).
		RemoveOverride(ctx, domain.RebuildLevelProduct, "prod-1", "alice"); !errors.Is(err, boom) {
		t.Errorf("remove store error: %v", err)
	}
}

func TestRebuildPolicyList(t *testing.T) {
	st := &fakeRebuildPolicyStore{}
	svc := app.NewRebuildPolicyService(st, rebuildClock{})
	ctx := context.Background()

	// Nothing stored: the page still shows the installation policy, the shipped default.
	recs, err := svc.List(ctx)
	if err != nil || len(recs) != 1 || recs[0].ScopeKind != app.RebuildScopeInstallation || recs[0].Version != 0 ||
		recs[0].Policy != domain.DefaultRebuildPolicy() {
		t.Fatalf("empty list = %+v err=%v", recs, err)
	}
	p := domain.DefaultRebuildPolicy()
	for _, c := range []struct {
		level domain.RebuildPolicyLevel
		id    string
	}{{domain.RebuildLevelRelease, "rel-1"}, {domain.RebuildLevelProduct, "prod-2"}, {domain.RebuildLevelProduct, "prod-1"}} {
		if _, err := svc.PutOverride(ctx, c.level, c.id, p, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	// Overrides but no stored installation policy: the default still leads.
	if recs, err = svc.List(ctx); err != nil || len(recs) != 4 || recs[0].Version != 0 || recs[1].ScopeID != "prod-1" ||
		recs[2].ScopeID != "prod-2" || recs[3].ScopeKind != app.RebuildScopeRelease {
		t.Fatalf("list = %+v err=%v", recs, err)
	}
	if _, err := svc.PutInstallation(ctx, p, "alice"); err != nil {
		t.Fatal(err)
	}
	if recs, err = svc.List(ctx); err != nil || len(recs) != 4 || recs[0].Version != 1 {
		t.Fatalf("list with stored installation = %+v err=%v", recs, err)
	}
	boom := errors.New("db down")
	if _, err := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{listErr: boom}, rebuildClock{}).List(ctx); !errors.Is(err, boom) {
		t.Fatalf("list error: %v", err)
	}
}

func TestRebuildPolicyInForce(t *testing.T) {
	st := &fakeRebuildPolicyStore{}
	owner := releaseOwner{product: map[string]string{"rel-1": "prod-1", "rel-2": "prod-1", "rel-3": "prod-2"}}
	svc := app.NewRebuildPolicyService(st, rebuildClock{}).WithIdentity(owner)
	ctx := context.Background()

	// Nothing stored: the shipped default, from the installation.
	got, err := svc.InForce(ctx, " rel-1 ")
	if err != nil || got.ReleaseID != "rel-1" || got.ProductID != "prod-1" || got.InForce.ScopeKind != app.RebuildScopeInstallation ||
		got.InForce.Version != 0 || got.ModeCeiling != domain.RebuildModeAsk || got.ModeSetBy != domain.RebuildModeSetByInstallation ||
		got.InstallationMode != domain.RebuildModeAsk {
		t.Fatalf("defaults in force = %+v err=%v", got, err)
	}

	if _, err := svc.PutInstallation(ctx, policyWith(domain.RebuildModeAuto, domain.SLABucketHigh), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutOverride(ctx, domain.RebuildLevelProduct, "prod-1", policyWith(domain.RebuildModeAsk, domain.SLABucketMedium), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutOverride(ctx, domain.RebuildLevelRelease, "rel-2", policyWith(domain.RebuildModeOff, domain.SLABucketLow), "alice"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		release, kind, floor string
		ceiling              domain.RebuildMode
		setBy                string
	}{
		{"rel-1", app.RebuildScopeProduct, domain.SLABucketMedium, domain.RebuildModeAsk, domain.RebuildModeSetByPolicy},
		{"rel-2", app.RebuildScopeRelease, domain.SLABucketLow, domain.RebuildModeOff, domain.RebuildModeSetByPolicy},
		{"rel-3", app.RebuildScopeInstallation, domain.SLABucketHigh, domain.RebuildModeAuto, domain.RebuildModeSetByInstallation},
	}
	for _, c := range cases {
		got, err := svc.InForce(ctx, c.release)
		if err != nil || got.InForce.ScopeKind != c.kind || got.InForce.Policy.SeverityFloor != c.floor ||
			got.ModeCeiling != c.ceiling || got.ModeSetBy != c.setBy || got.InstallationMode != domain.RebuildModeAuto {
			t.Errorf("%s: got %+v err=%v", c.release, got, err)
		}
	}
}

func TestRebuildPolicyInForceFailsClosed(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("db down")
	owner := releaseOwner{product: map[string]string{"rel-1": "prod-1"}}

	if _, err := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithIdentity(owner).InForce(ctx, " "); !errors.Is(err, app.ErrRebuildPolicyScopeInvalid) {
		t.Errorf("blank release: %v", err)
	}
	// No Registry seam, a Registry error and a blank product all read as "cannot tell".
	for name, svc := range map[string]*app.RebuildPolicyService{
		"no seam":       app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}),
		"registry down": app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithIdentity(releaseOwner{err: boom}),
		"blank product": app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithIdentity(releaseOwner{}),
	} {
		if _, err := svc.InForce(ctx, "rel-1"); !errors.Is(err, app.ErrRebuildPolicyIdentityUnavailable) {
			t.Errorf("%s: err=%v, want ErrRebuildPolicyIdentityUnavailable", name, err)
		}
	}
	// A store error at any of the three reads surfaces; nothing is guessed.
	for _, kind := range []string{app.RebuildScopeInstallation, app.RebuildScopeProduct, app.RebuildScopeRelease} {
		st := &fakeRebuildPolicyStore{getErrs: map[string]error{kind: boom}}
		if _, err := app.NewRebuildPolicyService(st, rebuildClock{}).WithIdentity(owner).InForce(ctx, "rel-1"); !errors.Is(err, boom) {
			t.Errorf("%s read error: %v", kind, err)
		}
	}
}

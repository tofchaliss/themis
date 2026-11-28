package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// fakeRebuildPolicyStore keeps the versions of one scope in memory, as the real store does.
type fakeRebuildPolicyStore struct {
	versions []app.RebuildPolicyRecord
	getErr   error
	putErr   error
	histErr  error
}

func (f *fakeRebuildPolicyStore) RebuildPolicy(context.Context, string, string) (app.RebuildPolicyRecord, bool, error) {
	if f.getErr != nil {
		return app.RebuildPolicyRecord{}, false, f.getErr
	}
	if len(f.versions) == 0 {
		return app.RebuildPolicyRecord{}, false, nil
	}
	return f.versions[len(f.versions)-1], true, nil
}

func (f *fakeRebuildPolicyStore) PutRebuildPolicy(_ context.Context, rec app.RebuildPolicyRecord) (app.RebuildPolicyRecord, error) {
	if f.putErr != nil {
		return app.RebuildPolicyRecord{}, f.putErr
	}
	rec.Version = len(f.versions) + 1
	f.versions = append(f.versions, rec)
	return rec, nil
}

func (f *fakeRebuildPolicyStore) RebuildPolicyHistory(context.Context, string, string) ([]app.RebuildPolicyRecord, error) {
	if f.histErr != nil {
		return nil, f.histErr
	}
	out := make([]app.RebuildPolicyRecord, 0, len(f.versions))
	for i := len(f.versions) - 1; i >= 0; i-- {
		out = append(out, f.versions[i])
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
	if len(st.versions) != 0 {
		t.Fatalf("a refused change must store nothing, got %d versions", len(st.versions))
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

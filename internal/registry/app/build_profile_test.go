package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

type memProfiles struct {
	recs      map[string][]domain.BuildProfileRecord // newest first
	appendErr error
	histErr   error
	histErrOn string
}

func newMemProfiles() *memProfiles {
	return &memProfiles{recs: map[string][]domain.BuildProfileRecord{}}
}

func (m *memProfiles) AppendBuildProfile(_ context.Context, r domain.BuildProfileRecord) (domain.BuildProfileRecord, error) {
	if m.appendErr != nil {
		return domain.BuildProfileRecord{}, m.appendErr
	}
	k := string(r.Level) + "/" + r.EntityID
	r.Revision = len(m.recs[k]) + 1
	m.recs[k] = append([]domain.BuildProfileRecord{r}, m.recs[k]...)
	return r, nil
}

func (m *memProfiles) BuildProfileHistory(_ context.Context, level domain.BuildProfileLevel, id string) ([]domain.BuildProfileRecord, error) {
	if m.histErr != nil && (m.histErrOn == "" || m.histErrOn == string(level)) {
		return nil, m.histErr
	}
	return m.recs[string(level)+"/"+id], nil
}

// D10: a Project profile serves its Releases; a Release's own replaces it as a whole; removing
// the Release's own gives the Project's back; every change is a revision with its actor.
func TestBuildProfile_SetResolveRemove(t *testing.T) {
	ctx := context.Background()
	_, svc, _, proj, rel := estateFixture(t)
	svc.WithBuildProfiles(newMemProfiles(), reqClock)

	if got, err := svc.ResolvedBuildProfile(ctx, rel); err != nil || got.Found || got.ReleaseID != rel || got.ProjectID != proj {
		t.Fatalf("nothing stored: %+v %v", got, err)
	}
	p1, err := svc.SetBuildProfile(ctx, domain.TagProject, proj, []byte(`{"job": "team/build"}`), "alice", "ci-key")
	if err != nil || p1.Revision != 1 || string(p1.Profile) != `{"job":"team/build"}` || p1.Actor != "alice" || p1.Via != "ci-key" || !p1.At.Equal(reqClock()) {
		t.Fatalf("project profile: %+v %v", p1, err)
	}
	got, err := svc.ResolvedBuildProfile(ctx, rel)
	if err != nil || !got.Found || got.Record.Level != domain.TagProject || got.Record.Revision != 1 {
		t.Fatalf("inherited: %+v %v", got, err)
	}
	if _, err := svc.SetBuildProfile(ctx, domain.TagRelease, rel, []byte(`{"job":"team/special"}`), "bob", ""); err != nil {
		t.Fatal(err)
	}
	got, err = svc.ResolvedBuildProfile(ctx, rel)
	if err != nil || got.Record.Level != domain.TagRelease || string(got.Record.Profile) != `{"job":"team/special"}` {
		t.Fatalf("own: %+v %v", got, err)
	}
	gone, err := svc.RemoveBuildProfile(ctx, domain.TagRelease, rel, "bob", "")
	if err != nil || !gone.Removed || gone.Revision != 2 {
		t.Fatalf("removal: %+v %v", gone, err)
	}
	got, err = svc.ResolvedBuildProfile(ctx, rel)
	if err != nil || got.Record.Level != domain.TagProject {
		t.Fatalf("after removal: %+v %v", got, err)
	}
	// Removing what is not there (never set, or already removed) is refused.
	if _, err := svc.RemoveBuildProfile(ctx, domain.TagRelease, rel, "bob", ""); !errors.Is(err, app.ErrNoBuildProfile) {
		t.Errorf("second removal: %v", err)
	}
	hist, err := svc.BuildProfileHistory(ctx, domain.TagRelease, rel)
	if err != nil || len(hist) != 2 || !hist[0].Removed || hist[1].Revision != 1 {
		t.Errorf("history: %+v %v", hist, err)
	}
}

func TestBuildProfile_Refusals(t *testing.T) {
	ctx := context.Background()
	repo, svc, prod, proj, rel := estateFixture(t)
	ok := []byte(`{"job":"a"}`)

	if _, err := svc.SetBuildProfile(ctx, domain.TagProject, proj, ok, "a", ""); !errors.Is(err, app.ErrBuildProfilesUnavailable) {
		t.Errorf("unwired set: %v", err)
	}
	if _, err := svc.RemoveBuildProfile(ctx, domain.TagProject, proj, "a", ""); !errors.Is(err, app.ErrBuildProfilesUnavailable) {
		t.Errorf("unwired remove: %v", err)
	}
	if _, err := svc.BuildProfileHistory(ctx, domain.TagProject, proj); !errors.Is(err, app.ErrBuildProfilesUnavailable) {
		t.Errorf("unwired history: %v", err)
	}
	if _, err := svc.ResolvedBuildProfile(ctx, rel); !errors.Is(err, app.ErrBuildProfilesUnavailable) {
		t.Errorf("unwired resolve: %v", err)
	}

	store := newMemProfiles()
	svc.WithBuildProfiles(store, reqClock)
	if _, err := svc.SetBuildProfile(ctx, domain.TagProject, proj, []byte(`{"password":"x"}`), "a", ""); !errors.Is(err, domain.ErrInvalidBuildProfile) {
		t.Errorf("secret key: %v", err)
	}
	if _, err := svc.SetBuildProfile(ctx, domain.TagProduct, prod, ok, "a", ""); !errors.Is(err, domain.ErrInvalidBuildProfile) {
		t.Errorf("product level: %v", err)
	}
	if _, err := svc.RemoveBuildProfile(ctx, domain.TagProject, proj, " ", ""); !errors.Is(err, domain.ErrInvalidBuildProfile) {
		t.Errorf("removal without actor: %v", err)
	}
	if _, err := svc.BuildProfileHistory(ctx, domain.TagProduct, prod); !errors.Is(err, domain.ErrInvalidBuildProfile) {
		t.Errorf("history at product level: %v", err)
	}
	if _, err := svc.SetBuildProfile(ctx, domain.TagProject, "missing", ok, "a", ""); !errors.Is(err, app.ErrUnknownProject) {
		t.Errorf("unknown project: %v", err)
	}
	if _, err := svc.RemoveBuildProfile(ctx, domain.TagRelease, "missing", "a", ""); !errors.Is(err, app.ErrUnknownRelease) {
		t.Errorf("unknown release remove: %v", err)
	}
	if _, err := svc.BuildProfileHistory(ctx, domain.TagRelease, "missing"); !errors.Is(err, app.ErrUnknownRelease) {
		t.Errorf("unknown release history: %v", err)
	}
	if _, err := svc.ResolvedBuildProfile(ctx, "missing"); !errors.Is(err, app.ErrUnknownRelease) {
		t.Errorf("unknown release resolve: %v", err)
	}
	if _, err := svc.RemoveBuildProfile(ctx, domain.TagProject, proj, "a", ""); !errors.Is(err, app.ErrNoBuildProfile) {
		t.Errorf("nothing to remove: %v", err)
	}

	store.appendErr = errors.New("db")
	if _, err := svc.SetBuildProfile(ctx, domain.TagProject, proj, ok, "a", ""); err == nil {
		t.Error("append error")
	}
	store.appendErr = nil
	store.histErr, store.histErrOn = errors.New("db"), string(domain.TagProject)
	if _, err := svc.RemoveBuildProfile(ctx, domain.TagProject, proj, "a", ""); err == nil {
		t.Error("history error on remove")
	}
	if _, err := svc.ResolvedBuildProfile(ctx, rel); err == nil {
		t.Error("project history error on resolve")
	}
	store.histErrOn = string(domain.TagRelease)
	if _, err := svc.ResolvedBuildProfile(ctx, rel); err == nil {
		t.Error("release history error on resolve")
	}
	store.histErr = nil
	repo.errGetRelease = errors.New("db")
	if _, err := svc.ResolvedBuildProfile(ctx, rel); err == nil {
		t.Error("release read error")
	}
}

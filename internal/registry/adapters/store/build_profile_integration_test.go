//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/domain"
)

// TestBuildProfilesAppendOnly: each change of one entity is its next revision, a removal is a
// row with no profile, the stored text is exactly what was written, and the history reads
// newest first (EDR-REBUILD-01 D10, D16).
func TestBuildProfilesAppendOnly(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))
	_, proj, rel := seed(t, s)
	at := time.Unix(1_700_000_000, 0).UTC()

	first, err := domain.NewBuildProfileRecord(domain.TagProject, string(proj), []byte(`{"z": 1, "a": {"job": "team/build"}}`), "alice", "ci", at)
	must(t, err)
	got1, err := s.AppendBuildProfile(ctx, first)
	must(t, err)
	second, err := domain.NewBuildProfileRecord(domain.TagProject, string(proj), []byte(`{"job":"team/other"}`), "bob", "", at.Add(time.Hour))
	must(t, err)
	got2, err := s.AppendBuildProfile(ctx, second)
	must(t, err)
	gone, err := domain.NewBuildProfileRemoval(domain.TagProject, string(proj), "bob", "", at.Add(2*time.Hour))
	must(t, err)
	got3, err := s.AppendBuildProfile(ctx, gone)
	must(t, err)
	if got1.Revision != 1 || got2.Revision != 2 || got3.Revision != 3 {
		t.Fatalf("revisions = %d %d %d", got1.Revision, got2.Revision, got3.Revision)
	}
	// Another entity counts on its own.
	own, err := domain.NewBuildProfileRecord(domain.TagRelease, string(rel), []byte(`{}`), "alice", "", at)
	must(t, err)
	if r, err := s.AppendBuildProfile(ctx, own); err != nil || r.Revision != 1 {
		t.Fatalf("release revision = %+v %v", r, err)
	}

	hist, err := s.BuildProfileHistory(ctx, domain.TagProject, string(proj))
	must(t, err)
	if len(hist) != 3 || !hist[0].Removed || hist[0].Profile != nil || hist[0].Revision != 3 || hist[0].SHA256() != "" ||
		hist[1].Actor != "bob" || !hist[1].At.Equal(second.At) ||
		string(hist[2].Profile) != `{"z":1,"a":{"job":"team/build"}}` || hist[2].Via != "ci" || hist[2].SHA256() != first.SHA256() ||
		hist[2].Level != domain.TagProject || hist[2].EntityID != string(proj) {
		t.Fatalf("history: %+v", hist)
	}
	if none, err := s.BuildProfileHistory(ctx, domain.TagRelease, "rel-none"); err != nil || len(none) != 0 {
		t.Errorf("unknown entity: %+v %v", none, err)
	}
}

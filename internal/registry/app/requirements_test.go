package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

type memReqs struct {
	recs      map[string][]domain.RequirementRecord // newest first
	appendErr error
	histErr   error
	histErrOn string
}

func (m *memReqs) AppendRequirement(_ context.Context, r domain.RequirementRecord) error {
	if m.appendErr != nil {
		return m.appendErr
	}
	k := string(r.Level) + "/" + r.EntityID
	m.recs[k] = append([]domain.RequirementRecord{r}, m.recs[k]...)
	return nil
}

func (m *memReqs) RequirementHistory(_ context.Context, level domain.RequirementLevel, id string) ([]domain.RequirementRecord, error) {
	if m.histErr != nil && (m.histErrOn == "" || m.histErrOn == string(level)) {
		return nil, m.histErr
	}
	return m.recs[string(level)+"/"+id], nil
}

func reqClock() time.Time { return time.Unix(1_700_000_000, 0) }

func TestRequirements_SetHistoryAndResolve(t *testing.T) {
	ctx := context.Background()
	_, svc, prod, proj, rel := estateFixture(t)
	store := &memReqs{recs: map[string][]domain.RequirementRecord{}}
	svc.WithRequirements(store, reqClock)

	if _, err := svc.SetRequirements(ctx, domain.TagProduct, prod, app.RequirementChange{CR: "L", IR: "M", Reason: "baseline", Actor: "ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetRequirements(ctx, domain.TagRelease, rel, app.RequirementChange{CR: "H", Reason: "holds card data", Actor: "ops", Via: "ci"}); err != nil {
		t.Fatal(err)
	}
	rec, err := svc.SetRequirements(ctx, domain.TagRelease, rel, app.RequirementChange{CR: "H", AR: "H", Reason: "uptime", Actor: "ops"})
	if err != nil || rec.Requirements.AR != "H" {
		t.Fatal(rec, err)
	}
	hist, err := svc.RequirementHistory(ctx, domain.TagRelease, rel)
	if err != nil || len(hist) != 2 || hist[0].Reason != "uptime" {
		t.Fatalf("history: %+v %v", hist, err)
	}
	rr, err := svc.ResolvedRequirements(ctx, rel)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Resolved.CR != (domain.ResolvedRequirement{Value: "H", Level: domain.TagRelease}) ||
		rr.Resolved.IR != (domain.ResolvedRequirement{Value: "M", Level: domain.TagProduct}) ||
		rr.Resolved.AR != (domain.ResolvedRequirement{Value: "H", Level: domain.TagRelease}) ||
		rr.Project != nil || rr.Product == nil || rr.Release.Reason != "uptime" {
		t.Errorf("resolved: %+v", rr)
	}
	_ = proj
}

func TestRequirements_Refusals(t *testing.T) {
	ctx := context.Background()
	repo, svc, prod, _, rel := estateFixture(t)
	if _, err := svc.SetRequirements(ctx, domain.TagProduct, prod, app.RequirementChange{}); !errors.Is(err, app.ErrRequirementsUnavailable) {
		t.Errorf("unwired set: %v", err)
	}
	if _, err := svc.RequirementHistory(ctx, domain.TagProduct, prod); !errors.Is(err, app.ErrRequirementsUnavailable) {
		t.Errorf("unwired history: %v", err)
	}
	if _, err := svc.ResolvedRequirements(ctx, rel); !errors.Is(err, app.ErrRequirementsUnavailable) {
		t.Errorf("unwired resolve: %v", err)
	}
	store := &memReqs{recs: map[string][]domain.RequirementRecord{}}
	svc.WithRequirements(store, reqClock)
	ok := app.RequirementChange{CR: "H", Reason: "r", Actor: "a"}
	if _, err := svc.SetRequirements(ctx, domain.TagProduct, prod, app.RequirementChange{CR: "H"}); !errors.Is(err, domain.ErrInvalidRequirement) {
		t.Errorf("no reason: %v", err)
	}
	if _, err := svc.SetRequirements(ctx, domain.TagProduct, "missing", ok); !errors.Is(err, app.ErrUnknownProduct) {
		t.Errorf("unknown product: %v", err)
	}
	if _, err := svc.RequirementHistory(ctx, domain.TagRelease, "missing"); !errors.Is(err, app.ErrUnknownRelease) {
		t.Errorf("unknown release: %v", err)
	}
	if _, err := svc.ResolvedRequirements(ctx, "missing"); !errors.Is(err, app.ErrUnknownRelease) {
		t.Errorf("unknown release resolve: %v", err)
	}
	store.appendErr = errors.New("db")
	if _, err := svc.SetRequirements(ctx, domain.TagProduct, prod, ok); err == nil {
		t.Error("append error")
	}
	store.histErr = errors.New("db")
	if _, err := svc.ResolvedRequirements(ctx, rel); err == nil {
		t.Error("history error")
	}
	store.histErr = nil
	repo.errGetRelease = errors.New("db")
	if _, err := svc.ResolvedRequirements(ctx, rel); err == nil {
		t.Error("release read error")
	}
	repo.errGetRelease = nil
	repo.projectObjs = map[string]domain.Project{}
	if _, err := svc.ResolvedRequirements(ctx, rel); err == nil {
		t.Error("project read error")
	}
}

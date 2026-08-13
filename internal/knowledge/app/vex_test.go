package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeDocReader struct {
	raw  []byte
	kind string
	err  error
}

func (f fakeDocReader) GetDocument(context.Context, string) ([]byte, string, error) {
	return f.raw, f.kind, f.err
}

type fakeVEXParser struct {
	stmts []app.VEXStatement
	err   error
}

func (f fakeVEXParser) Parse([]byte) ([]app.VEXStatement, error) { return f.stmts, f.err }

func vexService(repo app.Repository, docs app.DocumentReader, parser app.VEXParser) *app.VEXApplicabilityService {
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	return app.NewVEXApplicabilityService(docs, parser, fold, fixedClock{})
}

func TestVEXApplicability_FoldsAndSkips(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	parser := fakeVEXParser{stmts: []app.VEXStatement{
		{CVE: "CVE-2024-1", Package: "pkg:pypi/urllib3", Status: "not_affected", Justification: "vulnerable_code_not_present"},
		{CVE: "not a cve", Package: "p", Status: "affected"},     // skipped: unparseable CVE id
		{CVE: "CVE-2024-2", Package: "", Status: "not_affected"}, // skipped: empty package → invalid proposal
	}}
	if err := vexService(repo, fakeDocReader{raw: []byte(`{}`), kind: "vex"}, parser).Apply(ctx, "ev-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	f, found, _ := repo.GetByCVE(ctx, "CVE-2024-1")
	if !found {
		t.Fatal("expected a card for CVE-2024-1")
	}
	if apps := f.View().Applicabilities; len(apps) != 1 || apps[0].Status != "not_affected" || apps[0].Package != "pkg:pypi/urllib3" {
		t.Errorf("applicabilities = %+v", apps)
	}
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-2"); found {
		t.Error("an empty-package statement must not create a card")
	}
}

func TestVEXApplicability_Errors(t *testing.T) {
	ctx := context.Background()
	if err := vexService(newRepo(), fakeDocReader{err: errors.New("down")}, fakeVEXParser{}).Apply(ctx, "ev-1"); err == nil {
		t.Error("doc read error must propagate")
	}
	if err := vexService(newRepo(), fakeDocReader{raw: []byte(`x`)}, fakeVEXParser{err: errors.New("bad")}).Apply(ctx, "ev-1"); err == nil {
		t.Error("parse error must propagate")
	}
	// A fold failure (repo GetByCVE errors) propagates.
	badRepo := newRepo()
	badRepo.getErr = errors.New("db down")
	parser := fakeVEXParser{stmts: []app.VEXStatement{{CVE: "CVE-2024-1", Package: "p", Status: "affected"}}}
	if err := vexService(badRepo, fakeDocReader{raw: []byte(`{}`)}, parser).Apply(ctx, "ev-1"); err == nil {
		t.Error("fold error must propagate")
	}
}

func TestCoordinator_DispatchesByKind(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	parser := fakeVEXParser{stmts: []app.VEXStatement{{CVE: "CVE-2024-9", Package: "pkg:x", Status: "not_affected"}}}
	coord := app.NewCoordinator(nil, vexService(repo, fakeDocReader{raw: []byte(`{}`), kind: "vex"}, parser))

	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{EvidenceID: "ev-1", Kind: "vex"}); err != nil {
		t.Fatalf("on vex: %v", err)
	}
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-9"); !found {
		t.Error("a VEX evidence must fold a card")
	}
	// An unknown kind is ignored (and does not touch the nil correlate service). A
	// scanner-report on a coordinator with NO scanner service wired is likewise a no-op —
	// the dispatch is guarded, not assumed.
	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{Kind: "attestation"}); err != nil {
		t.Errorf("unknown kinds must be ignored: %v", err)
	}
	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{Kind: "scanner-report"}); err != nil {
		t.Errorf("scanner-report without a wired scanner service must be a no-op: %v", err)
	}
}

// TestCoordinator_VEXReadErrorPropagates proves a failure in the VEX READ phase (the document
// fetch, now run outside the inbox transaction) surfaces from OnEvidenceRegistered so the event
// is retried rather than silently applied against a transaction.
func TestCoordinator_VEXReadErrorPropagates(t *testing.T) {
	ctx := context.Background()
	coord := app.NewCoordinator(nil, vexService(newRepo(), fakeDocReader{err: errors.New("evidence down")}, fakeVEXParser{}))
	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{EvidenceID: "ev-1", Kind: "vex"}); err == nil {
		t.Error("a read-phase (document) error must propagate from OnEvidenceRegistered")
	}
}

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// --- fakes ---------------------------------------------------------------------------

type fakePosture struct {
	rows []app.RollupPostureRow
	err  error
}

func (f fakePosture) ReleasePosture(context.Context, string) ([]app.RollupPostureRow, error) {
	return f.rows, f.err
}

type fakeIdentity struct {
	ref domain.RollupProductRef
	err error
}

func (f fakeIdentity) ReleaseIdentity(context.Context, string) (domain.RollupProductRef, error) {
	return f.ref, f.err
}

type fakeRollupStore struct {
	current      domain.RollupPublication
	hasCurrent   bool
	currentErr   error
	saved        []domain.RollupPublication
	savedPrior   []*domain.RollupPublication
	saveErrs     []error // consumed per call; empty → nil
	listed       []domain.RollupPublication
	got          domain.RollupPublication
	getErr       error
	listErr      error
	currentCalls int
}

func (f *fakeRollupStore) CurrentRollup(context.Context, string, string, string) (domain.RollupPublication, bool, error) {
	f.currentCalls++
	return f.current, f.hasCurrent, f.currentErr
}

func (f *fakeRollupStore) SaveRollup(_ context.Context, pub domain.RollupPublication, prior *domain.RollupPublication, _ int) error {
	f.saved = append(f.saved, pub)
	f.savedPrior = append(f.savedPrior, prior)
	if len(f.saveErrs) > 0 {
		err := f.saveErrs[0]
		f.saveErrs = f.saveErrs[1:]
		return err
	}
	return nil
}

func (f *fakeRollupStore) GetRollup(context.Context, domain.RollupPublicationID) (domain.RollupPublication, error) {
	return f.got, f.getErr
}

func (f *fakeRollupStore) ListRollups(context.Context, string) ([]domain.RollupPublication, error) {
	return f.listed, f.listErr
}

type fakeRollupSerializers struct {
	payload []byte
	err     error
	art     domain.RollupArtifact // last artifact seen, for assertions
}

func (f *fakeRollupSerializers) RenderRollup(_ string, art domain.RollupArtifact) ([]byte, error) {
	f.art = art
	return f.payload, f.err
}

type rollupIDs struct{ n int }

func (g *rollupIDs) NewID() string { g.n++; return "rp-" + string(rune('0'+g.n)) }

type rollupClock struct{}

func (rollupClock) Now() time.Time { return time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC) }

var mrfIdentity = fakeIdentity{ref: domain.RollupProductRef{
	Product: "MRF", Project: "cdmrf-oamp", Version: "20.1.0.0-118", ReleaseID: "rel-1"}}

// The measured MRF posture: a decided finding, and the mixed finding whose cleared copy must
// annotate while its open copy is the subcomponent (D13.1).
func mrfRows() []app.RollupPostureRow {
	return []app.RollupPostureRow{
		{FindingID: "f1", FaultlineID: "fl1", CVE: "CVE-2020-1747", HasPosition: true,
			Stance: "not_affected", PositionVersion: 2, PositionRationale: "not reachable",
			Components: []app.RollupComponentRow{{PURL: "pkg:rpm/rocky/python3-pyyaml@3.12", ClaimClass: "carrier"}}},
		{FindingID: "f2", FaultlineID: "fl2", CVE: "CVE-2025-47273",
			Components: []app.RollupComponentRow{
				{PURL: "pkg:pypi/setuptools@39.2.0", ClaimClass: "carrier", VerdictState: "cleared_vendor_fix",
					VerdictGrade: "inferred", VerdictReason: "matched to platform-python-setuptools"},
				{PURL: "pkg:pypi/setuptools@70.3.0", ClaimClass: "carrier"},
			}},
		{FindingID: "f3", FaultlineID: "fl3", CVE: "CVE-2026-48962",
			Components: []app.RollupComponentRow{
				{PURL: "pkg:rpm/rocky/perl-Carp@1.42", ClaimClass: "scope"},
				{PURL: "pkg:rpm/rocky/perl-Errno@1.28", ClaimClass: "scope"},
			}},
	}
}

func rollupSvc(posture fakePosture, identity fakeIdentity, st *fakeRollupStore, sz *fakeRollupSerializers) *app.RollupService {
	return app.NewRollupService(posture, identity, st, sz, &rollupIDs{}, rollupClock{})
}

// --- tests ---------------------------------------------------------------------------

func TestCreateRollup(t *testing.T) {
	st := &fakeRollupStore{}
	sz := &fakeRollupSerializers{payload: []byte(`{"doc":true}`)}
	id, err := rollupSvc(fakePosture{rows: mrfRows()}, mrfIdentity, st, sz).CreateRollup(context.Background(), "rel-1", "openvex", "customer")
	if err != nil || id == "" {
		t.Fatalf("create: id=%q err=%v", id, err)
	}
	if len(st.saved) != 1 || st.savedPrior[0] != nil {
		t.Fatalf("saved=%d prior=%v, want one save with no prior", len(st.saved), st.savedPrior)
	}
	pub := st.saved[0]
	if pub.ReleaseID() != "rel-1" || pub.Format() != "openvex" || pub.Audience() != "customer" || pub.Statements() != 3 {
		t.Errorf("publication = %+v", pub)
	}

	// The artifact handed to the serializer carries the D13.1 shape: the cleared copy as an
	// annotation, the open copy as the sole subcomponent, the scope-only finding aggregated.
	byCVE := map[string]domain.RollupStatement{}
	for _, s := range sz.art.Statements {
		byCVE[s.CVE] = s
	}
	mixed := byCVE["CVE-2025-47273"]
	if mixed.Status != "under_investigation" ||
		len(mixed.Subcomponents) != 1 || mixed.Subcomponents[0] != "pkg:pypi/setuptools@70.3.0" ||
		len(mixed.Annotations) != 1 || !strings.Contains(mixed.Annotations[0], "cleared by vendor fix (inferred)") {
		t.Errorf("mixed statement = %+v", mixed)
	}
	decided := byCVE["CVE-2020-1747"]
	if decided.Status != "not_affected" || decided.Rationale != "not reachable" {
		t.Errorf("decided statement = %+v", decided)
	}
	scope := byCVE["CVE-2026-48962"]
	if len(scope.Subcomponents) != 0 || len(scope.Annotations) != 1 ||
		!strings.Contains(scope.Annotations[0], "2 component(s) listed via a module-stream rebuild set") {
		t.Errorf("scope-only statement = %+v", scope)
	}
}

func TestCreateRollup_SupersedesAndRetries(t *testing.T) {
	art, _ := domain.MaterializeRollup(mrfIdentity.ref, rollupClock{}.Now(), []domain.RollupEntry{{FindingID: "f1", CVE: "CVE-1"}}, 0)
	prior, _ := domain.NewRollupPublication("rp-old", art, "openvex", "customer", []byte(`{}`), "", rollupClock{}.Now())
	st := &fakeRollupStore{current: prior, hasCurrent: true, saveErrs: []error{app.ErrConcurrent}}
	sz := &fakeRollupSerializers{payload: []byte(`{}`)}

	id, err := rollupSvc(fakePosture{rows: mrfRows()}, mrfIdentity, st, sz).CreateRollup(context.Background(), "rel-1", "openvex", "customer")
	if err != nil || id == "" {
		t.Fatalf("create: %v", err)
	}
	// First attempt lost the race (ErrConcurrent), the second succeeded — two saves, both
	// superseding the prior.
	if len(st.saved) != 2 || st.savedPrior[1] == nil || st.saved[1].Supersedes() != "rp-old" {
		t.Errorf("saves=%d, second=%+v", len(st.saved), st.saved[len(st.saved)-1])
	}

	// Retry budget exhaustion surfaces ErrConcurrent.
	exhausted := &fakeRollupStore{current: prior, hasCurrent: true,
		saveErrs: []error{app.ErrConcurrent, app.ErrConcurrent, app.ErrConcurrent, app.ErrConcurrent, app.ErrConcurrent}}
	// A fresh prior per attempt (Supersede mutates); the fake returns the same value copy each
	// call, which is what the service reloads.
	if _, err := rollupSvc(fakePosture{rows: mrfRows()}, mrfIdentity, exhausted, &fakeRollupSerializers{payload: []byte(`{}`)}).
		CreateRollup(context.Background(), "rel-1", "openvex", ""); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("exhausted retries err = %v, want ErrConcurrent", err)
	}
}

func TestCreateRollup_Errors(t *testing.T) {
	rows := fakePosture{rows: mrfRows()}
	for name, run := range map[string]func() error{
		"posture read fails": func() error {
			_, e := rollupSvc(fakePosture{err: errors.New("gov down")}, mrfIdentity, &fakeRollupStore{}, &fakeRollupSerializers{payload: []byte(`{}`)}).
				CreateRollup(context.Background(), "rel-1", "openvex", "")
			return e
		},
		"identity fails closed (D13.4)": func() error {
			_, e := rollupSvc(rows, fakeIdentity{err: app.ErrIncompleteIdentity}, &fakeRollupStore{}, &fakeRollupSerializers{payload: []byte(`{}`)}).
				CreateRollup(context.Background(), "rel-1", "openvex", "")
			return e
		},
		"serializer fails": func() error {
			_, e := rollupSvc(rows, mrfIdentity, &fakeRollupStore{}, &fakeRollupSerializers{err: errors.New("no such format")}).
				CreateRollup(context.Background(), "rel-1", "nope", "")
			return e
		},
		"current read fails": func() error {
			_, e := rollupSvc(rows, mrfIdentity, &fakeRollupStore{currentErr: errors.New("db down")}, &fakeRollupSerializers{payload: []byte(`{}`)}).
				CreateRollup(context.Background(), "rel-1", "openvex", "")
			return e
		},
		"empty payload refused": func() error {
			_, e := rollupSvc(rows, mrfIdentity, &fakeRollupStore{}, &fakeRollupSerializers{payload: nil}).
				CreateRollup(context.Background(), "rel-1", "openvex", "")
			return e
		},
		"save fails hard": func() error {
			_, e := rollupSvc(rows, mrfIdentity, &fakeRollupStore{saveErrs: []error{errors.New("disk full")}}, &fakeRollupSerializers{payload: []byte(`{}`)}).
				CreateRollup(context.Background(), "rel-1", "openvex", "")
			return e
		},
	} {
		if run() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A posture row claiming a decision with a nonsense stance fails materialization — the
	// projection is trusted but still validated (garbage in must not become a document).
	bad := fakePosture{rows: []app.RollupPostureRow{{FindingID: "f1", CVE: "CVE-1", HasPosition: true, Stance: "nonsense"}}}
	if _, err := rollupSvc(bad, mrfIdentity, &fakeRollupStore{}, &fakeRollupSerializers{payload: []byte(`{}`)}).
		CreateRollup(context.Background(), "rel-1", "openvex", ""); err == nil {
		t.Error("invalid posture stance: expected an error")
	}
	// A prior that is ALREADY superseded (the chain raced past us entirely) fails the
	// Supersede call itself — surfaced, not retried blindly.
	art, _ := domain.MaterializeRollup(mrfIdentity.ref, rollupClock{}.Now(), []domain.RollupEntry{{FindingID: "f1", CVE: "CVE-1"}}, 0)
	stalePrior, _ := domain.NewRollupPublication("rp-old", art, "openvex", "", []byte(`{}`), "", rollupClock{}.Now())
	_ = stalePrior.Supersede("rp-mid")
	if _, err := rollupSvc(rows, mrfIdentity, &fakeRollupStore{current: stalePrior, hasCurrent: true}, &fakeRollupSerializers{payload: []byte(`{}`)}).
		CreateRollup(context.Background(), "rel-1", "openvex", ""); !errors.Is(err, domain.ErrAlreadySuperseded) {
		t.Errorf("already-superseded prior err = %v", err)
	}

	// The identity error keeps its D13.4 identity for the transport mapping.
	_, err := rollupSvc(rows, fakeIdentity{err: app.ErrIncompleteIdentity}, &fakeRollupStore{}, &fakeRollupSerializers{payload: []byte(`{}`)}).
		CreateRollup(context.Background(), "rel-1", "openvex", "")
	if !errors.Is(err, app.ErrIncompleteIdentity) {
		t.Errorf("identity err = %v, want ErrIncompleteIdentity preserved", err)
	}
}

func TestPreviewRollup(t *testing.T) {
	sz := &fakeRollupSerializers{payload: []byte(`{"preview":true}`)}
	st := &fakeRollupStore{}
	got, err := rollupSvc(fakePosture{rows: mrfRows()}, mrfIdentity, st, sz).PreviewRollup(context.Background(), "rel-1", "openvex")
	if err != nil || string(got) != `{"preview":true}` {
		t.Fatalf("preview = %q err=%v", got, err)
	}
	if len(st.saved) != 0 || st.currentCalls != 0 {
		t.Error("preview must record nothing and consult no store")
	}
	if _, err := rollupSvc(fakePosture{err: errors.New("down")}, mrfIdentity, st, sz).PreviewRollup(context.Background(), "rel-1", "openvex"); err == nil {
		t.Error("preview posture error must surface")
	}
}

func TestRollupStatus(t *testing.T) {
	// No rollup yet.
	got, err := rollupSvc(fakePosture{rows: mrfRows()}, mrfIdentity, &fakeRollupStore{}, &fakeRollupSerializers{}).
		Status(context.Background(), "rel-1", "openvex", "")
	if err != nil || got.Found || got.Summary != "no rollup published" {
		t.Fatalf("no-rollup status = %+v err=%v", got, err)
	}

	// A current rollup whose recorded inputs match the live posture: current, not stale.
	rows := mrfRows()
	entriesArt := func(rs []app.RollupPostureRow) domain.RollupArtifact {
		st := &fakeRollupStore{}
		sz := &fakeRollupSerializers{payload: []byte(`{}`)}
		if _, err := rollupSvc(fakePosture{rows: rs}, mrfIdentity, st, sz).CreateRollup(context.Background(), "rel-1", "openvex", ""); err != nil {
			t.Fatal(err)
		}
		return sz.art
	}
	pub, _ := domain.NewRollupPublication("rp-1", entriesArt(rows), "openvex", "", []byte(`{}`), "", rollupClock{}.Now())
	current := &fakeRollupStore{current: pub, hasCurrent: true}
	got, err = rollupSvc(fakePosture{rows: rows}, mrfIdentity, current, &fakeRollupSerializers{}).Status(context.Background(), "rel-1", "openvex", "")
	if err != nil || !got.Found || got.Stale || got.Summary != "current" || got.PublicationID != "rp-1" || got.Statements != 3 || got.AsOf == "" {
		t.Fatalf("current status = %+v err=%v", got, err)
	}

	// The live posture moved: a decision changed and a finding appeared — exact drift, named.
	moved := append([]app.RollupPostureRow{}, rows...)
	moved[0].PositionVersion = 3
	moved = append(moved, app.RollupPostureRow{FindingID: "f4", CVE: "CVE-2026-9"})
	got, err = rollupSvc(fakePosture{rows: moved}, mrfIdentity, current, &fakeRollupSerializers{}).Status(context.Background(), "rel-1", "openvex", "")
	if err != nil || !got.Stale || got.Drift.ChangedDecisions != 1 || got.Drift.NewFindings != 1 {
		t.Fatalf("stale status = %+v err=%v", got, err)
	}
	if !strings.Contains(got.Summary, "STALE") {
		t.Errorf("summary = %q", got.Summary)
	}

	// Errors surface.
	if _, err := rollupSvc(fakePosture{rows: rows}, mrfIdentity, &fakeRollupStore{currentErr: errors.New("db")}, &fakeRollupSerializers{}).
		Status(context.Background(), "rel-1", "openvex", ""); err == nil {
		t.Error("store error must surface")
	}
	if _, err := rollupSvc(fakePosture{err: errors.New("gov")}, mrfIdentity, current, &fakeRollupSerializers{}).
		Status(context.Background(), "rel-1", "openvex", ""); err == nil {
		t.Error("posture error must surface")
	}
}

func TestRollupPassthroughReads(t *testing.T) {
	art, _ := domain.MaterializeRollup(mrfIdentity.ref, rollupClock{}.Now(), []domain.RollupEntry{{FindingID: "f1", CVE: "CVE-1"}}, 0)
	pub, _ := domain.NewRollupPublication("rp-9", art, "openvex", "", []byte(`{}`), "", rollupClock{}.Now())
	st := &fakeRollupStore{got: pub, listed: []domain.RollupPublication{pub}}
	s := rollupSvc(fakePosture{}, mrfIdentity, st, &fakeRollupSerializers{})
	if got, err := s.GetRollup(context.Background(), "rp-9"); err != nil || got.ID() != "rp-9" {
		t.Errorf("get = %v %v", got.ID(), err)
	}
	if got, err := s.ListRollups(context.Background(), "rel-1"); err != nil || len(got) != 1 {
		t.Errorf("list = %d %v", len(got), err)
	}
}

package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

var (
	rollupAt      = time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC)
	rollupProduct = domain.RollupProductRef{Product: "MRF", Project: "cdmrf-oamp", Version: "20.1.0.0-118", ReleaseID: "rel-1"}
)

// The measured MRF shape (D13.1/D13.3): a decided finding speaks its stance; the undecided
// mixed finding is under_investigation carrying the clearance as an annotation and only the
// OPEN copy as a subcomponent; entries sort deterministically; the input set records every
// finding with its position version and annotation fingerprint.
func TestMaterializeRollup(t *testing.T) {
	entries := []domain.RollupEntry{
		{FindingID: "f2", FaultlineID: "fl2", CVE: "CVE-2025-47273",
			OpenComponents: []string{"pkg:pypi/setuptools@70.3.0"},
			Annotations:    []string{"setuptools@39.2.0 cleared: vendor fix present via platform-python-setuptools"}},
		{FindingID: "f1", FaultlineID: "fl1", CVE: "CVE-2020-1747", HasPosition: true,
			Stance: domain.StanceNotAffected, PositionVersion: 2, Rationale: "not reachable in our config",
			OpenComponents: []string{"pkg:rpm/rocky/python3-pyyaml@3.12-12.el8"}},
	}
	art, err := domain.MaterializeRollup(rollupProduct, rollupAt, entries, 3)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if len(art.Statements) != 2 || len(art.InputSet) != 2 {
		t.Fatalf("statements=%d inputs=%d, want 2/2", len(art.Statements), len(art.InputSet))
	}
	// Sorted by CVE: 2020 before 2025 — order is part of determinism.
	if art.Statements[0].CVE != "CVE-2020-1747" || art.Statements[1].CVE != "CVE-2025-47273" {
		t.Errorf("order = %s, %s", art.Statements[0].CVE, art.Statements[1].CVE)
	}
	decided, undecided := art.Statements[0], art.Statements[1]
	if decided.Status != "not_affected" || decided.Rationale != "not reachable in our config" {
		t.Errorf("decided = %+v, want the Position speaking via the D3 mapping", decided)
	}
	if undecided.Status != "under_investigation" || undecided.Rationale != "" {
		t.Errorf("undecided = %+v, want under_investigation with no rationale", undecided)
	}
	if len(undecided.Annotations) != 1 || !strings.Contains(undecided.Annotations[0], "cleared") {
		t.Errorf("annotations = %v, want the clearance carried as context", undecided.Annotations)
	}
	if len(undecided.Subcomponents) != 1 || undecided.Subcomponents[0] != "pkg:pypi/setuptools@70.3.0" {
		t.Errorf("subcomponents = %v, want the OPEN copy only", undecided.Subcomponents)
	}
	if art.WithdrawnExcluded != 3 || !art.AsOf.Equal(rollupAt) {
		t.Errorf("meta = withdrawn %d asOf %v", art.WithdrawnExcluded, art.AsOf)
	}
	// Input set: position versions recorded (0 for undecided), fingerprints non-empty.
	for _, in := range art.InputSet {
		if in.FindingID == "" || in.Fingerprint == "" {
			t.Errorf("input record = %+v", in)
		}
	}
	if art.Product.PURL() != "pkg:generic/MRF/cdmrf-oamp@20.1.0.0-118" {
		t.Errorf("purl = %q", art.Product.PURL())
	}
}

func TestMaterializeRollup_Validation(t *testing.T) {
	ok := []domain.RollupEntry{{FindingID: "f1", CVE: "CVE-1"}}
	for name, tc := range map[string]struct {
		product domain.RollupProductRef
		asOf    time.Time
		entries []domain.RollupEntry
	}{
		"incomplete product (fail-closed D13.4)": {domain.RollupProductRef{Product: "MRF", ReleaseID: "rel-1"}, rollupAt, ok},
		"zero as-of":                             {rollupProduct, time.Time{}, ok},
		"entry without identity":                 {rollupProduct, rollupAt, []domain.RollupEntry{{CVE: "CVE-1"}}},
		"decided entry with invalid stance":      {rollupProduct, rollupAt, []domain.RollupEntry{{FindingID: "f1", CVE: "CVE-1", HasPosition: true, Stance: "nonsense"}}},
	} {
		if _, err := domain.MaterializeRollup(tc.product, tc.asOf, tc.entries, 0); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// Determinism: two runs, identical artifacts — including the same-CVE tiebreak on
	// FindingID (two releases' findings of one CVE never wobble in order).
	entries := []domain.RollupEntry{{FindingID: "f1", CVE: "CVE-2", Annotations: []string{"b", "a"}}, {FindingID: "f0", CVE: "CVE-2"}}
	a1, err1 := domain.MaterializeRollup(rollupProduct, rollupAt, entries, 0)
	a2, err2 := domain.MaterializeRollup(rollupProduct, rollupAt, entries, 0)
	if err1 != nil || err2 != nil {
		t.Fatalf("errs: %v %v", err1, err2)
	}
	if a1.InputSet[0] != a2.InputSet[0] || a1.InputSet[1] != a2.InputSet[1] {
		t.Errorf("input sets differ across runs: %+v vs %+v", a1.InputSet, a2.InputSet)
	}
}

// D13.2's three drift kinds, counted and ranked — plus the no-drift case that proves a
// republish would change nothing.
func TestComputeRollupDrift(t *testing.T) {
	base := []domain.RollupEntry{
		{FindingID: "f1", CVE: "CVE-1", HasPosition: true, Stance: domain.StanceNotAffected, PositionVersion: 1},
		{FindingID: "f2", CVE: "CVE-2", Annotations: []string{"cleared: x"}},
	}
	art, err := domain.MaterializeRollup(rollupProduct, rollupAt, base, 0)
	if err != nil {
		t.Fatal(err)
	}

	if d := domain.ComputeRollupDrift(art.InputSet, base); d.Stale() || d.String() != "current" {
		t.Errorf("no drift expected, got %+v (%s)", d, d)
	}

	// A decision moved, a finding appeared, one vanished, one annotation changed.
	current := []domain.RollupEntry{
		{FindingID: "f1", CVE: "CVE-1", HasPosition: true, Stance: domain.StanceAffected, PositionVersion: 2},
		{FindingID: "f2", CVE: "CVE-2", Annotations: []string{"cleared: y"}},
		{FindingID: "f3", CVE: "CVE-3"},
	}
	d := domain.ComputeRollupDrift(art.InputSet, current)
	if d.ChangedDecisions != 1 || d.NewFindings != 1 || d.AnnotationOnly != 1 || d.RemovedFindings != 0 {
		t.Errorf("drift = %+v", d)
	}
	if !d.Stale() || !strings.Contains(d.String(), "1 changed decision(s)") || !strings.Contains(d.String(), "1 annotation-only") {
		t.Errorf("summary = %q", d.String())
	}
	// Removal counts too.
	d2 := domain.ComputeRollupDrift(art.InputSet, current[:1])
	if d2.RemovedFindings != 1 {
		t.Errorf("removed = %d, want 1", d2.RemovedFindings)
	}
	if !strings.Contains(domain.ComputeRollupDrift(art.InputSet, nil).String(), "removed finding(s)") {
		t.Errorf("all-removed summary = %q", domain.ComputeRollupDrift(art.InputSet, nil).String())
	}
	if !strings.Contains(d.String(), "new finding(s)") {
		t.Errorf("summary missing new findings: %q", d.String())
	}
}

func TestRollupPublicationLifecycle(t *testing.T) {
	art, err := domain.MaterializeRollup(rollupProduct, rollupAt,
		[]domain.RollupEntry{{FindingID: "f1", CVE: "CVE-1"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := domain.NewRollupPublication("rp-1", art, "openvex", "customer", []byte(`{}`), "", rollupAt)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if pub.ID() != "rp-1" || pub.ReleaseID() != "rel-1" || pub.Format() != "openvex" ||
		pub.Audience() != "customer" || pub.Statements() != 1 || pub.WithdrawnExcluded() != 1 ||
		pub.ProductPURL() != rollupProduct.PURL() || pub.Version() != 1 || pub.Supersedes() != "" ||
		len(pub.InputSet()) != 1 || string(pub.Payload()) != `{}` || !pub.AsOf().Equal(rollupAt) ||
		pub.CreatedAt().IsZero() || pub.SupersededBy() != "" {
		t.Errorf("publication = %+v", pub)
	}
	if err := pub.Supersede("rp-2"); err != nil || pub.SupersededBy() != "rp-2" || pub.Version() != 2 {
		t.Errorf("supersede: %v %+v", err, pub)
	}
	if err := pub.Supersede("rp-3"); err == nil {
		t.Error("second supersede must fail — links are set once")
	}

	// Constructor validation.
	for name, run := range map[string]func() error{
		"empty id":      func() error { _, e := domain.NewRollupPublication("", art, "openvex", "", []byte(`{}`), "", rollupAt); return e },
		"empty format":  func() error { _, e := domain.NewRollupPublication("rp", art, "", "", []byte(`{}`), "", rollupAt); return e },
		"empty payload": func() error { _, e := domain.NewRollupPublication("rp", art, "openvex", "", nil, "", rollupAt); return e },
		"incomplete product": func() error {
			_, e := domain.NewRollupPublication("rp", domain.RollupArtifact{AsOf: rollupAt}, "openvex", "", []byte(`{}`), "", rollupAt)
			return e
		},
	} {
		if run() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	// Round-trip via Reconstitute (the store's path).
	back := domain.ReconstituteRollupPublication(pub.ID(), pub.ReleaseID(), pub.ProductPURL(), pub.Format(),
		pub.Audience(), pub.Payload(), pub.InputSet(), pub.AsOf(), pub.Statements(), pub.WithdrawnExcluded(),
		pub.Supersedes(), pub.SupersededBy(), pub.Version(), pub.CreatedAt())
	if back.ID() != pub.ID() || back.Version() != 2 || back.SupersededBy() != "rp-2" {
		t.Errorf("reconstitute = %+v", back)
	}
}

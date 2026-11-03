package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// --- fakes -----------------------------------------------------------------------------

var errWatchMissing = errors.New("watch not found")

type memWatches struct {
	byID    map[string]domain.Watch
	order   []string
	saveErr error
	listErr error
	saves   int
}

func newMemWatches() *memWatches { return &memWatches{byID: map[string]domain.Watch{}} }

func (m *memWatches) SaveWatch(_ context.Context, w domain.Watch) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saves++
	if _, ok := m.byID[w.ID()]; !ok {
		m.order = append(m.order, w.ID())
	}
	m.byID[w.ID()] = w
	return nil
}

func (m *memWatches) GetWatch(_ context.Context, id string) (domain.Watch, error) {
	w, ok := m.byID[id]
	if !ok {
		return domain.Watch{}, errWatchMissing
	}
	return w, nil
}

func (m *memWatches) ListWatches(context.Context) ([]domain.Watch, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	out := make([]domain.Watch, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		if w, ok := m.byID[m.order[i]]; ok {
			out = append(out, w)
		}
	}
	return out, nil
}

func (m *memWatches) DeleteWatch(_ context.Context, id string) error {
	if _, ok := m.byID[id]; !ok {
		return errWatchMissing
	}
	delete(m.byID, id)
	return nil
}

// cardsByCVE is the Knowledge resolution seam: cards by CVE, advisories to CVE sets.
type cardsByCVE struct {
	cards      map[string]app.FaultlineKnowledge
	advisories map[string][]string
	cveErr     map[string]error
	advErr     map[string]error
}

func (k *cardsByCVE) FaultlineByCVE(_ context.Context, cve string) (app.FaultlineKnowledge, bool, error) {
	if err := k.cveErr[cve]; err != nil {
		return app.FaultlineKnowledge{}, false, err
	}
	c, ok := k.cards[cve]
	return c, ok, nil
}

func (k *cardsByCVE) FaultlinesByAdvisory(_ context.Context, adv string) ([]app.FaultlineKnowledge, error) {
	if err := k.advErr[adv]; err != nil {
		return nil, err
	}
	var out []app.FaultlineKnowledge
	for _, cve := range k.advisories[adv] {
		out = append(out, k.cards[cve])
	}
	return out, nil
}

type latestEvidence struct {
	by   map[string]app.EvidenceRef
	fail map[string]bool
}

func (e latestEvidence) LatestEvidence(_ context.Context, rel string) (app.EvidenceRef, bool, error) {
	if e.fail[rel] {
		return app.EvidenceRef{}, false, errors.New("evidence down")
	}
	ev, ok := e.by[rel]
	return ev, ok, nil
}

// --- fixtures --------------------------------------------------------------------------

func watchFinding(t *testing.T, id, rel, fl, cve string, comps ...domain.MatchedComponent) domain.Finding {
	t.Helper()
	f := identified(t, id, rel, fl, cve)
	for _, c := range comps {
		if _, err := f.AbsorbComponent(c); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func decidedAs(t *testing.T, f domain.Finding, stance domain.Stance) domain.Finding {
	t.Helper()
	p, err := domain.NewGovernanceProposal("p1", human, stance, "x", fixedClock{}.Now(), value.TrustAsserted)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatal(err)
	}
	terms := domain.AcceptanceTerms{}
	if stance == domain.StanceAcceptedRisk {
		terms.Owner = "bob"
	}
	if _, err := f.AcceptProposalWith("p1", human, fixedClock{}.Now(), terms); err != nil {
		t.Fatal(err)
	}
	return f
}

func rowFor(rows []app.WatchRow, rel, cve string) (app.WatchRow, bool) {
	for _, r := range rows {
		if r.ReleaseID == rel && r.CVE == cve {
			return r, true
		}
	}
	return app.WatchRow{}, false
}

// --- tests ------------------------------------------------------------------------------

// Create / list / get / add / delete: the list is the record, the rejected tokens are reported,
// a blank name or a text with nothing recognised stores nothing.
func TestWatchService_Lifecycle(t *testing.T) {
	store := newMemWatches()
	svc := app.NewWatchService(store, newRepo(), nil, &seqIDs{}, fixedClock{})
	ctx := context.Background()

	if _, rejected, err := svc.Create(ctx, "", "alice", "CVE-2026-0001", false); !errors.Is(err, domain.ErrWatchNameRequired) || rejected != nil {
		t.Errorf("blank name: %v / %v", err, rejected)
	}
	if _, rejected, err := svc.Create(ctx, "wave", "alice", "foo bar", false); !errors.Is(err, domain.ErrWatchEmpty) || len(rejected) != 2 {
		t.Errorf("nothing recognised: %v / %v", err, rejected)
	}
	if store.saves != 0 {
		t.Fatal("a refused watch was saved")
	}
	w, rejected, err := svc.Create(ctx, "wave", "alice", "CVE-2026-0001, rhsa-2026:0001 junk", true)
	if err != nil {
		t.Fatal(err)
	}
	if w.ID() == "" || !w.Notify() || len(w.Identifiers()) != 2 || len(rejected) != 1 || rejected[0] != "JUNK" {
		t.Errorf("created = %+v rejected %v", w, rejected)
	}
	store.saveErr = errors.New("disk full")
	if _, _, err := svc.Create(ctx, "w2", "alice", "CVE-2026-0002", false); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("save failure: %v", err)
	}
	store.saveErr = nil
	w2, _, err := svc.Create(ctx, "w2", "alice", "CVE-2026-0002", false)
	if err != nil {
		t.Fatal(err)
	}

	list, err := svc.List(ctx)
	if err != nil || len(list) != 2 || list[0].Name() != "w2" {
		t.Errorf("list = %+v err %v", list, err)
	}
	if got, err := svc.Get(ctx, w.ID()); err != nil || got.Name() != "wave" {
		t.Errorf("get = %+v err %v", got, err)
	}
	if _, err := svc.Get(ctx, "ghost"); !errors.Is(err, errWatchMissing) {
		t.Errorf("get ghost: %v", err)
	}

	// Add: append-only, de-duplicated, rejected reported, no save when nothing is new.
	saves := store.saves
	got, added, rejected, err := svc.AddIdentifiers(ctx, w.ID(), "CVE-2026-0001 CVE-2026-0009 nope")
	if err != nil || added != 1 || len(got.Identifiers()) != 3 || len(rejected) != 1 || store.saves != saves+1 {
		t.Errorf("add = %+v added %d rejected %v err %v saves %d", got, added, rejected, err, store.saves)
	}
	if _, added, _, err := svc.AddIdentifiers(ctx, w.ID(), "CVE-2026-0009"); err != nil || added != 0 || store.saves != saves+1 {
		t.Errorf("re-add = %d err %v saves %d", added, err, store.saves)
	}
	if _, _, _, err := svc.AddIdentifiers(ctx, "ghost", "CVE-2026-0009"); !errors.Is(err, errWatchMissing) {
		t.Errorf("add to ghost: %v", err)
	}
	store.saveErr = errors.New("disk full")
	if _, _, _, err := svc.AddIdentifiers(ctx, w.ID(), "CVE-2026-0010"); err == nil {
		t.Error("add with a failing save returned nothing")
	}
	store.saveErr = nil

	if err := svc.Delete(ctx, w2.ID()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, w2.ID()); !errors.Is(err, errWatchMissing) {
		t.Errorf("delete twice: %v", err)
	}
	if list, _ := svc.List(ctx); len(list) != 1 {
		t.Errorf("after delete = %d", len(list))
	}
}

// The table (D2): every (release, CVE) of the estate slice the Watch touches, with the state
// from the human's answer first, then the machine's; a release without a Finding for a CVE
// matches no component; an advisory resolves through the cards; an unknown identifier is a row
// that says so; names and last proof come from the optional seams; the resolution is recorded.
func TestWatchService_Status(t *testing.T) {
	repo := newRepo()
	open := func(purl, name string) domain.MatchedComponent {
		return domain.MatchedComponent{PURL: purl, Name: name, Version: "1.el8", Ecosystem: "rpm", ClaimClass: "carrier"}
	}
	cleared := func(purl, name string) domain.MatchedComponent {
		c := open(purl, name)
		c.VerdictState = "cleared_vendor_fix"
		return c
	}
	// rel-a: CVE-1 open with a fix for its package; CVE-2 open, fix for another package only.
	repo.seed(watchFinding(t, "a1", "rel-a", "fl-1", "CVE-2026-0001", open("pkg:rpm/redhat/kernel@1.el8", "kernel")))
	repo.seed(watchFinding(t, "a2", "rel-a", "fl-2", "CVE-2026-0002", open("pkg:rpm/redhat/curl@1.el8", "curl")))
	// rel-b: CVE-1 cleared; CVE-2 accepted risk; CVE-3 decided not affected.
	repo.seed(watchFinding(t, "b1", "rel-b", "fl-1", "CVE-2026-0001", cleared("pkg:rpm/redhat/kernel@2.el8", "kernel")))
	repo.seed(decidedAs(t, watchFinding(t, "b2", "rel-b", "fl-2", "CVE-2026-0002", open("pkg:rpm/redhat/curl@1.el8", "curl")), domain.StanceAcceptedRisk))
	repo.seed(decidedAs(t, watchFinding(t, "b3", "rel-b", "fl-3", "CVE-2026-0003", open("pkg:rpm/redhat/perl@1.el8", "perl")), domain.StanceNotAffected))

	kn := &cardsByCVE{
		cards: map[string]app.FaultlineKnowledge{
			"CVE-2026-0001": {FaultlineID: "fl-1", CVE: "CVE-2026-0001", Fixes: []app.FixedVersion{{Package: "kernel", Version: "0:3.el8", Ecosystem: "rpm"}}},
			"CVE-2026-0002": {FaultlineID: "fl-2", CVE: "CVE-2026-0002", Fixes: []app.FixedVersion{{Package: "openssl", Version: "1:1.1.1k.el8"}}},
			"CVE-2026-0003": {FaultlineID: "fl-3", CVE: "CVE-2026-0003"},
			"CVE-2026-0004": {FaultlineID: "fl-4", CVE: "cve-2026-0004"},
			"":              {FaultlineID: "fl-blank"},
		},
		advisories: map[string][]string{"RHSA-2026:0001": {"CVE-2026-0001", "", "CVE-2026-0003"}},
	}
	owners := &ownersByRelease{
		owners: map[string][2]string{"rel-a": {"P1", "A"}, "rel-b": {"P1", "B"}},
		names:  map[string][3]string{"rel-a": {"Product One", "alpha", "1.0.0-7"}, "rel-b": {"Product One", "beta", "1.0.0-7"}},
		fail:   map[string]bool{"rel-b": true},
	}
	ev := latestEvidence{
		by:   map[string]app.EvidenceRef{"rel-a": {ID: "ev-1", Kind: "scanner-report", FiledAt: fixedClock{}.Now().Add(-time.Hour)}},
		fail: map[string]bool{"rel-b": true},
	}
	store := newMemWatches()
	svc := app.NewWatchService(store, repo, kn, &seqIDs{}, fixedClock{}).WithOwners(owners).WithEvidence(ev)
	ctx := context.Background()
	w, _, err := svc.Create(ctx, "wave", "alice", "RHSA-2026:0001 CVE-2026-0002 CVE-2026-0004 CVE-2026-0009 RHBA-2026:9999", false)
	if err != nil {
		t.Fatal(err)
	}

	st, err := svc.Status(ctx, w.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !st.GeneratedAt.Equal(fixedClock{}.Now()) {
		t.Errorf("generated_at = %v", st.GeneratedAt)
	}
	// Identifiers: the advisory resolved to two CVEs, the carded CVEs to themselves, the
	// uncarded CVE and the unseen advisory to nothing.
	if len(st.Identifiers) != 5 {
		t.Fatalf("identifiers = %+v", st.Identifiers)
	}
	if is := st.Identifiers[0]; is.Kind != "advisory" || !is.Resolved || len(is.CVEs) != 2 {
		t.Errorf("advisory = %+v", is)
	}
	if is := st.Identifiers[2]; is.Kind != "cve" || !is.Resolved || len(is.CVEs) != 1 || is.CVEs[0] != "CVE-2026-0004" {
		t.Errorf("uppercased card cve = %+v", is)
	}
	if is := st.Identifiers[3]; is.Resolved || is.Kind != "cve" {
		t.Errorf("uncarded cve = %+v", is)
	}
	if is := st.Identifiers[4]; is.Resolved || is.Kind != "advisory" {
		t.Errorf("unseen advisory = %+v", is)
	}

	// Rows: 2 releases × 4 carded CVEs + 2 unknown = 10.
	if len(st.Rows) != 10 {
		t.Fatalf("rows = %d: %+v", len(st.Rows), st.Rows)
	}
	want := map[[2]string]domain.WatchState{
		{"rel-a", "CVE-2026-0001"}: domain.WatchOpenFixAvailable,
		{"rel-a", "CVE-2026-0002"}: domain.WatchOpenNoFix,
		{"rel-a", "CVE-2026-0003"}: domain.WatchNotAffected,
		{"rel-a", "CVE-2026-0004"}: domain.WatchNotAffected,
		{"rel-b", "CVE-2026-0001"}: domain.WatchFixed,
		{"rel-b", "CVE-2026-0002"}: domain.WatchAccepted,
		{"rel-b", "CVE-2026-0003"}: domain.WatchNotAffected,
		{"rel-b", "CVE-2026-0004"}: domain.WatchNotAffected,
		{"", "CVE-2026-0009"}:      domain.WatchUnknown,
		{"", "RHBA-2026:9999"}:     domain.WatchUnknown,
	}
	for k, state := range want {
		r, ok := rowFor(st.Rows, k[0], k[1])
		if !ok || r.State != state {
			t.Errorf("row %v = %+v (found %v), want %s", k, r, ok, state)
		}
	}
	a1, _ := rowFor(st.Rows, "rel-a", "CVE-2026-0001")
	if a1.FindingID != "a1" || a1.FaultlineID != "fl-1" || a1.ProductName != "Product One" || a1.ProjectName != "alpha" || a1.Version != "1.0.0-7" ||
		a1.ProductID != "P1" || a1.ProjectID != "A" || len(a1.Packages) != 1 || a1.Packages[0] != "kernel" || len(a1.Fixes) != 1 || a1.Fixes[0] != "0:3.el8" ||
		a1.LastEvidenceKind != "scanner-report" || a1.LastEvidenceAt.IsZero() || a1.Stance != "" {
		t.Errorf("a1 row = %+v", a1)
	}
	b2, _ := rowFor(st.Rows, "rel-b", "CVE-2026-0002")
	if b2.Stance != "accepted_risk" || b2.ProductName != "" || b2.ProjectID != "" || b2.LastEvidenceKind != "" || len(b2.Packages) != 1 {
		t.Errorf("b2 row (owners and evidence down) = %+v", b2)
	}
	a3, _ := rowFor(st.Rows, "rel-a", "CVE-2026-0003")
	if a3.FindingID != "" || a3.FaultlineID != "fl-3" || a3.ProjectName != "alpha" {
		t.Errorf("no-finding row = %+v", a3)
	}
	// Order: by product / project name (rel-b's are blank, Registry failed for it, so it sorts
	// first), CVEs within a release; unknown rows last.
	if st.Rows[0].ReleaseID != "rel-b" || st.Rows[0].CVE != "CVE-2026-0001" || st.Rows[4].ReleaseID != "rel-a" || st.Rows[8].ReleaseID != "" || st.Rows[9].ReleaseID != "" {
		t.Errorf("order = %+v", st.Rows)
	}
	if st.Counts[domain.WatchNotAffected] != 4 || st.Counts[domain.WatchUnknown] != 2 || st.Counts[domain.WatchOpenFixAvailable] != 1 {
		t.Errorf("counts = %v", st.Counts)
	}
	// The resolution is recorded on the stored Watch.
	stored, _ := store.GetWatch(ctx, w.ID())
	if r := stored.ResolvedCVEs(); len(r) != 4 || r[0] != "CVE-2026-0001" || !stored.ResolvedAt().Equal(fixedClock{}.Now()) {
		t.Errorf("recorded resolution = %v at %v", r, stored.ResolvedAt())
	}
	if len(st.Watch.ResolvedCVEs()) != 4 {
		t.Error("status does not carry the recorded resolution")
	}
}

// Nothing in the estate: a carded CVE with no Finding anywhere is one row that says nothing
// matches; without the optional seams the rows carry ids only.
func TestWatchService_Status_EmptyEstate(t *testing.T) {
	kn := &cardsByCVE{cards: map[string]app.FaultlineKnowledge{"CVE-2026-0001": {FaultlineID: "fl-1", CVE: "CVE-2026-0001"}}}
	store := newMemWatches()
	svc := app.NewWatchService(store, newRepo(), kn, &seqIDs{}, fixedClock{})
	w, _, err := svc.Create(context.Background(), "w", "alice", "CVE-2026-0001", false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := svc.Status(context.Background(), w.ID())
	if err != nil || len(st.Rows) != 1 || st.Rows[0].State != domain.WatchNotAffected || st.Rows[0].ReleaseID != "" || st.Rows[0].FaultlineID != "fl-1" {
		t.Errorf("rows = %+v err %v", st.Rows, err)
	}
}

// Failures: an unknown Watch, no Knowledge seam, a Knowledge outage on a CVE or an advisory, a
// repository outage, and a failing resolution record are errors — never an empty table.
func TestWatchService_Status_Failures(t *testing.T) {
	ctx := context.Background()
	store := newMemWatches()
	noKn := app.NewWatchService(store, newRepo(), nil, &seqIDs{}, fixedClock{})
	if _, err := noKn.Status(ctx, "ghost"); !errors.Is(err, errWatchMissing) {
		t.Errorf("ghost: %v", err)
	}
	w, _, _ := noKn.Create(ctx, "w", "alice", "CVE-2026-0001 RHSA-2026:0001", false)
	if _, err := noKn.Status(ctx, w.ID()); !errors.Is(err, app.ErrWatchUnresolvable) {
		t.Errorf("no seam: %v", err)
	}

	boom := errors.New("knowledge down")
	kn := &cardsByCVE{
		cards:      map[string]app.FaultlineKnowledge{"CVE-2026-0001": {FaultlineID: "fl-1", CVE: "CVE-2026-0001"}},
		advisories: map[string][]string{"RHSA-2026:0001": {"CVE-2026-0001"}},
		cveErr:     map[string]error{"CVE-2026-0001": boom},
	}
	repo := newRepo()
	repo.seed(watchFinding(t, "a1", "rel-a", "fl-1", "CVE-2026-0001", comp("pkg:rpm/redhat/kernel@1")))
	svc := app.NewWatchService(store, repo, kn, &seqIDs{}, fixedClock{})
	if _, err := svc.Status(ctx, w.ID()); !errors.Is(err, boom) {
		t.Errorf("cve outage: %v", err)
	}
	kn.cveErr = nil
	kn.advErr = map[string]error{"RHSA-2026:0001": boom}
	if _, err := svc.Status(ctx, w.ID()); !errors.Is(err, boom) {
		t.Errorf("advisory outage: %v", err)
	}
	kn.advErr = nil
	repo.byFaultlineErr = boom
	if _, err := svc.Status(ctx, w.ID()); !errors.Is(err, boom) {
		t.Errorf("findings outage: %v", err)
	}
	repo.byFaultlineErr = nil
	repo.getByIDErr = boom
	if _, err := svc.Status(ctx, w.ID()); !errors.Is(err, boom) {
		t.Errorf("finding read outage: %v", err)
	}
	repo.getByIDErr = nil
	store.saveErr = errors.New("disk full")
	if _, err := svc.Status(ctx, w.ID()); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("record failure: %v", err)
	}
	store.saveErr = nil
	if st, err := svc.Status(ctx, w.ID()); err != nil || len(st.Rows) != 1 || st.Rows[0].State != domain.WatchOpenNoFix {
		t.Errorf("recovered = %+v err %v", st.Rows, err)
	}
}

// Row order is the person's reading order: product, project, version, release, CVE — case
// folded on the names; blank-release rows last.
func TestWatchRowOrder(t *testing.T) {
	kn := &cardsByCVE{cards: map[string]app.FaultlineKnowledge{
		"CVE-2026-0002": {FaultlineID: "fl-2", CVE: "CVE-2026-0002"},
		"CVE-2026-0001": {FaultlineID: "fl-1", CVE: "CVE-2026-0001"},
	}}
	repo := newRepo()
	repo.seed(watchFinding(t, "z", "rel-z", "fl-2", "CVE-2026-0002", comp("pkg:x")))
	repo.seed(watchFinding(t, "y", "rel-y", "fl-2", "CVE-2026-0002", comp("pkg:x")))
	repo.seed(watchFinding(t, "x", "rel-x", "fl-1", "CVE-2026-0001", comp("pkg:x")))
	repo.seed(watchFinding(t, "w", "rel-w", "fl-1", "CVE-2026-0001", comp("pkg:x")))
	repo.seed(watchFinding(t, "v", "rel-v", "fl-1", "CVE-2026-0001", comp("pkg:x")))
	owners := &ownersByRelease{names: map[string][3]string{
		"rel-z": {"b", "a", "2"}, "rel-y": {"B", "a", "1"}, "rel-x": {"a", "Z", "1"}, "rel-w": {"a", "z", "1"}, "rel-v": {"a", "Y", "1"},
	}}
	svc := app.NewWatchService(newMemWatches(), repo, kn, &seqIDs{}, fixedClock{}).WithOwners(owners)
	w, _, _ := svc.Create(context.Background(), "w", "alice", "CVE-2026-0002 CVE-2026-0001 CVE-2026-0003", false)
	st, err := svc.Status(context.Background(), w.ID())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range st.Rows {
		got = append(got, r.ReleaseID+"/"+r.CVE)
	}
	want := "rel-v/CVE-2026-0001 rel-v/CVE-2026-0002 rel-w/CVE-2026-0001 rel-w/CVE-2026-0002 rel-x/CVE-2026-0001 rel-x/CVE-2026-0002 rel-y/CVE-2026-0001 rel-y/CVE-2026-0002 rel-z/CVE-2026-0001 rel-z/CVE-2026-0002 /CVE-2026-0003"
	if strings.Join(got, " ") != want {
		t.Errorf("order =\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
}

package app_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type psirtWorld struct {
	rows  []app.PublishedCVE
	older int
	err   error
}

func (w *psirtWorld) LatestPublished(context.Context, int) ([]app.PublishedCVE, int, error) {
	out := append([]app.PublishedCVE(nil), w.rows...)
	return out, w.older, w.err
}

type psirtEngine struct {
	m   map[string][]app.EngineMatch
	err error
	got []string
}

func (e *psirtEngine) MatchesByCVE(_ context.Context, cves []string) (map[string][]app.EngineMatch, error) {
	e.got = append(e.got, cves...)
	return e.m, e.err
}

type psirtEstate struct {
	releases map[string]app.ProductRef
	err      error
	calls    int
}

func (e *psirtEstate) ReleaseProducts(context.Context) (map[string]app.ProductRef, error) {
	e.calls++
	return e.releases, e.err
}

type psirtSBOMs struct {
	ids map[string]string
	err error
}

func (s psirtSBOMs) SBOMForRelease(_ context.Context, releaseID string) (string, bool, error) {
	id, ok := s.ids[releaseID]
	return id, ok, s.err
}

type psirtInventory struct {
	inv map[string]app.Inventory
	err error
}

func (i psirtInventory) GetInventory(_ context.Context, evidenceID string) (app.Inventory, error) {
	return i.inv[evidenceID], i.err
}

type psirtCVEOrg struct {
	mu    sync.Mutex
	obs   map[string]domain.ObservationInput
	err   error
	calls int
}

func (c *psirtCVEOrg) FetchRecord(_ context.Context, cve value.CVEID) (domain.ObservationInput, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	o, ok := c.obs[cve.String()]
	return o, ok, c.err
}

type movingClock struct{ now time.Time }

func (c *movingClock) Now() time.Time { return c.now }

func psirtEstateFixture() (*psirtEstate, psirtSBOMs, psirtInventory) {
	estate := &psirtEstate{releases: map[string]app.ProductRef{
		"r1": {ID: "p1", Name: "product-a"},
		"r2": {ID: "p1", Name: "product-a"},
		"r3": {ID: "p2", Name: "product-b"},
		"r4": {ID: "p2", Name: "product-b"}, // no SBOM filed
	}}
	sboms := psirtSBOMs{ids: map[string]string{"r1": "e1", "r2": "e2", "r3": "e3"}}
	inv := psirtInventory{inv: map[string]app.Inventory{
		"e1": {Components: []app.InventoryComponent{{Name: "openssl-libs", Source: "openssl"}, {Name: " "}}},
		"e2": {Components: []app.InventoryComponent{{Name: "openssl-libs", Source: "openssl"}, {Name: "libxml2"}}},
		"e3": {Components: []app.InventoryComponent{{Name: "golang.org/x/net"}}},
	}}
	return estate, sboms, inv
}

// EDR-PSIRT-01 P2: the floor filters by original score (unscored rows never alert), rows sort by
// score then newest, and each row carries the components it may hit in every product.
func TestPSIRT_AlertsMatchAndFilter(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	world := &psirtWorld{rows: []app.PublishedCVE{
		{CVE: "CVE-2026-1", Score: 9.8, Severity: "critical", Published: now.Add(-time.Hour), Affected: []string{"openssl"}},
		{CVE: "CVE-2026-2", Score: 7.5, Severity: "high", Published: now.Add(-2 * time.Hour), Affected: []string{"net", "libxml2"}, AffectedRefs: []string{"golang:net", "xmlsoft:libxml2"}},
		{CVE: "CVE-2026-3", Score: 7.5, Severity: "high", Published: now.Add(-time.Hour), Affected: []string{"nothing-here"}},
		{CVE: "CVE-2026-4", Score: 5.0, Severity: "medium", Published: now, Affected: []string{"openssl"}},
		{CVE: "CVE-2026-5", Score: 2.0, Severity: "low", Published: now, Affected: []string{"openssl"}},
		{CVE: "CVE-2026-6", Published: now, Affected: []string{"openssl"}}, // unscored
		{CVE: "CVE-2026-7", Score: 7.5, Severity: "high", Published: now.Add(-time.Hour), Affected: []string{"x1y"}},
	}}
	estate, sboms, inv := psirtEstateFixture()
	svc := app.NewPSIRTService(world, estate, sboms, inv, nil, &movingClock{now: now})

	res, err := svc.Alerts(context.Background(), 7, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range res.Alerts {
		got = append(got, fmt.Sprintf("%s:%s:%d", a.CVE, a.ScoreSource, len(a.Matches)))
	}
	if fmt.Sprint(got) != "[CVE-2026-1:nvd:1 CVE-2026-3:nvd:0 CVE-2026-7:nvd:0 CVE-2026-2:nvd:2]" {
		t.Errorf("high floor = %v", got)
	}
	if res.EstateUnavailable || res.LookupsSkipped != 0 {
		t.Errorf("flags = %+v", res)
	}
	m := res.Alerts[3].Matches
	if fmt.Sprintf("%+v", m) != "[{ProductID:p1 ProductName:product-a Component:libxml2 MatchedOn:libxml2} {ProductID:p2 ProductName:product-b Component:golang.org/x/net MatchedOn:golang:net}]" {
		t.Errorf("matches = %+v", m)
	}
	if mm := res.Alerts[0].Matches; len(mm) != 1 || mm[0].Component != "openssl-libs" || mm[0].MatchedOn != "openssl" {
		t.Errorf("one product, one component even across two releases: %+v", mm)
	}

	for floor, want := range map[string]int{"critical": 1, "medium": 5, "LOW": 6, "bogus": 4} {
		res, err := svc.Alerts(context.Background(), 7, floor)
		if err != nil || len(res.Alerts) != want {
			t.Errorf("floor %q: %d rows (%v), want %d", floor, len(res.Alerts), err, want)
		}
	}
	// The estate walk is reused within its TTL.
	if estate.calls != 1 {
		t.Errorf("estate walked %d times, want once within the TTL", estate.calls)
	}
}

// CVE.org fills what NVD lacked: a higher score wins (owner A) and names the source, the CNA's
// affected names join the match; a lookup that fails or finds nothing leaves the row as NVD gave
// it; the cap counts what it skipped; an analysed critical row is never looked up.
func TestPSIRT_CVEOrgFillsGaps(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	world := &psirtWorld{rows: []app.PublishedCVE{
		{CVE: "CVE-2026-10", Published: now},                               // unscored, unanalysed
		{CVE: "CVE-2026-11", Score: 8.0, Severity: "high", Published: now}, // scored, no names
		{CVE: "CVE-2026-12", Score: 9.0, Severity: "critical", Published: now, Affected: []string{"libxml2"}},
		{CVE: "CVE-2026-13", Score: 7.0, Severity: "high", Published: now},   // CVE.org has nothing
		{CVE: "CVE-2026-14", Score: 5.0, Severity: "medium", Published: now}, // below the floor: never asked
		{CVE: "not-a-cve", Score: 7.0, Severity: "high", Published: now},
	}}
	org := &psirtCVEOrg{obs: map[string]domain.ObservationInput{
		"CVE-2026-10": {Applicability: []string{"example:openssl"}, Ratings: []domain.PublishedRating{
			{StatedScore: 9.1, HasStatedScore: true}, {StatedScore: 9.9}}},
		"CVE-2026-11": {Applicability: []string{"acme:libxml2"}, Ratings: []domain.PublishedRating{{StatedScore: 7.2, HasStatedScore: true}}},
	}}
	estate, sboms, inv := psirtEstateFixture()
	svc := app.NewPSIRTService(world, estate, sboms, inv, org, &movingClock{now: now})
	res, err := svc.Alerts(context.Background(), 7, "high")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]app.PSIRTAlert{}
	for _, a := range res.Alerts {
		by[a.CVE] = a
	}
	if a := by["CVE-2026-10"]; a.Score != 9.1 || a.ScoreSource != "cve.org" || a.Severity != "critical" || len(a.Matches) != 1 {
		t.Errorf("unscored row filled = %+v", a)
	}
	if a := by["CVE-2026-11"]; a.Score != 8.0 || a.ScoreSource != "nvd" || len(a.Matches) != 1 || a.Matches[0].Component != "libxml2" {
		t.Errorf("a lower CVE.org score never replaces NVD's; names still join: %+v", a)
	}
	if a := by["CVE-2026-13"]; len(a.Matches) != 0 || a.ScoreSource != "nvd" {
		t.Errorf("nothing found = %+v", a)
	}
	if org.calls != 3 {
		t.Errorf("CVE.org calls = %d, want 3 (the analysed row, the row below the floor and the bad id are never asked)", org.calls)
	}
	// The answers, a "nothing there" included, are reused within PSIRTCVEOrgTTL, then asked again.
	clock := &movingClock{now: now}
	cached := app.NewPSIRTService(world, estate, sboms, inv, org, clock)
	org.calls = 0
	for i := 0; i < 2; i++ {
		res, _ = cached.Alerts(context.Background(), 7, "high")
	}
	if org.calls != 3 {
		t.Errorf("two reads asked CVE.org %d times, want 3", org.calls)
	}
	if a := res.Alerts[0]; a.CVE != "CVE-2026-10" || a.ScoreSource != "cve.org" || len(a.Matches) != 1 {
		t.Errorf("a cached answer still fills the row: %+v", a)
	}
	clock.now = now.Add(app.PSIRTCVEOrgTTL)
	_, _ = cached.Alerts(context.Background(), 7, "high")
	if org.calls != 6 {
		t.Errorf("after the TTL: %d calls, want 6", org.calls)
	}

	// A failing CVE.org leaves every row as NVD gave it.
	failing := &psirtCVEOrg{err: errors.New("down")}
	res, err = app.NewPSIRTService(world, estate, sboms, inv, failing, &movingClock{now: now}).Alerts(context.Background(), 7, "high")
	if err != nil || len(res.Alerts) != 4 {
		t.Errorf("CVE.org down: %d rows, %v", len(res.Alerts), err)
	}

	// The cap: more rows needing a lookup than PSIRTMaxCVEOrgLookups are counted, not asked.
	many := &psirtWorld{}
	for i := 0; i < app.PSIRTMaxCVEOrgLookups+3; i++ {
		many.rows = append(many.rows, app.PublishedCVE{CVE: fmt.Sprintf("CVE-2026-%d", 2000+i), Score: 7.5, Published: now})
	}
	capped := &psirtCVEOrg{}
	res, _ = app.NewPSIRTService(many, estate, sboms, inv, capped, &movingClock{now: now}).Alerts(context.Background(), 7, "high")
	if res.LookupsSkipped != 3 || capped.calls != app.PSIRTMaxCVEOrgLookups {
		t.Errorf("cap: skipped %d, calls %d", res.LookupsSkipped, capped.calls)
	}
	// The next read asks only about the rows not answered yet, so the list fills in.
	capSvc := app.NewPSIRTService(many, estate, sboms, inv, capped, &movingClock{now: now})
	capped.calls = 0
	_, _ = capSvc.Alerts(context.Background(), 7, "high")
	res, _ = capSvc.Alerts(context.Background(), 7, "high")
	if res.LookupsSkipped != 0 || capped.calls != app.PSIRTMaxCVEOrgLookups+3 {
		t.Errorf("second read: skipped %d, calls %d", res.LookupsSkipped, capped.calls)
	}
}

// cancellingCVEOrg ends the read's budget during its own lookup, as a slow CVE.org would.
type cancellingCVEOrg struct{ cancel context.CancelFunc }

func (c cancellingCVEOrg) FetchRecord(context.Context, value.CVEID) (domain.ObservationInput, bool, error) {
	c.cancel()
	return domain.ObservationInput{}, false, context.Canceled
}

// A lookup the budget cut off counts as skipped and is not remembered as an answer.
func TestPSIRT_CVEOrgBudgetCountsAsSkipped(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	world := &psirtWorld{rows: []app.PublishedCVE{{CVE: "CVE-2026-20", Score: 9.0, Published: now}, {CVE: "CVE-2026-21", Score: 9.0, Published: now}}}
	estate, sboms, inv := psirtEstateFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := app.NewPSIRTService(world, estate, sboms, inv, cancellingCVEOrg{cancel: cancel}, &movingClock{now: now}).Alerts(ctx, 7, "high")
	if err != nil || res.LookupsSkipped != 2 || len(res.Alerts) != 2 {
		t.Errorf("budget: skipped %d, %d rows, %v", res.LookupsSkipped, len(res.Alerts), err)
	}
}

// An estate that cannot be read never reads as "no product hit": the rows are listed and the
// flag is set. A world source failure is an error.
func TestPSIRT_EstateAndWorldFailures(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	world := &psirtWorld{rows: []app.PublishedCVE{{CVE: "CVE-2026-1", Score: 9.8, Published: now, Affected: []string{"openssl"}}}}
	estate, sboms, inv := psirtEstateFixture()

	cases := map[string]*app.PSIRTService{
		"unwired":         app.NewPSIRTService(world, nil, sboms, inv, nil, &movingClock{now: now}),
		"registry down":   app.NewPSIRTService(world, &psirtEstate{err: errors.New("registry down")}, sboms, inv, nil, &movingClock{now: now}),
		"evidence list":   app.NewPSIRTService(world, estate, psirtSBOMs{err: errors.New("401")}, inv, nil, &movingClock{now: now}),
		"inventory fails": app.NewPSIRTService(world, estate, sboms, psirtInventory{err: errors.New("500")}, nil, &movingClock{now: now}),
	}
	for name, svc := range cases {
		res, err := svc.Alerts(context.Background(), 7, "high")
		if err != nil || !res.EstateUnavailable || len(res.Alerts) != 1 || len(res.Alerts[0].Matches) != 0 {
			t.Errorf("%s: %+v, %v", name, res, err)
		}
	}

	if _, err := app.NewPSIRTService(&psirtWorld{err: app.ErrPublishedUnavailable}, estate, sboms, inv, nil, &movingClock{now: now}).
		Alerts(context.Background(), 7, "high"); !errors.Is(err, app.ErrPublishedUnavailable) {
		t.Errorf("world failure = %v", err)
	}

	// The estate cache expires after its TTL.
	clock := &movingClock{now: now}
	fresh := &psirtEstate{releases: estate.releases}
	svc := app.NewPSIRTService(world, fresh, sboms, inv, nil, clock)
	_, _ = svc.Alerts(context.Background(), 7, "high")
	clock.now = now.Add(app.PSIRTEstateTTL + time.Second)
	_, _ = svc.Alerts(context.Background(), 7, "high")
	if fresh.calls != 2 {
		t.Errorf("estate walked %d times, want 2 across the TTL", fresh.calls)
	}
}

// Ties sort deterministically: same score and time order by CVE id.
func TestPSIRT_TieOrder(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	world := &psirtWorld{rows: []app.PublishedCVE{
		{CVE: "CVE-2026-9", Score: 7.5, Published: now, Affected: []string{"a1b"}},
		{CVE: "CVE-2026-8", Score: 7.5, Published: now, Affected: []string{"a1b"}},
	}}
	// Two products with one name stay two products, ordered by id.
	estate := &psirtEstate{releases: map[string]app.ProductRef{"r1": {ID: "p9", Name: "same"}, "r2": {ID: "p8", Name: "same"}}}
	sboms := psirtSBOMs{ids: map[string]string{"r1": "e1", "r2": "e1"}}
	inv := psirtInventory{inv: map[string]app.Inventory{"e1": {Components: []app.InventoryComponent{{Name: "a1b"}}}}}
	res, _ := app.NewPSIRTService(world, estate, sboms, inv, nil, &movingClock{now: now}).Alerts(context.Background(), 7, "high")
	if len(res.Alerts) != 2 || res.Alerts[0].CVE != "CVE-2026-8" {
		t.Errorf("tie order = %+v", res.Alerts)
	}
	if m := res.Alerts[0].Matches; len(m) != 2 || m[0].ProductID != "p8" || m[1].ProductID != "p9" {
		t.Errorf("same-name products = %+v", m)
	}
}

// EDR-PSIRT-01 P4: a CVE Themis already filed shows the products its own correlation found,
// marked "themis" and listed first; a name match for the same component is not repeated; a
// release outside the estate walk is left out; only carded rows are asked about; the source's
// "older not read" count is passed on.
func TestPSIRT_EngineMatchesForCardedRows(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	world := &psirtWorld{older: 42, rows: []app.PublishedCVE{
		{CVE: "CVE-2026-30", Score: 8.2, Published: now, Carded: true, Affected: []string{"libxml2", "openssl"}},
		{CVE: "CVE-2026-31", Score: 7.5, Published: now, Carded: true},
		{CVE: "CVE-2026-32", Score: 7.5, Published: now, Affected: []string{"openssl"}},
		{CVE: "CVE-2026-33", Score: 4.0, Published: now, Carded: true},
	}}
	engine := &psirtEngine{m: map[string][]app.EngineMatch{
		"CVE-2026-30": {{ReleaseID: "r2", Component: "libxml2"}, {ReleaseID: "r1", Component: "libxml2"}, {ReleaseID: "r3", Component: "libxml2"}, {ReleaseID: "r1", Component: "libxml2-utils"}, {ReleaseID: "gone", Component: "x"}},
		"CVE-2026-31": {{ReleaseID: "gone", Component: "x"}},
	}}
	estate, sboms, inv := psirtEstateFixture()
	svc := app.NewPSIRTService(world, estate, sboms, inv, nil, &movingClock{now: now}).WithEngine(engine)
	res, err := svc.Alerts(context.Background(), 7, "high")
	if err != nil || res.OlderNotRead != 42 || res.EstateUnavailable {
		t.Fatalf("res = %+v, %v", res, err)
	}
	if fmt.Sprint(engine.got) != "[CVE-2026-30 CVE-2026-31]" {
		t.Errorf("asked about %v, want the carded rows at or above the floor", engine.got)
	}
	by := map[string][]app.PSIRTMatch{}
	for _, a := range res.Alerts {
		by[a.CVE] = a.Matches
	}
	if got := fmt.Sprintf("%+v", by["CVE-2026-30"]); got != "[{ProductID:p1 ProductName:product-a Component:libxml2 MatchedOn:themis} {ProductID:p1 ProductName:product-a Component:libxml2-utils MatchedOn:themis} {ProductID:p2 ProductName:product-b Component:libxml2 MatchedOn:themis} {ProductID:p1 ProductName:product-a Component:openssl-libs MatchedOn:openssl}]" {
		t.Errorf("engine matches = %s", got)
	}
	if len(by["CVE-2026-31"]) != 0 || len(by["CVE-2026-32"]) != 1 {
		t.Errorf("a release gone from the estate adds nothing; an uncarded row keeps its name match: %+v", by)
	}

	// An engine read that fails says the estate view is incomplete, never "no product hit".
	failing := app.NewPSIRTService(world, estate, sboms, inv, nil, &movingClock{now: now}).WithEngine(&psirtEngine{err: errors.New("db down")})
	if res, err := failing.Alerts(context.Background(), 7, "high"); err != nil || !res.EstateUnavailable {
		t.Errorf("engine down: %+v, %v", res, err)
	}
	// Without an estate there is no product to name, so the engine is not asked.
	unwired := &psirtEngine{}
	_, _ = app.NewPSIRTService(world, nil, sboms, inv, nil, &movingClock{now: now}).WithEngine(unwired).Alerts(context.Background(), 7, "high")
	if len(unwired.got) != 0 {
		t.Errorf("asked without an estate: %v", unwired.got)
	}
}

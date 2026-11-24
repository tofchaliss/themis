package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// ProductRef names the product a release belongs to (Registry's estate graph).
type ProductRef struct {
	ID   string
	Name string
}

// EstateProducts maps every release in the estate to its product, read from Registry's read API
// (EDR-PSIRT-01 P2). It never touches Registry's tables.
type EstateProducts interface {
	ReleaseProducts(ctx context.Context) (map[string]ProductRef, error)
}

// latestPublished is the slice of PublishedService the alert reads.
type latestPublished interface {
	LatestPublished(ctx context.Context, days int) ([]PublishedCVE, error)
}

// PSIRTMatch is one product component a world CVE's affected name matched (Q1, name match).
type PSIRTMatch struct {
	ProductID   string
	ProductName string
	Component   string
	MatchedOn   string
}

// PSIRTAlert is one row of the PSIRT early alert: a CVE the world published recently, its
// original (source) score, and the product components it may hit. No Themis score (owner B).
type PSIRTAlert struct {
	PublishedCVE
	// ScoreSource names where Score came from: "nvd", or "cve.org" when a CVE.org rating was
	// higher or NVD had none (owner A: the highest source score wins).
	ScoreSource string
	Matches     []PSIRTMatch
}

// PSIRTResult is the alert list plus what the page must say beside it.
type PSIRTResult struct {
	Alerts []PSIRTAlert
	// EstateUnavailable is set when the product inventory could not be read: the rows are still
	// listed, but "no product matched" would then be a lie, so the page says why instead.
	EstateUnavailable bool
	// LookupsSkipped counts rows that needed a CVE.org lookup beyond the per-call cap.
	LookupsSkipped int
}

// Bounds of one alert read. The CVE.org lookups run only for rows NVD left without a score or
// without affected names (a record NVD has not analysed yet), and at most this many per read.
const (
	PSIRTMaxCVEOrgLookups = 200
	psirtLookupWorkers    = 4
	// PSIRTLookupBudget bounds the whole CVE.org pass: an unreachable CVE.org must cost one
	// page view a few seconds, not a minute per row. A lookup cut off by it leaves its row as
	// NVD gave it.
	PSIRTLookupBudget = 20 * time.Second
	// PSIRTEstateTTL is how long the product inventory is reused between reads. Releases and
	// SBOMs change on upload, minutes apart at most; one walk per read would be one Evidence
	// round-trip per release on every page view.
	PSIRTEstateTTL = 15 * time.Minute
	// PSIRTCVEOrgTTL is how long one CVE.org answer is reused, a "nothing there" included. A
	// fresh week holds more unanalysed records than one read may ask about (VM 2026-11-24:
	// 1656 over the cap), so each read asks only about rows not yet answered and the list fills
	// in over a few page views. A CNA rarely changes a record within hours; an error is never
	// kept, so the next read asks again.
	PSIRTCVEOrgTTL = 6 * time.Hour
)

// PSIRTService builds the PSIRT early alert (EDR-PSIRT-01 P2). It reads the live world list,
// fills gaps from CVE.org, and name-matches each CVE against the estate's components. It stores
// nothing (EDR-KNOWLEDGE-01 D5) and decides nothing.
type PSIRTService struct {
	published latestPublished
	estate    EstateProducts
	sboms     ReleaseSBOMSource
	inventory InventoryReader
	cveorg    CVERecordSource // may be nil: no CVE.org gap filling
	clock     Clock

	mu       sync.Mutex
	cachedAt time.Time
	cached   []productComponents

	orgMu   sync.Mutex
	answers map[string]cveorgAnswer
}

// cveorgAnswer is what one CVE.org lookup said: its best stated score and the CNA's affected
// entries ("vendor:product[:package]"); both empty when the record was not found.
type cveorgAnswer struct {
	at       time.Time
	score    float64
	affected []string
}

type productComponents struct {
	ref   ProductRef
	comps []domain.ComponentRef
}

// NewPSIRTService wires the alert. A nil estate, SBOM source or inventory reader lists the
// world rows with EstateUnavailable set.
func NewPSIRTService(published latestPublished, estate EstateProducts, sboms ReleaseSBOMSource, inventory InventoryReader, cveorg CVERecordSource, clock Clock) *PSIRTService {
	return &PSIRTService{published: published, estate: estate, sboms: sboms, inventory: inventory, cveorg: cveorg, clock: clock}
}

// Alerts lists the CVEs published in the last `days` days whose original score is at least
// minSeverity ("critical" | "high" | "medium" | "low"; "" = "high"), sorted by score, then
// newest first, each with the product components it may hit.
func (s *PSIRTService) Alerts(ctx context.Context, days int, minSeverity string) (PSIRTResult, error) {
	rows, err := s.published.LatestPublished(ctx, days)
	if err != nil {
		return PSIRTResult{}, err
	}
	floor := severityFloor(minSeverity)
	alerts := make([]PSIRTAlert, len(rows))
	for i, r := range rows {
		alerts[i] = PSIRTAlert{PublishedCVE: r}
		if r.Score > 0 {
			alerts[i].ScoreSource = "nvd"
		}
	}
	res := PSIRTResult{}
	res.LookupsSkipped = s.fillFromCVEOrg(ctx, alerts, floor)

	products, estateErr := s.products(ctx)
	res.EstateUnavailable = estateErr != nil
	kept := alerts[:0]
	for _, a := range alerts {
		// An unscored row is not an alert at any floor: the alert is about severity.
		if severityRankOf(a.Score) < floor {
			continue
		}
		// The bare names (no vendor) still match whole component names; the vendor:product
		// pairs also allow a path's last segment (domain.MatchComponents).
		refs := domain.AffectedRefs(append(append([]string(nil), a.Affected...), a.AffectedRefs...))
		for _, p := range products {
			for _, m := range domain.MatchComponents(refs, p.comps) {
				a.Matches = append(a.Matches, PSIRTMatch{ProductID: p.ref.ID, ProductName: p.ref.Name, Component: m.Component, MatchedOn: m.MatchedOn})
			}
		}
		kept = append(kept, a)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].Score != kept[j].Score {
			return kept[i].Score > kept[j].Score
		}
		if !kept[i].Published.Equal(kept[j].Published) {
			return kept[i].Published.After(kept[j].Published)
		}
		return kept[i].CVE < kept[j].CVE
	})
	res.Alerts = kept
	return res, nil
}

// fillFromCVEOrg asks CVE.org about the rows NVD left without a score, or at or above the
// floor without affected names: the CNA's record usually names both from day one, NVD's
// analysis can take days. A row NVD scored below the floor is not asked (it is not an alert,
// and its names would show nowhere). A higher CVE.org score replaces NVD's (owner A). A failed
// lookup leaves the row as NVD gave it. Answers are reused for PSIRTCVEOrgTTL. It returns how
// many rows needed a lookup and did not get one: over the cap, or cut off by the budget.
func (s *PSIRTService) fillFromCVEOrg(ctx context.Context, alerts []PSIRTAlert, floor int) int {
	if s.cveorg == nil {
		return 0
	}
	now := s.clock.Now()
	s.orgMu.Lock()
	if s.answers == nil {
		s.answers = map[string]cveorgAnswer{}
	}
	for id, a := range s.answers {
		if now.Sub(a.at) >= PSIRTCVEOrgTTL {
			delete(s.answers, id)
		}
	}
	// A row that is already critical or high and only lacks its product names goes first (it
	// is an alert either way, and the names decide which team it reaches), then the unscored.
	var todo []int
	for i := range alerts {
		a := &alerts[i]
		if a.Score > 0 && (len(a.Affected) > 0 || severityRankOf(a.Score) < floor) {
			continue
		}
		if ans, ok := s.answers[a.CVE]; ok {
			applyCVEOrg(a, ans)
			continue
		}
		todo = append(todo, i)
	}
	s.orgMu.Unlock()
	sort.SliceStable(todo, func(x, y int) bool { return alerts[todo[x]].Score > alerts[todo[y]].Score })
	skipped := 0
	if len(todo) > PSIRTMaxCVEOrgLookups {
		skipped = len(todo) - PSIRTMaxCVEOrgLookups
		todo = todo[:PSIRTMaxCVEOrgLookups]
	}
	ctx, cancel := context.WithTimeout(ctx, PSIRTLookupBudget)
	defer cancel()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var late atomic.Int64
	for w := 0; w < psirtLookupWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					late.Add(1)
					continue
				}
				if !s.fillOne(ctx, &alerts[i], now) {
					late.Add(1)
				}
			}
		}()
	}
	for _, i := range todo {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return skipped + int(late.Load())
}

// fillOne reports false only when the budget cut the lookup off, so the row counts as skipped.
func (s *PSIRTService) fillOne(ctx context.Context, a *PSIRTAlert, now time.Time) bool {
	id, err := value.NewCVEID(a.CVE)
	if err != nil {
		return true
	}
	obs, found, err := s.cveorg.FetchRecord(ctx, id)
	if err != nil {
		return ctx.Err() == nil
	}
	ans := cveorgAnswer{at: now}
	if found {
		for _, r := range obs.Ratings {
			if r.HasStatedScore && r.StatedScore > ans.score {
				ans.score = r.StatedScore
			}
		}
		ans.affected = obs.Applicability
	}
	s.orgMu.Lock()
	s.answers[a.CVE] = ans
	s.orgMu.Unlock()
	applyCVEOrg(a, ans)
	return true
}

func applyCVEOrg(a *PSIRTAlert, ans cveorgAnswer) {
	if ans.score > a.Score {
		a.Score, a.Severity, a.ScoreSource = ans.score, string(value.SeverityFromCVSSScore(ans.score)), "cve.org"
	}
	if len(ans.affected) > 0 {
		a.Affected = domain.AffectedNames(a.Affected, ans.affected)
		a.AffectedRefs = append(append([]string(nil), a.AffectedRefs...), ans.affected...)
	}
}

// products returns every product with the components of all its releases' latest SBOMs,
// reused for PSIRTEstateTTL. Any failure is an error: a partial estate would silently read as
// "no product matched".
func (s *PSIRTService) products(ctx context.Context) ([]productComponents, error) {
	if s.estate == nil || s.sboms == nil || s.inventory == nil {
		return nil, errEstateUnwired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if s.cached != nil && now.Sub(s.cachedAt) < PSIRTEstateTTL {
		return s.cached, nil
	}
	releases, err := s.estate.ReleaseProducts(ctx)
	if err != nil {
		return nil, err
	}
	byProduct := map[string]*productComponents{}
	seen := map[string]map[domain.ComponentRef]struct{}{}
	ids := make([]string, 0, len(releases))
	for id := range releases {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, releaseID := range ids {
		ref := releases[releaseID]
		evidenceID, found, err := s.sboms.SBOMForRelease(ctx, releaseID)
		if err != nil {
			return nil, err
		}
		pc := byProduct[ref.ID]
		if pc == nil {
			pc = &productComponents{ref: ref}
			byProduct[ref.ID], seen[ref.ID] = pc, map[domain.ComponentRef]struct{}{}
		}
		if !found {
			continue
		}
		inv, err := s.inventory.GetInventory(ctx, evidenceID)
		if err != nil {
			return nil, err
		}
		for _, c := range inv.Components {
			ref := domain.ComponentRef{Name: strings.TrimSpace(c.Name), Source: strings.TrimSpace(c.Source)}
			if ref.Name == "" {
				continue
			}
			if _, dup := seen[pc.ref.ID][ref]; !dup {
				seen[pc.ref.ID][ref] = struct{}{}
				pc.comps = append(pc.comps, ref)
			}
		}
	}
	out := make([]productComponents, 0, len(byProduct))
	for _, pc := range byProduct {
		out = append(out, *pc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ref.Name != out[j].ref.Name {
			return out[i].ref.Name < out[j].ref.Name
		}
		return out[i].ref.ID < out[j].ref.ID
	})
	s.cached, s.cachedAt = out, now
	return out, nil
}

var errEstateUnwired = errors.New("psirt: no estate source wired on this node")

// severityFloor maps the requested minimum to a rank; anything unknown is "high", the
// owner's default for the alert.
func severityFloor(min string) int {
	switch strings.ToLower(strings.TrimSpace(min)) {
	case "critical":
		return 4
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 3
	}
}

func severityRankOf(score float64) int {
	switch value.SeverityFromCVSSScore(score) {
	case value.SeverityCritical:
		return 4
	case value.SeverityHigh:
		return 3
	case value.SeverityMedium:
		return 2
	case value.SeverityLow:
		return 1
	default:
		return 0
	}
}

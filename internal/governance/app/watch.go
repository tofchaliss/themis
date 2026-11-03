package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The Watch (EDR-INCIDENT-01 D2): identifiers in, one per-(release, CVE) state table out. The
// table is COMPUTED ON READ from the Findings, the Positions and the cards' recorded fixes —
// Governance stores only the list, so the table cannot drift from the truth it is read from.
// Nothing here decides: no Finding, Position or proposal changes because a Watch exists.

// ErrWatchUnresolvable is returned when the Knowledge seam needed to resolve identifiers is not
// wired: a Watch can be kept, but its table cannot be told.
var ErrWatchUnresolvable = errors.New("governance: watch status needs the Knowledge seam")

// WatchStore is the Watch persistence seam. GetWatch and DeleteWatch answer a missing id with
// the store's not-found error.
type WatchStore interface {
	SaveWatch(ctx context.Context, w domain.Watch) error
	GetWatch(ctx context.Context, id string) (domain.Watch, error)
	ListWatches(ctx context.Context) ([]domain.Watch, error)
	DeleteWatch(ctx context.Context, id string) error
}

// WatchKnowledge resolves identifiers against Knowledge's read API: a CVE to its card (found=false
// when there is none), an advisory to the cards whose vendor statements carry it (empty when
// Themis has not seen it).
type WatchKnowledge interface {
	FaultlineByCVE(ctx context.Context, cve string) (FaultlineKnowledge, bool, error)
	FaultlinesByAdvisory(ctx context.Context, advisory string) ([]FaultlineKnowledge, error)
}

// WatchFindings is the slice of the Repository the table reads.
type WatchFindings interface {
	FindingsByFaultline(ctx context.Context, faultlineID string) ([]domain.FindingID, error)
	GetByID(ctx context.Context, id domain.FindingID) (domain.Finding, error)
}

// EvidenceRef is the newest evidence filed against a release — "last proof" on the table.
type EvidenceRef struct {
	ID      string
	Kind    string
	FiledAt time.Time
}

// WatchEvidence reads the newest evidence of a release; found=false when none is filed.
type WatchEvidence interface {
	LatestEvidence(ctx context.Context, releaseID string) (EvidenceRef, bool, error)
}

// WatchIdentifierStatus is what one identifier resolved to.
type WatchIdentifierStatus struct {
	ID   string
	Kind string
	// CVEs the identifier stands for: itself for a carded CVE, the advisory's CVE set for an
	// advisory; empty when Resolved is false.
	CVEs     []string
	Resolved bool
}

// WatchRow is one (release, CVE) line of the table.
type WatchRow struct {
	ReleaseID   string
	ProductID   string
	ProjectID   string
	ProductName string
	ProjectName string
	Version     string
	CVE         string
	FaultlineID string
	FindingID   domain.FindingID
	State       domain.WatchState
	// Stance is the standing Position's stance, blank when undecided.
	Stance string
	// Packages are the OPEN components' package names; Fixes the recorded fix versions that
	// apply to them (why the state says a fix is available).
	Packages []string
	Fixes    []string
	// LastEvidenceAt / LastEvidenceKind: the release's newest filed evidence, zero when none or
	// when the Evidence seam is not wired.
	LastEvidenceAt   time.Time
	LastEvidenceKind string
}

// WatchStatus is the table with its heading.
type WatchStatus struct {
	Watch       domain.Watch
	GeneratedAt time.Time
	Identifiers []WatchIdentifierStatus
	Rows        []WatchRow
	// Counts per state, for the page's filter chips.
	Counts map[domain.WatchState]int
}

// WatchService keeps Watches and computes their tables.
type WatchService struct {
	store     WatchStore
	findings  WatchFindings
	knowledge WatchKnowledge
	ids       IDGenerator
	clock     Clock
	owners    ReleaseOwnerResolver
	evidence  WatchEvidence
}

// NewWatchService wires the service. knowledge may be nil: Watches can then be kept but not
// told (Status answers ErrWatchUnresolvable).
func NewWatchService(store WatchStore, findings WatchFindings, knowledge WatchKnowledge, ids IDGenerator, clock Clock) *WatchService {
	return &WatchService{store: store, findings: findings, knowledge: knowledge, ids: ids, clock: clock}
}

// WithOwners attaches the Registry hop that names each release's product and project. Without
// it the rows carry ids only.
func (s *WatchService) WithOwners(r ReleaseOwnerResolver) *WatchService {
	s.owners = r
	return s
}

// WithEvidence attaches the Evidence read that fills "last proof".
func (s *WatchService) WithEvidence(e WatchEvidence) *WatchService {
	s.evidence = e
	return s
}

// Create parses the pasted text and stores a new Watch. It returns the tokens it did not
// recognise beside the Watch, so the caller can say so; a text with none recognised is
// domain.ErrWatchEmpty.
func (s *WatchService) Create(ctx context.Context, name, createdBy, text string, notify bool) (domain.Watch, []string, error) {
	accepted, rejected := domain.ParseWatchIdentifiers(text)
	w, err := domain.NewWatch(s.ids.NewID(), name, createdBy, accepted, s.clock.Now())
	if err != nil {
		return domain.Watch{}, rejected, err
	}
	w.SetNotify(notify)
	if err := s.store.SaveWatch(ctx, w); err != nil {
		return domain.Watch{}, rejected, fmt.Errorf("save watch: %w", err)
	}
	return w, rejected, nil
}

// List returns every Watch, newest first.
func (s *WatchService) List(ctx context.Context) ([]domain.Watch, error) {
	return s.store.ListWatches(ctx)
}

// Get returns one Watch.
func (s *WatchService) Get(ctx context.Context, id string) (domain.Watch, error) {
	return s.store.GetWatch(ctx, id)
}

// AddIdentifiers appends the recognised identifiers of text (append-only) and reports how many
// were new and which tokens were not understood.
func (s *WatchService) AddIdentifiers(ctx context.Context, id, text string) (domain.Watch, int, []string, error) {
	w, err := s.store.GetWatch(ctx, id)
	if err != nil {
		return domain.Watch{}, 0, nil, err
	}
	accepted, rejected := domain.ParseWatchIdentifiers(text)
	added := w.AddIdentifiers(accepted)
	if added > 0 {
		if err := s.store.SaveWatch(ctx, w); err != nil {
			return domain.Watch{}, 0, rejected, fmt.Errorf("save watch: %w", err)
		}
	}
	return w, added, rejected, nil
}

// Delete removes a Watch whole.
func (s *WatchService) Delete(ctx context.Context, id string) error {
	return s.store.DeleteWatch(ctx, id)
}

// Status computes the table now. Resolution goes through Knowledge (a failure there is an error:
// "cannot tell" must not read as "nothing is affected"); names and last proof come from the
// optional Registry and Evidence seams and are blank when those are not wired or fail — ids are
// always present. The CVE set the identifiers resolved to is recorded on the Watch.
func (s *WatchService) Status(ctx context.Context, id string) (WatchStatus, error) {
	w, err := s.store.GetWatch(ctx, id)
	if err != nil {
		return WatchStatus{}, err
	}
	if s.knowledge == nil {
		return WatchStatus{}, ErrWatchUnresolvable
	}
	now := s.clock.Now()
	st := WatchStatus{Watch: w, GeneratedAt: now, Counts: map[domain.WatchState]int{}}

	// 1. Identifiers → cards, in first-seen order.
	var cves []string
	cards := map[string]FaultlineKnowledge{}
	for _, ident := range w.Identifiers() {
		is := WatchIdentifierStatus{ID: ident, Kind: domain.WatchIdentifierKind(ident)}
		var found []FaultlineKnowledge
		switch is.Kind {
		case "cve":
			card, ok, err := s.knowledge.FaultlineByCVE(ctx, ident)
			if err != nil {
				return WatchStatus{}, fmt.Errorf("resolve %s: %w", ident, err)
			}
			if ok {
				found = []FaultlineKnowledge{card}
			}
		case "advisory":
			found, err = s.knowledge.FaultlinesByAdvisory(ctx, ident)
			if err != nil {
				return WatchStatus{}, fmt.Errorf("resolve %s: %w", ident, err)
			}
		}
		for _, card := range found {
			cve := domain.NormalizeWatchIdentifier(card.CVE)
			if cve == "" {
				continue
			}
			is.CVEs = append(is.CVEs, cve)
			if _, seen := cards[cve]; !seen {
				cards[cve] = card
				cves = append(cves, cve)
			}
		}
		is.Resolved = len(is.CVEs) > 0
		st.Identifiers = append(st.Identifiers, is)
	}

	// 2. Cards → Findings, grouped by release in first-seen order.
	type cell struct {
		finding domain.Finding
		ok      bool
	}
	byRelease := map[string]map[string]cell{}
	var releases []string
	for _, cve := range cves {
		ids, err := s.findings.FindingsByFaultline(ctx, cards[cve].FaultlineID)
		if err != nil {
			return WatchStatus{}, fmt.Errorf("findings of %s: %w", cve, err)
		}
		for _, fid := range ids {
			f, err := s.findings.GetByID(ctx, fid)
			if err != nil {
				return WatchStatus{}, fmt.Errorf("read finding %s: %w", fid, err)
			}
			rel := f.ReleaseID()
			if _, seen := byRelease[rel]; !seen {
				byRelease[rel] = map[string]cell{}
				releases = append(releases, rel)
			}
			byRelease[rel][cve] = cell{finding: f, ok: true}
		}
	}

	// 3. Rows: every (release, CVE); a release with no Finding for a CVE matches no component.
	owners := map[string]ReleaseOwners{}
	proofs := map[string]EvidenceRef{}
	for _, rel := range releases {
		if s.owners != nil {
			if o, err := s.owners.ReleaseOwners(ctx, rel); err == nil {
				owners[rel] = o
			}
		}
		if s.evidence != nil {
			if ev, ok, err := s.evidence.LatestEvidence(ctx, rel); err == nil && ok {
				proofs[rel] = ev
			}
		}
	}
	add := func(row WatchRow) {
		st.Rows = append(st.Rows, row)
		st.Counts[row.State]++
	}
	for _, cve := range cves {
		card := cards[cve]
		if len(releases) == 0 {
			add(WatchRow{CVE: cve, FaultlineID: card.FaultlineID, State: domain.WatchNotAffected})
			continue
		}
		for _, rel := range releases {
			o, ev := owners[rel], proofs[rel]
			row := WatchRow{
				ReleaseID: rel, ProductID: o.ProductID, ProjectID: o.ProjectID,
				ProductName: o.ProductName, ProjectName: o.ProjectName, Version: o.Version,
				CVE: cve, FaultlineID: card.FaultlineID, LastEvidenceAt: ev.FiledAt, LastEvidenceKind: ev.Kind,
			}
			c := byRelease[rel][cve]
			if !c.ok {
				row.State = domain.WatchNotAffected
				add(row)
				continue
			}
			row.FindingID = c.finding.ID()
			if pos, ok := c.finding.CurrentPosition(); ok {
				row.Stance = string(pos.Stance())
			}
			comps := c.finding.ActiveComponents()
			for _, comp := range comps {
				if comp.VerdictIsOpen() {
					row.Packages = appendUnique(row.Packages, comp.Name)
				}
			}
			for _, fx := range selectFixesFor(card.Fixes, comps) {
				row.Fixes = appendUnique(row.Fixes, fx.Version)
			}
			row.State = domain.WatchStateOf(c.finding, len(row.Fixes) > 0)
			add(row)
		}
	}
	for _, is := range st.Identifiers {
		if !is.Resolved {
			add(WatchRow{CVE: is.ID, State: domain.WatchUnknown})
		}
	}
	sortWatchRows(st.Rows)

	// 4. Record what the identifiers meant at this read.
	w.RecordResolution(cves, now)
	if err := s.store.SaveWatch(ctx, w); err != nil {
		return WatchStatus{}, fmt.Errorf("record resolution: %w", err)
	}
	st.Watch = w
	return st, nil
}

// sortWatchRows orders by product, project, version, release id, CVE; rows with no release
// (nothing in the estate, or unknown) come last.
func sortWatchRows(rows []WatchRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if (a.ReleaseID == "") != (b.ReleaseID == "") {
			return a.ReleaseID != ""
		}
		if k := strings.Compare(strings.ToLower(a.ProductName), strings.ToLower(b.ProductName)); k != 0 {
			return k < 0
		}
		if k := strings.Compare(strings.ToLower(a.ProjectName), strings.ToLower(b.ProjectName)); k != 0 {
			return k < 0
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.ReleaseID != b.ReleaseID {
			return a.ReleaseID < b.ReleaseID
		}
		return a.CVE < b.CVE
	})
}

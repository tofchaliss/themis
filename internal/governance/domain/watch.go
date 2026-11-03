package domain

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A Watch (EDR-INCIDENT-01 D2) is a named, operator-owned list of identifiers — CVE ids and
// vendor advisory ids — whose per-(release, CVE) state the operator wants to see in one table
// during a vulnerability wave. It holds NO state of its own about any Finding: the state is
// computed on read from what Governance and Knowledge already store, so it cannot drift. A
// Watch is append-only on its identifiers (add, never silently drop) and deletable as a whole.

// ErrWatchNameRequired is returned when a Watch is created with a blank name.
var ErrWatchNameRequired = errors.New("governance: a watch needs a name")

// ErrWatchEmpty is returned when a Watch would hold no recognisable identifier.
var ErrWatchEmpty = errors.New("governance: a watch needs at least one CVE or advisory id")

// WatchState is the per-(release, CVE) state of a watched identifier (D2's table).
type WatchState string

const (
	// WatchNotAffected: no component of the release matches the CVE, or a not_affected
	// Position stands.
	WatchNotAffected WatchState = "not_affected"
	// WatchOpenNoFix: an occurrence is open and no vendor fix is known for its package.
	WatchOpenNoFix WatchState = "open_no_fix"
	// WatchOpenFixAvailable: an occurrence is open and a fix is recorded for its package.
	WatchOpenFixAvailable WatchState = "open_fix_available"
	// WatchFixed: every occurrence is cleared by evidence (the installed build carries the fix).
	WatchFixed WatchState = "fixed"
	// WatchAccepted: an accepted_risk / mitigated / deferred Position stands.
	WatchAccepted WatchState = "accepted"
	// WatchUnknown: the CVE has no card, or the advisory resolved to no CVE.
	WatchUnknown WatchState = "unknown"
)

var (
	cveIDPattern      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	advisoryIDPattern = regexp.MustCompile(`^RH[SBE]A-\d{4}:\d{3,}$`)
)

// WatchIdentifierKind classifies one identifier: "cve", "advisory", or "" for a token Themis
// does not recognise. Identifiers are compared upper-cased.
func WatchIdentifierKind(id string) string {
	id = NormalizeWatchIdentifier(id)
	switch {
	case cveIDPattern.MatchString(id):
		return "cve"
	case advisoryIDPattern.MatchString(id):
		return "advisory"
	}
	return ""
}

// NormalizeWatchIdentifier trims and upper-cases one identifier.
func NormalizeWatchIdentifier(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// ParseWatchIdentifiers splits pasted text on whitespace, commas and semicolons and returns the
// recognised identifiers (normalised, de-duplicated, in first-seen order) and the tokens it
// rejected — so the page can say "3 added, 1 not understood" instead of dropping one silently.
func ParseWatchIdentifiers(text string) (accepted, rejected []string) {
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	}) {
		id := NormalizeWatchIdentifier(tok)
		if id == "" {
			continue
		}
		if WatchIdentifierKind(id) == "" {
			rejected = append(rejected, id)
			continue
		}
		if !seen[id] {
			seen[id] = true
			accepted = append(accepted, id)
		}
	}
	return accepted, rejected
}

// Watch is the aggregate. Identifiers are kept as typed (normalised), in insertion order.
type Watch struct {
	id          string
	name        string
	createdBy   string
	createdAt   time.Time
	identifiers []string
	// resolvedCVEs is the CVE set the identifiers resolved to at the last status read, kept so
	// a later reader can see what an advisory meant THEN; resolvedAt stamps it.
	resolvedCVEs []string
	resolvedAt   time.Time
	// notify marks the Watch for D2a change announcements (not emitted in v1; recorded so the
	// flag survives when the emitter arrives).
	notify bool
}

// NewWatch creates a Watch from a name and the recognised identifiers. The name and at least one
// identifier are required.
func NewWatch(id, name, createdBy string, identifiers []string, now time.Time) (Watch, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Watch{}, ErrWatchNameRequired
	}
	w := Watch{id: id, name: name, createdBy: strings.TrimSpace(createdBy), createdAt: now.UTC()}
	if w.AddIdentifiers(identifiers) == 0 {
		return Watch{}, ErrWatchEmpty
	}
	return w, nil
}

// ReconstituteWatch rebuilds a Watch from storage. Unrecognised identifiers are kept as stored —
// the store is the record, and the status read reports them as unknown.
func ReconstituteWatch(id, name, createdBy string, createdAt time.Time, identifiers, resolvedCVEs []string, resolvedAt time.Time, notify bool) Watch {
	return Watch{
		id: id, name: name, createdBy: createdBy, createdAt: createdAt.UTC(),
		identifiers: append([]string(nil), identifiers...), resolvedCVEs: append([]string(nil), resolvedCVEs...),
		resolvedAt: resolvedAt.UTC(), notify: notify,
	}
}

// AddIdentifiers appends the recognised identifiers not already held and reports how many were
// added. Append-only: nothing is ever removed.
func (w *Watch) AddIdentifiers(ids []string) (added int) {
	have := map[string]bool{}
	for _, id := range w.identifiers {
		have[id] = true
	}
	for _, raw := range ids {
		id := NormalizeWatchIdentifier(raw)
		if WatchIdentifierKind(id) == "" || have[id] {
			continue
		}
		have[id] = true
		w.identifiers = append(w.identifiers, id)
		added++
	}
	return added
}

// RecordResolution stores the CVE set the identifiers resolved to at this read (sorted).
func (w *Watch) RecordResolution(cves []string, at time.Time) {
	set := map[string]bool{}
	for _, c := range cves {
		if c = NormalizeWatchIdentifier(c); c != "" {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	w.resolvedCVEs = out
	w.resolvedAt = at.UTC()
}

// SetNotify sets the D2a flag.
func (w *Watch) SetNotify(on bool) { w.notify = on }

// ID returns the Watch's identity.
func (w Watch) ID() string { return w.id }

// Name returns the operator's name for it.
func (w Watch) Name() string { return w.name }

// CreatedBy returns who created it.
func (w Watch) CreatedBy() string { return w.createdBy }

// CreatedAt returns when.
func (w Watch) CreatedAt() time.Time { return w.createdAt }

// Identifiers returns the identifiers as typed, in order (a copy).
func (w Watch) Identifiers() []string { return append([]string(nil), w.identifiers...) }

// ResolvedCVEs returns the CVE set of the last resolution (a copy).
func (w Watch) ResolvedCVEs() []string { return append([]string(nil), w.resolvedCVEs...) }

// ResolvedAt returns when the last resolution was recorded; zero when never.
func (w Watch) ResolvedAt() time.Time { return w.resolvedAt }

// Notify reports the D2a flag.
func (w Watch) Notify() bool { return w.notify }

// WatchStateOf classifies one Finding for the table (D2). fixKnown says whether a vendor fix is
// on record for one of its OPEN components' packages; the caller selects that from the card,
// the way the posture's selected fixes are.
//
// Order matters and is the fail-safe one: a standing Position that says the release is not
// affected or that the risk is accepted answers first, because that is the human's answer;
// then the machine's — every active occurrence cleared is `fixed`; any occurrence open is open,
// with or without a known fix; and a Finding with no active component matches nothing.
func WatchStateOf(f Finding, fixKnown bool) WatchState {
	if pos, ok := f.CurrentPosition(); ok {
		switch pos.Stance() {
		case StanceNotAffected:
			return WatchNotAffected
		case StanceAcceptedRisk, StanceMitigated, StanceDeferred:
			return WatchAccepted
		}
	}
	comps := f.ActiveComponents()
	if len(comps) == 0 {
		return WatchNotAffected
	}
	open := false
	for _, c := range comps {
		if c.VerdictIsOpen() {
			open = true
			break
		}
	}
	if !open {
		return WatchFixed
	}
	if fixKnown {
		return WatchOpenFixAvailable
	}
	return WatchOpenNoFix
}

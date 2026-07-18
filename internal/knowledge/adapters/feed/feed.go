// Package feed holds the Knowledge context's feed anti-corruption layers (D6 ·
// BCK-0052): one ACL per external source (NVD, OSV, Red Hat, EPSS/KEV, ExploitDB,
// vendor VEX) that translates the source's raw dialect into common domain Proposals,
// typed by kind. External shapes never leak past this package — the domain only ever
// sees a Proposal. Adding a source is one new ACL plus a registry entry. The package
// is pure translation (no I/O); the feed clients that fetch bytes are wired in later.
package feed

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Translated pairs a canonical CVE with a Proposal produced from a feed record. The
// CVE is the Faultline's binding key (the app finds-or-creates the card); the Proposal
// carries the source's claim.
type Translated struct {
	CVE      value.CVEID
	Proposal domain.Proposal
}

// ACL is one feed's anti-corruption layer: it names its source and translates the
// source's raw dialect bytes into common domain Proposals.
type ACL interface {
	Source() string
	Translate(raw []byte) ([]Translated, error)
}

// UnsupportedSourceError is the helpful rejection returned for an unknown feed source.
type UnsupportedSourceError struct {
	Requested string
	Supported []string
}

func (e *UnsupportedSourceError) Error() string {
	return fmt.Sprintf("feed: unsupported source %q; supported: %s", e.Requested, strings.Join(e.Supported, ", "))
}

// Registry routes raw feed bytes to the right ACL. It is the reusable, extensible
// boundary: adding a feed is one new ACL registered here.
type Registry struct {
	acls map[string]ACL
}

// NewRegistry builds the default registry with all standard feed ACLs.
func NewRegistry() *Registry {
	r := &Registry{acls: map[string]ACL{}}
	for _, a := range []ACL{
		nvdACL{}, osvACL{}, redhatACL{}, epssKevACL{}, exploitDBACL{}, vexACL{},
	} {
		r.acls[a.Source()] = a
	}
	return r
}

// Sources lists the registered feed sources, sorted for stable messages.
func (r *Registry) Sources() []string {
	out := make([]string, 0, len(r.acls))
	for s := range r.acls {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Translate routes raw bytes for a named source through its ACL. An unknown source
// yields an *UnsupportedSourceError (a helpful rejection).
func (r *Registry) Translate(source string, raw []byte) ([]Translated, error) {
	a, ok := r.acls[source]
	if !ok {
		return nil, &UnsupportedSourceError{Requested: source, Supported: r.Sources()}
	}
	return a.Translate(raw)
}

// --- shared helpers --------------------------------------------------------

// firstCVE returns the first candidate that normalizes to a canonical CVE (folding
// distro aliases). Feeds such as OSV carry the CVE as an alias of a GHSA id.
func firstCVE(candidates ...string) (value.CVEID, error) {
	for _, c := range candidates {
		if cve, err := value.NewCVEID(c); err == nil {
			return cve, nil
		}
	}
	return value.CVEID{}, fmt.Errorf("feed: no canonical CVE among %v", candidates)
}

// parseObserved parses the feed record's observation timestamp (RFC 3339). A feed
// record must carry when it was observed so the Proposal is explainable + reconcilable.
func parseObserved(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, fmt.Errorf("feed: missing observed_at")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("feed: invalid observed_at %q: %w", s, err)
	}
	return t, nil
}

// severityFrom resolves a feed's severity: a recognized label wins; otherwise the band
// is derived from the CVSS base score.
func severityFrom(label string, cvss value.CVSS) value.Severity {
	if s := value.ParseSeverity(label); s != value.SeverityUnknown {
		return s
	}
	return cvss.Severity()
}

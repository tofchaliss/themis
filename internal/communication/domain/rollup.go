package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Release-scoped VEX rollup (EDR-COMMUNICATION-01 D13, COMM-VEX-1): ONE multi-statement
// document covering every finding on a release — the shape every vendor VEX feed Themis
// consumes has, and the document a customer actually asks for. The materialization here is
// pure and deterministic like D3's per-Position transform: same product identity + same
// as-of + same entries ⇒ identical artifact.
//
// The constitutional rule (D13.1): only POSITIONS speak. A finding without one — including a
// finding whose every occurrence a vendor-fix verdict cleared — is `under_investigation`,
// with the machine's knowledge carried as ANNOTATIONS beside the statement, never as the
// statement itself. Communication re-presents; it never becomes the first place a machine
// conclusion turns into an enterprise assertion.

var (
	errIncompleteProduct = errors.New("communication: rollup product identity incomplete (D13.4 fail-closed — a customer document whose product line is a UUID is not degraded, it is useless)")
	errZeroAsOf          = errors.New("communication: rollup as-of time is zero")
	errEmptyRollupEntry  = errors.New("communication: rollup entry missing finding id or cve")

	// ErrRollupNotFound is returned by stores when no rollup publication matches.
	ErrRollupNotFound = errors.New("communication: rollup publication not found")
)

// RollupProductRef is the release's customer-facing identity (D13.4), built from Registry's
// name chain. The internal ReleaseID rides as a reference, never as the product line.
type RollupProductRef struct {
	Product   string
	Project   string
	Version   string
	ReleaseID string
}

// Complete reports whether every half of the identity is present — the D13.4 fail-closed
// gate: no name chain, no document.
func (r RollupProductRef) Complete() bool {
	return r.Product != "" && r.Project != "" && r.Version != "" && r.ReleaseID != ""
}

// PURL renders the deterministic product identifier a consumer's tooling can match
// (`pkg:generic/<product>/<project>@<version>`).
func (r RollupProductRef) PURL() string {
	return "pkg:generic/" + r.Product + "/" + r.Project + "@" + r.Version
}

// RollupEntry is one finding's slice of the release posture, as the app assembled it from
// the Governance projection.
type RollupEntry struct {
	FindingID   string
	FaultlineID string
	CVE         string
	// HasPosition + Stance/PositionVersion/Rationale: the decided half. Only these entries
	// SPEAK (D13.1); Stance must be valid when HasPosition.
	HasPosition     bool
	Stance          Stance
	PositionVersion int
	Rationale       string
	// OpenComponents are the live carrier purls — the statement's subcomponents. Cleared
	// copies never appear here (they live in Annotations), so the subcomponent list and the
	// assertion always agree (D13.4).
	OpenComponents []string
	// Annotations size the nuance without asserting (D13.1/D13.3): a clearance's stated
	// premise, a scope-only note. Rendered beside the statement, never as its status.
	Annotations []string
}

// RollupStatement is one materialized statement of the document.
type RollupStatement struct {
	CVE           string
	FindingID     string
	Status        string // VEX vocabulary: the Position's status, or under_investigation
	Rationale     string // the Position's rationale; empty when nothing was decided
	Annotations   []string
	Subcomponents []string
}

// RollupInputRecord is one line of the recorded input set (D13.2) — what makes the
// snapshot's staleness EXACTLY computable: stale ⇔ the current inputs differ from these.
type RollupInputRecord struct {
	FindingID       string `json:"finding_id"`
	PositionVersion int    `json:"position_version"`
	// Fingerprint hashes the annotation-level inputs (annotations + open components), so
	// annotation-only drift is detectable and distinguishable from a decision change.
	Fingerprint string `json:"fingerprint"`
}

// RollupArtifact is the abstract materialized document a serializer renders.
type RollupArtifact struct {
	Product           RollupProductRef
	AsOf              time.Time
	Statements        []RollupStatement
	WithdrawnExcluded int
	InputSet          []RollupInputRecord
}

// MaterializeRollup is the pure release-scoped transform (D13): posture entries + identity +
// as-of → the multi-statement artifact with its recorded input set. Deterministic — entries
// are sorted (CVE, then FindingID), and the as-of is an INPUT precisely so regeneration from
// a recorded snapshot reproduces identical bytes (D3's regenerability, carried over).
func MaterializeRollup(product RollupProductRef, asOf time.Time, entries []RollupEntry, withdrawnExcluded int) (RollupArtifact, error) {
	if !product.Complete() {
		return RollupArtifact{}, errIncompleteProduct
	}
	if asOf.IsZero() {
		return RollupArtifact{}, errZeroAsOf
	}
	sorted := append([]RollupEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CVE != sorted[j].CVE {
			return sorted[i].CVE < sorted[j].CVE
		}
		return sorted[i].FindingID < sorted[j].FindingID
	})

	art := RollupArtifact{Product: product, AsOf: asOf.UTC(), WithdrawnExcluded: withdrawnExcluded}
	for _, e := range sorted {
		if e.FindingID == "" || e.CVE == "" {
			return RollupArtifact{}, errEmptyRollupEntry
		}
		status := "under_investigation"
		rationale := ""
		if e.HasPosition {
			if !e.Stance.Valid() {
				return RollupArtifact{}, errInvalidStance
			}
			status = e.Stance.VEXStatus() // the D3 stance mapping, reused verbatim
			rationale = e.Rationale
		}
		art.Statements = append(art.Statements, RollupStatement{
			CVE: e.CVE, FindingID: e.FindingID, Status: status, Rationale: rationale,
			Annotations:   append([]string(nil), e.Annotations...),
			Subcomponents: append([]string(nil), e.OpenComponents...),
		})
		art.InputSet = append(art.InputSet, RollupInputRecord{
			FindingID:       e.FindingID,
			PositionVersion: e.PositionVersion,
			Fingerprint:     rollupFingerprint(e),
		})
	}
	return art, nil
}

// rollupFingerprint hashes an entry's annotation-level inputs. Sorted copies, so the hash
// is order-independent for inputs whose order carries no meaning.
func rollupFingerprint(e RollupEntry) string {
	ann := append([]string(nil), e.Annotations...)
	sort.Strings(ann)
	open := append([]string(nil), e.OpenComponents...)
	sort.Strings(open)
	sum := sha256.Sum256([]byte(strings.Join(ann, "\x00") + "\x01" + strings.Join(open, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

// RollupDrift is the computed difference between a recorded input set and the current one
// (D13.2): the three kinds of change, counted, so "stale" always says HOW.
type RollupDrift struct {
	ChangedDecisions int // a finding's position version moved (incl. gaining its first)
	NewFindings      int // findings in the current set the snapshot never saw
	RemovedFindings  int // findings the snapshot covered that are gone
	AnnotationOnly   int // same decision, different annotation fingerprint (minor drift)
}

// Stale reports whether any drift at all exists.
func (d RollupDrift) Stale() bool {
	return d.ChangedDecisions+d.NewFindings+d.RemovedFindings+d.AnnotationOnly > 0
}

// String renders the worklist row's plain-language summary.
func (d RollupDrift) String() string {
	if !d.Stale() {
		return "current"
	}
	parts := make([]string, 0, 4)
	if d.ChangedDecisions > 0 {
		parts = append(parts, fmt.Sprintf("%d changed decision(s)", d.ChangedDecisions))
	}
	if d.NewFindings > 0 {
		parts = append(parts, fmt.Sprintf("%d new finding(s)", d.NewFindings))
	}
	if d.RemovedFindings > 0 {
		parts = append(parts, fmt.Sprintf("%d removed finding(s)", d.RemovedFindings))
	}
	if d.AnnotationOnly > 0 {
		parts = append(parts, fmt.Sprintf("%d annotation-only change(s)", d.AnnotationOnly))
	}
	return "STALE: " + strings.Join(parts, ", ")
}

// ComputeRollupDrift diffs a recorded input set against the current entries. Pure; the app
// feeds it the same posture read a fresh rollup would use, so a diff of zero means a
// republish would reproduce the recorded document's assertions.
func ComputeRollupDrift(recorded []RollupInputRecord, current []RollupEntry) RollupDrift {
	rec := make(map[string]RollupInputRecord, len(recorded))
	for _, r := range recorded {
		rec[r.FindingID] = r
	}
	var d RollupDrift
	seen := make(map[string]bool, len(current))
	for _, e := range current {
		seen[e.FindingID] = true
		r, ok := rec[e.FindingID]
		if !ok {
			d.NewFindings++
			continue
		}
		switch {
		case r.PositionVersion != e.PositionVersion:
			d.ChangedDecisions++
		case r.Fingerprint != rollupFingerprint(e):
			d.AnnotationOnly++
		}
	}
	for id := range rec {
		if !seen[id] {
			d.RemovedFindings++
		}
	}
	return d
}

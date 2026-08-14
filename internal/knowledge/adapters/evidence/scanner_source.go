package evidence

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// ScannerSource implements app.ScannerReportSource (KN-SCAN-1): it reads a scanner-report
// document from Evidence's read API — the same GetDocument the VEX door uses — and
// translates each finding through the scanner feed ACL. This is the seam whose absence made
// scanner uploads a silent no-op: the service and the ACL both existed; nothing connected
// them to a document.
type ScannerSource struct {
	docs *Client
	acl  *feed.Registry
}

// NewScannerSource builds the source over the shared Evidence client and the feed registry
// (which owns the scanner ACL — the single place scanner facts are interpreted).
func NewScannerSource(docs *Client, acl *feed.Registry) *ScannerSource {
	return &ScannerSource{docs: docs, acl: acl}
}

// scannerReportDoc is the curated report envelope (design.md): findings are kept as raw
// JSON so each can be handed VERBATIM to the scanner ACL — the record fields belong to the
// ACL's vocabulary, and re-declaring them here would create a second interpretation of
// scanner facts that could drift from the first.
type scannerReportDoc struct {
	Findings []json.RawMessage `json:"findings"`
}

// findingComponent is the half of a finding the ACL deliberately does not know: WHICH
// component the scanner matched, and WHICH ENGINE said so. The ACL translates what the
// flaw IS; the component and the engine name are match context, so they are parsed here
// where matches are being prepared (KN-SCAN-2 — before this, the record's `scanner` field
// was accepted and dropped, so two engines' reports were indistinguishable downstream).
type findingComponent struct {
	Scanner   string `json:"scanner"`
	Component struct {
		PURL      string `json:"purl"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		Source    string `json:"source"`
	} `json:"component"`
}

// ScannerProposals fetches and translates one report. Per-finding failures — a malformed
// record, no canonical CVE, a finding naming no component — are SKIPPED and counted, never
// fatal: one bad finding must not void a 400-finding report, and the count keeps the gap
// visible in the caller's log line. Only document-level failures (unreachable Evidence, a
// mis-routed evidence id of another kind, an unparseable envelope) abort.
func (s *ScannerSource) ScannerProposals(ctx context.Context, evidenceID string) ([]app.ScannerProposal, int, error) {
	raw, kind, err := s.docs.GetDocument(ctx, evidenceID)
	if err != nil {
		return nil, 0, err
	}
	if kind != "scanner-report" {
		return nil, 0, fmt.Errorf("evidence: document %s is kind %q, not a scanner-report", evidenceID, kind)
	}
	var doc scannerReportDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("evidence: scanner-report %s: invalid envelope: %w", evidenceID, err)
	}
	props := make([]app.ScannerProposal, 0, len(doc.Findings))
	skipped := 0
	for _, f := range doc.Findings {
		translated, terr := s.acl.Translate("scanner", f)
		if terr != nil || len(translated) == 0 {
			skipped++
			continue
		}
		var fc findingComponent
		// The envelope guarantees f is valid JSON (the ACL just parsed it), so the only
		// skippable outcome here is a finding that names no component — which cannot be
		// matched, and a proposal without its match would enrich a card while hiding WHERE
		// the scanner saw it.
		_ = json.Unmarshal(f, &fc)
		if fc.Component.PURL == "" && fc.Component.Name == "" {
			skipped++
			continue
		}
		origin := "scanner"
		if fc.Scanner != "" {
			origin = "scanner/" + fc.Scanner
		}
		props = append(props, app.ScannerProposal{
			CVE:      translated[0].CVE,
			Proposal: translated[0].Proposal,
			Component: app.InventoryComponent{
				PURL: fc.Component.PURL, Name: fc.Component.Name, Version: fc.Component.Version,
				Ecosystem: fc.Component.Ecosystem, Source: fc.Component.Source,
			},
			Origin: origin,
		})
	}
	return props, skipped, nil
}

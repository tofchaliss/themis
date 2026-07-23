//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// logCard prints a Faultline's observable state — run with `-v` to watch it change.
func logCard(t *testing.T, label string, f domain.Faultline) {
	t.Helper()
	v := f.View()
	t.Logf("  [%-14s] id=%s cve=%s stage=%-10s | severity=%-8s source=%-6q kev=%v exploit=%v | version=%d proposals=%d",
		label, f.ID(), f.CVE(), f.Stage(), v.Severity, v.SeveritySource, v.KEV, v.ExploitPublic, f.Version(), len(f.Proposals()))
}

// TestFaultlineLifecycleDemo is an executable walkthrough of the Faultline concept
// (run: `go test -run TestFaultlineLifecycleDemo -v ./internal/knowledge/adapters/store/`).
// It exercises the real aggregate + Postgres store to show, step by step, how a card is
// created, changed/updated (by folding source Proposals through deterministic
// reconciliation), correlated, listed, and finally superseded (never deleted) — and which
// events each transition emits for downstream Governance.
func TestFaultlineLifecycleDemo(t *testing.T) {
	pool := newPool(t) // skips if embedded Postgres is unavailable
	ctx := context.Background()
	svc := service(pool) // precedence: redhat > nvd > osv
	st := store.New(pool)
	cve := cveID(t, "CVE-2024-9999")

	t.Log("STEP 1 — first source Proposal (NVD, high): the card is CREATED and ENRICHED.")
	id, err := svc.FoldProposal(ctx, cve, vulnFacts(t, "nvd", value.SeverityHigh, ">=1.0,<3.0"))
	if err != nil {
		t.Fatal(err)
	}
	card, _, _ := st.GetByCVE(ctx, cve.String())
	logCard(t, "after NVD", card)
	if card.Stage() != domain.StageEnriched || card.View().Severity != value.SeverityHigh {
		t.Fatalf("want enriched/high, got %s/%s", card.Stage(), card.View().Severity)
	}
	if id != card.ID() {
		t.Fatalf("identity is the card's own id (never the CVE): %s vs %s", id, card.ID())
	}

	t.Log("STEP 2 — higher-authority source (Red Hat, critical): the enterprise view CHANGES (headline flips).")
	if _, err := svc.FoldProposal(ctx, cve, vulnFacts(t, "redhat", value.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	card, _, _ = st.GetByCVE(ctx, cve.String())
	logCard(t, "after RedHat", card)
	if card.View().Severity != value.SeverityCritical || card.View().SeveritySource != "redhat" {
		t.Fatalf("reconciliation should pick redhat/critical, got %s/%s", card.View().Severity, card.View().SeveritySource)
	}

	t.Log("STEP 3 — lower-authority source (OSV, low): appended, but the headline does NOT change (deterministic precedence).")
	if _, err := svc.FoldProposal(ctx, cve, vulnFacts(t, "osv", value.SeverityLow)); err != nil {
		t.Fatal(err)
	}
	card, _, _ = st.GetByCVE(ctx, cve.String())
	logCard(t, "after OSV", card)
	if card.View().Severity != value.SeverityCritical {
		t.Fatalf("headline must not regress from a lower-authority source: %s", card.View().Severity)
	}
	if len(card.Proposals()) != 3 {
		t.Fatalf("append-only: want 3 recorded proposals, got %d", len(card.Proposals()))
	}

	t.Log("STEP 4 — correlation: a release component matches the card → stage advances to CORRELATED + ComponentMatched.")
	matched, err := st.RecordMatch(ctx, app.Match{
		ReleaseID: "rel-1", FaultlineID: id, CVE: cve.String(),
		Component:  app.InventoryComponent{PURL: "pkg:pypi/foo@2.0", Name: "foo", Version: "2.0", Ecosystem: "PyPI"},
		OccurredAt: time.Now(),
	})
	if err != nil || !matched {
		t.Fatalf("record match: matched=%v err=%v", matched, err)
	}
	card, _ = st.GetByID(ctx, id)
	logCard(t, "after match", card)
	if card.Stage() != domain.StageCorrelated {
		t.Fatalf("want correlated, got %s", card.Stage())
	}

	t.Log("STEP 5 — LISTING / identify: by-CVE and by-id resolve the same card; affected-releases is a projection.")
	byCVE, found, _ := st.GetByCVE(ctx, cve.String())
	byID, _ := st.GetByID(ctx, id)
	if !found || byCVE.ID() != byID.ID() {
		t.Fatal("GetByCVE and GetByID must resolve the same card")
	}
	releases, _ := st.AffectedReleases(ctx, string(id))
	t.Logf("  GetByCVE(%s) == GetByID(%s) == card %s ; AffectedReleases = %v", cve, id, id, releases)

	t.Log("STEP 6 — supersede (the closest thing to DELETE): CVE withdrawn → terminal SUPERSEDED, still persisted.")
	fresh, _ := st.GetByID(ctx, id)
	prev := fresh.Version()
	if !fresh.Supersede() {
		t.Fatal("supersede should change the stage")
	}
	now := time.Now().UTC()
	notes := []app.OutboxNote{{EventType: app.EventFaultlineSuperseded, Event: domain.NewFaultlineSuperseded(fresh, now), OccurredAt: now}}
	if err := st.Save(ctx, fresh, false, prev, notes); err != nil {
		t.Fatal(err)
	}
	superseded, stillThere, _ := st.GetByCVE(ctx, cve.String())
	logCard(t, "after supersede", superseded)
	if !stillThere {
		t.Fatal("a superseded card is NEVER deleted — it must still be readable (audit)")
	}
	if superseded.Stage() != domain.StageSuperseded {
		t.Fatalf("want superseded, got %s", superseded.Stage())
	}

	t.Log("STEP 7 — events emitted to the outbox (what downstream Governance consumes):")
	rows, err := pool.Query(ctx, "SELECT event_type, count(*) FROM knowledge_outbox GROUP BY 1 ORDER BY 1")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var et string
		var n int
		if err := rows.Scan(&et, &n); err != nil {
			t.Fatal(err)
		}
		t.Logf("  %-34s x%d", et, n)
	}
}

// TestFaultlineReuseAcrossSBOMs demonstrates the core Faultline guarantee: one enterprise
// card per canonical CVE, REUSED from history when the same CVE shows up in a later SBOM —
// even reported as a distro alias, on a different component, in a different release. The
// card is never duplicated; matches and source-Proposal history accumulate on the single
// card, and its reconciled view reflects every source.
// Run: `go test -tags=integration -run TestFaultlineReuseAcrossSBOMs -v ./internal/knowledge/adapters/store/`.
func TestFaultlineReuseAcrossSBOMs(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	svc := service(pool) // one service → find-or-create by CVE
	st := store.New(pool)

	t.Log("SBOM #1 (release rel-A): first sighting of CVE-2024-9999 on foo → a NEW card is created.")
	cve1 := cveID(t, "CVE-2024-9999")
	id1, err := svc.FoldProposal(ctx, cve1, vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordMatch(ctx, app.Match{ReleaseID: "rel-A", FaultlineID: id1, CVE: cve1.String(),
		Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1.0"}, OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	t.Logf("  created card id=%s for %s (release rel-A)", id1, cve1)

	t.Log("SBOM #2 (release rel-B): the SAME CVE arrives as distro alias 'ALPINE-CVE-2024-9999' on a different component.")
	cve2 := cveID(t, "ALPINE-CVE-2024-9999") // normalizes to the same canonical CVE
	t.Logf("  'ALPINE-CVE-2024-9999' normalizes to canonical %s (== SBOM #1's CVE)", cve2)
	id2, err := svc.FoldProposal(ctx, cve2, vulnFacts(t, "redhat", value.SeverityCritical))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordMatch(ctx, app.Match{ReleaseID: "rel-B", FaultlineID: id2, CVE: cve2.String(),
		Component: app.InventoryComponent{PURL: "pkg:apk/alpine/bar@2.0"}, OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// --- the payoff: the second SBOM REUSES the first card, from history ---
	if id1 != id2 {
		t.Fatalf("a duplicate CVE must REUSE the existing card; got two ids %s vs %s", id1, id2)
	}
	t.Logf("  SBOM #2 REUSED card id=%s — not a new card", id2)

	if cards := count(t, pool, "SELECT count(*) FROM faultlines WHERE cve=$1", "CVE-2024-9999"); cards != 1 {
		t.Fatalf("exactly one Faultline per canonical CVE across all SBOMs; got %d", cards)
	}

	card, _, _ := st.GetByCVE(ctx, "CVE-2024-9999")
	t.Logf("  the ONE card now holds %d source Proposals (history accumulated from both SBOMs)", len(card.Proposals()))
	if len(card.Proposals()) != 2 {
		t.Fatalf("both SBOMs' proposals should accumulate on the card; got %d", len(card.Proposals()))
	}
	if card.View().Severity != value.SeverityCritical || card.View().SeveritySource != "redhat" {
		t.Fatalf("the shared view reconciles BOTH sources; want critical/redhat, got %s/%s", card.View().Severity, card.View().SeveritySource)
	}
	releases, _ := st.AffectedReleases(ctx, string(id1))
	t.Logf("  AffectedReleases(%s) = %v — one card, both releases", id1, releases)
	if len(releases) != 2 {
		t.Fatalf("the shared card must link BOTH releases; got %v", releases)
	}

	t.Log("Re-scan of SBOM #2 (same facts re-delivered): the card is not duplicated, the match is idempotent, the view converges.")
	if _, err := svc.FoldProposal(ctx, cve2, vulnFacts(t, "redhat", value.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	dup, err := st.RecordMatch(ctx, app.Match{ReleaseID: "rel-B", FaultlineID: id1, CVE: "CVE-2024-9999",
		Component: app.InventoryComponent{PURL: "pkg:apk/alpine/bar@2.0"}, OccurredAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if dup {
		t.Fatal("re-recording the same (release, faultline, component) match must be idempotent")
	}
	if cards := count(t, pool, "SELECT count(*) FROM faultlines WHERE cve=$1", "CVE-2024-9999"); cards != 1 {
		t.Fatalf("still exactly one card after a re-scan; got %d", cards)
	}
	after, _, _ := st.GetByCVE(ctx, "CVE-2024-9999")
	if after.View().Severity != value.SeverityCritical {
		t.Fatalf("view must converge unchanged on re-delivery; got %s", after.View().Severity)
	}
	t.Logf("  after re-scan: cards=1, match idempotent (no new match), view still critical; "+
		"proposals=%d (append-only audit trail records the re-observation)", len(after.Proposals()))
}

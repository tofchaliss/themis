//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// The trust class MUST survive persistence. The aggregate is reloaded before every
// decision, so a class that failed to round-trip would come back unset, read as Inferred
// under value.MaxTrust, and silently bar a proposal from a policy that accepted it before.
// The Knowledge-side equivalent of this bug (the view DTO dropping three fields) shipped
// far enough to fire a duplicate event on every fold before a test caught it.
func TestProposalEvidenceTrustRoundTrips(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	epoch := time.Unix(1_700_000_000, 0).UTC()

	for _, class := range []value.TrustClass{value.TrustObserved, value.TrustAsserted, value.TrustInferred} {
		t.Run(string(class), func(t *testing.T) {
			id := domain.FindingID("fnd-" + string(class))
			f, err := domain.NewFinding(id, "rel-"+string(class), "fl-1", "CVE-2024-1")
			if err != nil {
				t.Fatalf("new finding: %v", err)
			}
			p, err := domain.NewGovernanceProposal(
				domain.ProposalID("p-"+string(class)),
				domain.Actor{Kind: domain.ActorSystem, ID: "rule"},
				domain.StanceNotAffected, "because", epoch, class,
			)
			if err != nil {
				t.Fatalf("new proposal: %v", err)
			}
			if err := f.RaiseProposal(p); err != nil {
				t.Fatalf("raise: %v", err)
			}
			if err := st.Save(ctx, f, true, 0, nil); err != nil {
				t.Fatalf("save: %v", err)
			}

			got, err := st.GetByID(ctx, id)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if len(got.Proposals()) != 1 {
				t.Fatalf("proposals = %d, want 1", len(got.Proposals()))
			}
			if reloaded := got.Proposals()[0].EvidenceTrust(); reloaded != class {
				t.Fatalf("EvidenceTrust after reload = %q, want %q", reloaded, class)
			}
			// The constitutional verdict must be identical before and after a round trip —
			// that is the property the persistence exists to protect.
			if before, after := domain.ConstitutionallyAutoAcceptable(p),
				domain.ConstitutionallyAutoAcceptable(got.Proposals()[0]); before != after {
				t.Fatalf("constitutional verdict changed across persistence: %v -> %v", before, after)
			}
		})
	}
}

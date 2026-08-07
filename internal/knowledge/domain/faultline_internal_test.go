package domain

import (
	"testing"
	"time"
)

// sameContentAs is the dedup's safety valve (KN-PROPOSAL-BLOAT-1). Its rule is asymmetric on
// purpose: a dropped observation is unrecoverable, a duplicate is merely waste — so anything it
// cannot PROVE identical must compare as different.
//
// The mixed/empty-payload cases are unreachable through FoldProposal, because repeatsLatestFrom
// filters on kind first and a kind determines the payload. They are exercised here directly so
// the guarantee is tested rather than assumed: if a future kind is added and the switch is not
// extended, this is what keeps the fallthrough safe instead of silently collapsing proposals.
func TestSameContentAs_UnprovableIsAlwaysDifferent(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	sig, err := NewExploitSignalProposal("epsskev", at, ExploitSignal{EPSS: 0.27})
	if err != nil {
		t.Fatalf("signal: %v", err)
	}
	empty := Proposal{source: "epsskev", observedAt: at, kind: ProposalKind("future-kind")}

	for _, tc := range []struct {
		name string
		a, b Proposal
	}{
		{"a payload-less proposal never matches one with a payload", empty, sig},
		{"nor the other way round", sig, empty},
		{"two payload-less proposals do not match either", empty, empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.a.sameContentAs(tc.b) {
				t.Error("must compare as DIFFERENT — suppressing what cannot be compared loses history")
			}
		})
	}
}

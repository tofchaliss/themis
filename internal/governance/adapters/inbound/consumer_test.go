package inbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/kernel/value"
)

// mkEnv wraps an event type + payload in the kernel Envelope the consumer now handles
// (M5 EB-02). The other envelope fields are transport metadata the ACL does not read.
func mkEnv(typ string, payload []byte) event.Envelope {
	return event.Envelope{Type: typ, Payload: payload}
}

// --- minimal in-memory repo (drives the real FindingService) -------------------------

type memRepo struct {
	lastBand    string
	lastFixes   []app.FixedVersion
	lastSignals domain.ExploitSignals
	byID        map[domain.FindingID]domain.Finding
	order       []domain.FindingID
	baseScores  map[string]int

	lastVerdictRelease   string
	lastVerdictFaultline string
	lastVerdict          domain.MatchedComponent
}

func (r *memRepo) SetBaseScore(_ context.Context, fl string, score int) error {
	if r.baseScores == nil {
		r.baseScores = map[string]int{}
	}
	r.baseScores[fl] = score
	return nil
}

func (r *memRepo) SetSignals(_ context.Context, faultlineID string, sig domain.ExploitSignals) error {
	r.lastSignals = sig
	return nil
}

func (r *memRepo) SetComponentVerdict(_ context.Context, releaseID, faultlineID string, comp domain.MatchedComponent) error {
	r.lastVerdictRelease, r.lastVerdictFaultline, r.lastVerdict = releaseID, faultlineID, comp
	return nil
}

func (r *memRepo) SetBandAndFixes(_ context.Context, findingID, band string, fixes []app.FixedVersion) error {
	r.lastBand = band
	r.lastFixes = fixes
	return nil
}

func newMemRepo() *memRepo { return &memRepo{byID: map[domain.FindingID]domain.Finding{}} }

func (r *memRepo) seed(f domain.Finding) {
	if _, ok := r.byID[f.ID()]; !ok {
		r.order = append(r.order, f.ID())
	}
	r.byID[f.ID()] = f
}

func clone(f domain.Finding) domain.Finding {
	return domain.ReconstituteFinding(f.ID(), f.ReleaseID(), f.FaultlineID(), f.CVE(),
		f.Components(), f.Stage(), f.Proposals(), f.Positions(), f.Version())
}

func (r *memRepo) GetByKey(_ context.Context, rel, fl string) (domain.Finding, bool, error) {
	for _, id := range r.order {
		if f := r.byID[id]; f.ReleaseID() == rel && f.FaultlineID() == fl {
			return clone(f), true, nil
		}
	}
	return domain.Finding{}, false, nil
}

func (r *memRepo) GetByID(_ context.Context, id domain.FindingID) (domain.Finding, error) {
	f, ok := r.byID[id]
	if !ok {
		return domain.Finding{}, errNotFound
	}
	return clone(f), nil
}

func (r *memRepo) FindingsByFaultline(_ context.Context, fl string) ([]domain.FindingID, error) {
	var out []domain.FindingID
	for _, id := range r.order {
		if r.byID[id].FaultlineID() == fl {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *memRepo) Save(_ context.Context, f domain.Finding, _ bool, _ int, _ []app.OutboxNote) error {
	r.seed(f)
	return nil
}

var errNotFound = errNotFoundType("not found")

type errNotFoundType string

func (e errNotFoundType) Error() string { return string(e) }

type ids struct{ n int }

func (g *ids) NewID() string { g.n++; return "id-x" }

type clk struct{}

func (clk) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func consumer(repo *memRepo) *inbound.Consumer {
	svc := app.NewFindingService(repo, &ids{}, clk{})
	return inbound.NewConsumer(app.NewCoordinator(svc))
}

// --- tests ---------------------------------------------------------------------------

func TestConsumer_ComponentMatched(t *testing.T) {
	repo := newMemRepo()
	// A payload shaped like Knowledge's ComponentMatched (PascalCase keys, no json tags).
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2024-1","ReleaseID":"rel-1",
		"Components":[{"PURL":"pkg:apk/openssl@3","Name":"openssl","Version":"3","Ecosystem":"Alpine","DetectionOrigin":"scanner/trivy"}]}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.component_matched", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.order) != 1 {
		t.Fatalf("expected a Finding, got %d", len(repo.order))
	}
	f := repo.byID[repo.order[0]]
	if f.ReleaseID() != "rel-1" || f.FaultlineID() != "fl-1" || len(f.Components()) != 1 || f.Components()[0].PURL != "pkg:apk/openssl@3" {
		t.Errorf("finding = %+v", f)
	}
	// KN-SCAN-2: origin is carried, never re-derived — Governance's answer to "which engine
	// found this" is whatever Knowledge said.
	if f.Components()[0].DetectionOrigin != "scanner/trivy" {
		t.Errorf("detection origin = %q, want scanner/trivy", f.Components()[0].DetectionOrigin)
	}
}

// The verdict rides ComponentMatched additively and the change event dispatches to the
// mirror (EDR-VERDICT-01 D5): Governance stores what Knowledge concluded, verbatim, and
// re-derives nothing.
func TestConsumer_ComponentMatchedCarriesVerdict(t *testing.T) {
	repo := newMemRepo()
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2025-47273","ReleaseID":"rel-1",
		"Components":[{"PURL":"pkg:pypi/setuptools@39.2.0","Name":"setuptools","Version":"39.2.0","Ecosystem":"pypi",
		"VerdictState":"cleared_vendor_fix","VerdictGrade":"observed","VerdictReason":"vendor fix present"}]}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.component_matched", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	c := repo.byID[repo.order[0]].Components()[0]
	if c.VerdictState != "cleared_vendor_fix" || c.VerdictGrade != "observed" || c.VerdictReason != "vendor fix present" {
		t.Errorf("component verdict = %q/%q/%q, want the mirrored clearance", c.VerdictState, c.VerdictGrade, c.VerdictReason)
	}
}

func TestConsumer_ComponentVerdictChanged(t *testing.T) {
	repo := newMemRepo()
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2025-47273","ReleaseID":"rel-1",
		"Component":{"PURL":"pkg:pypi/setuptools@39.2.0","Name":"setuptools","Version":"39.2.0","Ecosystem":"pypi",
		"VerdictState":"cleared_vendor_fix","VerdictGrade":"inferred","VerdictReason":"matched to python-setuptools at the distro version"}}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.component_verdict_changed", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if repo.lastVerdictRelease != "rel-1" || repo.lastVerdictFaultline != "fl-1" {
		t.Errorf("mirror keyed to %s/%s, want rel-1/fl-1", repo.lastVerdictRelease, repo.lastVerdictFaultline)
	}
	if repo.lastVerdict.VerdictState != "cleared_vendor_fix" || repo.lastVerdict.VerdictGrade != "inferred" {
		t.Errorf("mirrored verdict = %+v, want the inferred clearance", repo.lastVerdict)
	}
}

func TestConsumer_FaultlineEnriched(t *testing.T) {
	repo := newMemRepo()
	f, _ := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-1")
	repo.seed(f)
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-1","Severity":"high","KEV":false,"ExploitPublic":false}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.faultline_enriched", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got := repo.byID["fnd-1"]
	if len(got.Proposals()) != 1 || got.Proposals()[0].Stance() != domain.StanceAffected {
		t.Errorf("proposals = %+v", got.Proposals())
	}
}

func TestConsumer_FaultlineEnriched_Applicability(t *testing.T) {
	repo := newMemRepo()
	f, _ := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:rpm/openssl@1.0.2", Name: "openssl"}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	// A vendor not_affected statement on the wire (EDR-VEX-01 D5) is decoded and drives a system
	// not_affected Proposal on the covered Finding (D4). Severity is low, so this is the only one.
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-1","Severity":"low","Applicabilities":[{"Package":"openssl","Status":"not_affected","Justification":"vulnerable_code_not_present"}]}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.faultline_enriched", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got := repo.byID["fnd-1"]
	if len(got.Proposals()) != 1 || got.Proposals()[0].Stance() != domain.StanceNotAffected {
		t.Errorf("proposals = %+v, want one system not_affected", got.Proposals())
	}
}

func TestConsumer_FaultlineSuperseded(t *testing.T) {
	repo := newMemRepo()
	f, _ := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-1")
	repo.seed(f)
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-1"}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.faultline_superseded", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got := repo.byID["fnd-1"]
	if len(got.Proposals()) != 1 || got.Proposals()[0].Stance() != domain.StanceNotAffected {
		t.Errorf("proposals = %+v", got.Proposals())
	}
}

// TRUST-4: the Trust field on the superseded payload must survive the DTO and reach the raised
// proposal's evidence class. Decoding it into a field nothing reads would look identical from
// the outside, so this asserts the value that policy actually gates on.
//
// The empty case is the wire-compatibility contract: an event predating the field must keep
// reading as Observed, or replaying old bus rows would retroactively bar auto-acceptance.
func TestConsumer_FaultlineSupersededCarriesTrustToTheProposal(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		want          value.TrustClass
	}{
		{"asserted rides the wire", `{"FaultlineID":"fl-1","CVE":"CVE-1","Trust":"asserted"}`, value.TrustAsserted},
		{"observed rides the wire", `{"FaultlineID":"fl-1","CVE":"CVE-1","Trust":"observed"}`, value.TrustObserved},
		{"absent falls back to observed", `{"FaultlineID":"fl-1","CVE":"CVE-1"}`, value.TrustObserved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMemRepo()
			f, _ := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-1")
			repo.seed(f)
			if err := consumer(repo).Handle(context.Background(),
				mkEnv("knowledge.faultline_superseded", []byte(tc.payload))); err != nil {
				t.Fatalf("handle: %v", err)
			}
			props := repo.byID["fnd-1"].Proposals()
			if len(props) != 1 {
				t.Fatalf("proposals = %d, want 1", len(props))
			}
			if got := props[0].EvidenceTrust(); got != tc.want {
				t.Errorf("EvidenceTrust = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConsumer_UnknownTypeIgnored(t *testing.T) {
	repo := newMemRepo()
	if err := consumer(repo).Handle(context.Background(), mkEnv("knowledge.something_else", []byte(`{}`))); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if len(repo.order) != 0 {
		t.Error("unknown event must not create a Finding")
	}
}

func TestConsumer_MalformedPayloads(t *testing.T) {
	repo := newMemRepo()
	c := consumer(repo)
	for _, evt := range []string{"knowledge.component_matched", "knowledge.component_verdict_changed", "knowledge.faultline_enriched", "knowledge.faultline_superseded"} {
		if err := c.Handle(context.Background(), mkEnv(evt, []byte("{not json"))); err == nil {
			t.Errorf("%s: malformed payload should error", evt)
		}
	}
}

package store

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// Integration-contract v1 guard (M5 EB-03 / D9 / BCK-0046). Each published event type's
// marshaled payload must satisfy the schema pinned by its schema_ref, so a domain refactor
// that reshapes the wire (rename/retype/drop a field) fails here rather than silently
// breaking a consumer.

//go:embed schemas/*.schema.json
var schemaFS embed.FS

func compileContract(t *testing.T, schemaRef string) *jsonschema.Schema {
	t.Helper()
	name := schemaRef + ".schema.json"
	raw, err := schemaFS.ReadFile("schemas/" + name)
	if err != nil {
		t.Fatalf("read schema %s: %v", name, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal schema %s: %v", name, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatalf("add resource %s: %v", name, err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return sch
}

func assertValidContract(t *testing.T, schemaRef string, raw []byte) {
	t.Helper()
	sch := compileContract(t, schemaRef)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("payload fails %s:\npayload=%s\nerror=%v", schemaRef, raw, err)
	}
}

func TestIntegrationContractV1_GovernanceEvents(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		eventType string
		event     any
	}{
		{app.EventFindingOpened, domain.FindingOpened{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventFindingResolved, domain.FindingResolved{FindingID: "fnd-1", OccurredAt: now}},
		{app.EventFindingReopened, domain.FindingReopened{FindingID: "fnd-1", OccurredAt: now}},
		{app.EventFindingArchived, domain.FindingArchived{FindingID: "fnd-1", OccurredAt: now}},
		{app.EventProposalRaised, domain.ProposalRaised{FindingID: "fnd-1", ProposalID: "p1", Stance: domain.StanceNotAffected, ProposerKind: domain.ActorAI, OccurredAt: now}},
		{app.EventProposalAccepted, domain.ProposalAccepted{FindingID: "fnd-1", ProposalID: "p1", PositionVersion: 1, OccurredAt: now}},
		{app.EventProposalRejected, domain.ProposalRejected{FindingID: "fnd-1", ProposalID: "p1", OccurredAt: now}},
		{app.EventPositionEstablished, domain.PositionEstablished{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", Version: 1, Stance: domain.StanceAffected, OccurredAt: now}},
		{app.EventPositionRevised, domain.PositionRevised{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", Version: 2, Stance: domain.StanceMitigated, OccurredAt: now}},
		{app.EventFindingCommissioned, domain.FindingCommissioned{FindingID: "fnd-1", CommissionID: "c-1", Skill: "remediate-dependency@4", Anchor: "rsys@6", OccurredAt: now}},
		{app.EventCommissionWithdrawn, domain.CommissionWithdrawn{FindingID: "fnd-1", CommissionID: "c-1", OccurredAt: now}},
		// The one event whose subject is a RELEASE (N-M2b). Zero counts are a legitimate payload
		// and the schema admits them, because they are the success case.
		{app.EventReleaseEvaluated, domain.NewReleaseEvaluated("prod-1", "prj-1", "rel-1", "ev-1", domain.CauseNewSBOM, domain.SeverityCounts{})},
		{app.EventDispositionStale, domain.DispositionStale{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", Stance: string(domain.StanceNotAffected), PositionVersion: 1, Reason: "a public exploit now exists for this CVE", OccurredAt: now}},
		{app.EventSLABreached, domain.SLABreachedEvent{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", Bucket: domain.SLABucketCritical, PeriodStart: now, Due: now.Add(7 * 24 * time.Hour), OccurredAt: now}},
		// EDR-INCIDENT-01 D1: one announcement per release, every optional field set.
		{app.EventFixAvailable, domain.NewFixAvailable("rel-1", []domain.FixAvailableItem{
			{FindingID: "fnd-1", CVE: "CVE-2026-1", Package: "kernel", Ecosystem: "rpm",
				Fixes: []string{"0:4.18.0-553.80.1.el8_10"}, Advisories: []string{"RHSA-2026:0001"}},
			{FindingID: "", CVE: "CVE-2026-2", Package: "openssl", Ecosystem: "rpm", Fixes: []string{"1:1.1.1k-14.el8_6"}},
		}, now)},
		// EDR-REBUILD-01 step R2 part 2: the two rebuild events carry one decision shape.
		{app.EventRebuildRecommended, contractRebuildDecision(domain.RebuildOutcomeRecommend, now)},
		{app.EventRebuildRequested, contractRebuildDecision(domain.RebuildOutcomeRequest, now)},
		{app.EventReviewDueSoon, domain.ReviewDueSoon{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", Stance: string(domain.StanceAcceptedRisk), PositionVersion: 2, ReviewBy: now.Add(24 * time.Hour), Owner: "risk-owner@example.test", OccurredAt: now}},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			raw, err := json.Marshal(tc.event)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.eventType, err)
			}
			assertValidContract(t, schemaRefFor(tc.eventType), raw)
		})
	}

	if len(cases) != len(schemaRefByEventType) {
		t.Errorf("cases=%d but schemaRefByEventType=%d; freeze every published event type", len(cases), len(schemaRefByEventType))
	}
	files, err := schemaFS.ReadDir("schemas")
	if err != nil {
		t.Fatalf("read schemas dir: %v", err)
	}
	if len(files) != len(schemaRefByEventType) {
		t.Errorf("schema files=%d but frozen event types=%d", len(files), len(schemaRefByEventType))
	}
}

func TestSchemaRefFor_UnmappedFallsBackToRawType(t *testing.T) {
	if got := schemaRefFor("governance.unknown_event"); got != "governance.unknown_event" {
		t.Errorf("unmapped schemaRefFor = %q, want raw type", got)
	}
}

// EDR-REMEDIATION-01 D3: the additive upload_outcome object validates against the frozen v1
// schema, with and without its CVE lists, and its absence still validates (older payloads).
func TestIntegrationContractV1_ReleaseEvaluatedUploadOutcome(t *testing.T) {
	ev := domain.NewReleaseEvaluated("prod-1", "prj-1", "rel-1", "ev-2", domain.CauseNewSBOM, domain.SeverityCounts{High: 2})
	ev.UploadOutcome = &domain.UploadOutcome{New: 1, Reappeared: 0, NoLongerPresent: 3, Unchanged: 7, NotJudged: 1,
		NewCVEs: []string{"CVE-2026-1"}, GoneCVEs: []string{"CVE-2025-1", "CVE-2025-2", "CVE-2025-3"}, HasBaseline: true}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	assertValidContract(t, schemaRefFor(app.EventReleaseEvaluated), raw)
	ev.UploadOutcome = &domain.UploadOutcome{}
	raw, _ = json.Marshal(ev)
	assertValidContract(t, schemaRefFor(app.EventReleaseEvaluated), raw)
}

// contractRebuildDecision is a decision with every field set, for the two rebuild contracts.
func contractRebuildDecision(outcome string, at time.Time) domain.RebuildDecision {
	mode := string(domain.RebuildModeAsk)
	if outcome == domain.RebuildOutcomeRequest {
		mode = string(domain.RebuildModeAuto)
	}
	entry := domain.RebuildDecisionEntry{
		FindingID: "fnd-1", CVE: "CVE-2026-1", PURL: "pkg:rpm/example/libexample@1.0-1.el8",
		CurrentVersion: "1.0-1.el8", FixedVersions: []string{"0:1.0-2.el8_10"}, FixSource: app.RebuildFixSourceVerdict,
		Severity: domain.SLABucketHigh, Score: 75, ScoreSource: app.RebuildScoreSourceBase,
		ClaimClass: "carrier", Position: "none", AssessmentState: app.RebuildAssessmentNotAssessed,
		CountedBecause: []string{"severity_floor"},
	}
	d := domain.RebuildDecision{
		DecisionID: "dec-1", ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "prj-1",
		TriggerID: "evt-1", TriggerSource: "governance", TriggerType: domain.RebuildTriggerFixAvailable,
		Outcome: outcome, EffectiveMode: mode, EffectiveModeSetBy: "tag", InstallationMode: mode,
		Tag: "rebuild:" + mode, TagLevel: "release",
		Policy: domain.RebuildDecisionPolicy{ScopeKind: "installation", Version: 0, FixRequired: true,
			SeverityFloor: domain.SLABucketHigh, CountKnownExploited: true, SkipDecided: true, CarrierOnly: true,
			CoolDownSeconds: 86400, Mode: mode},
		Considered: 3, Skipped: map[string]int{domain.RebuildSkippedBelowFloor: 1},
		Targeted: []domain.RebuildDecisionEntry{entry}, OtherStream: []domain.RebuildDecisionEntry{entry},
		DecidedAt: at,
	}
	d.Build = json.RawMessage(`{"job":"team/build-image","parameters":{"BRANCH":"release/1"}}`)
	d.BuildProfile = &domain.RebuildDecisionBuildProfile{Scope: "project", Revision: 2, SHA256: "ab12"}
	if outcome == domain.RebuildOutcomeRecommend {
		d.RecommendReason = domain.RebuildRecommendModeAsk
	}
	return d
}

// D10 item 6: a recommendation held by a missing build profile carries no profile; a request
// without one does not satisfy the contract.
func TestIntegrationContractV1_RebuildWithoutBuildProfile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	d := contractRebuildDecision(domain.RebuildOutcomeRecommend, now)
	d.Build, d.BuildProfile, d.RecommendReason = nil, nil, domain.RebuildRecommendNoBuildProfile
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertValidContract(t, schemaRefFor(app.EventRebuildRecommended), raw)

	req := contractRebuildDecision(domain.RebuildOutcomeRequest, now)
	req.Build, req.BuildProfile = nil, nil
	raw, _ = json.Marshal(req)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compileContract(t, schemaRefFor(app.EventRebuildRequested)).Validate(inst); err == nil {
		t.Error("a rebuild request with no build profile must not satisfy the contract")
	}
}

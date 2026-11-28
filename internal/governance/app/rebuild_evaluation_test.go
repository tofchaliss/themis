package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type releaseTags struct {
	levels map[string]app.ReleaseTagLevels
	err    error
}

func (r releaseTags) ReleaseTagLevels(_ context.Context, releaseID string) (app.ReleaseTagLevels, error) {
	return r.levels[releaseID], r.err
}

type rebuildFacts struct {
	rows  []app.RebuildFindingFacts
	asked string
	err   error
}

func (r *rebuildFacts) RebuildFacts(_ context.Context, releaseID string) ([]app.RebuildFindingFacts, error) {
	r.asked = releaseID
	return r.rows, r.err
}

type fixVerdicts struct {
	rows []app.ReleaseFixVerdict
	err  error
}

func (f fixVerdicts) ReleaseFixVerdicts(context.Context, string) ([]app.ReleaseFixVerdict, error) {
	return f.rows, f.err
}

func taggedRelease(tags ...string) releaseTags {
	return releaseTags{levels: map[string]app.ReleaseTagLevels{
		"rel-1": {ProductID: "prod-1", ProjectID: "proj-1", Release: tags},
	}}
}

// D17: with a tag reader the in-force read also answers the effective mode and who set it; the
// tag reader gives the Product, so no second Registry walk is needed.
func TestRebuildPolicyInForceAppliesTags(t *testing.T) {
	ctx := context.Background()
	st := &fakeRebuildPolicyStore{}
	tags := releaseTags{levels: map[string]app.ReleaseTagLevels{
		"rel-1": {ProductID: "prod-1", ProjectID: "proj-1", Release: []string{"rebuild:auto"}},
		"rel-2": {ProductID: "prod-1", ProjectID: "proj-2", Product: []string{"rebuild:off"}, Release: []string{"rebuild:auto"}},
		"rel-3": {ProductID: "prod-2", ProjectID: "proj-3"},
	}}
	svc := app.NewRebuildPolicyService(st, rebuildClock{}).WithTags(tags)
	if _, err := svc.PutInstallation(ctx, policyWith(domain.RebuildModeAuto, domain.SLABucketHigh), "alice"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		release string
		mode    domain.RebuildMode
		setBy   string
		tag     string
		level   string
	}{
		{"rel-1", domain.RebuildModeAuto, domain.RebuildModeSetByInstallation, domain.RebuildTagAuto, domain.RebuildTagLevelRelease},
		{"rel-2", domain.RebuildModeOff, domain.RebuildModeSetByTag, domain.RebuildTagOff, domain.RebuildTagLevelProduct},
		{"rel-3", domain.RebuildModeOff, domain.RebuildModeSetByTag, "", ""},
	}
	for _, c := range cases {
		got, err := svc.InForce(ctx, c.release)
		if err != nil || !got.TagsApplied || got.EffectiveMode != c.mode || got.EffectiveSetBy != c.setBy ||
			got.Tag.Tag != c.tag || got.Tag.Level != c.level || got.ProjectID == "" || got.ProductID == "" {
			t.Errorf("%s: %+v err=%v", c.release, got, err)
		}
	}
	// A tag read that fails, or one that names no Product, is "cannot tell".
	for name, tr := range map[string]releaseTags{"registry down": {err: errors.New("down")}, "blank product": {}} {
		svc := app.NewRebuildPolicyService(st, rebuildClock{}).WithTags(tr)
		if _, err := svc.InForce(ctx, "rel-1"); !errors.Is(err, app.ErrRebuildPolicyIdentityUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func rebuildFixture() *rebuildFacts {
	open := func(purl, version, class string) domain.MatchedComponent {
		return domain.MatchedComponent{PURL: purl, Version: version, ClaimClass: class, VerdictState: "open"}
	}
	return &rebuildFacts{rows: []app.RebuildFindingFacts{
		// Counts: high, open, behind a fix.
		{FindingID: "f1", FaultlineID: "fl-1", CVE: "CVE-2026-0001", Stage: "triage", BaseScore: 80,
			Components: []domain.MatchedComponent{
				open("pkg:rpm/redhat/kernel@4.18.0-1.el8", "4.18.0-1.el8", "carrier"),
				{PURL: "pkg:rpm/redhat/kernel-core@4.18.0-2.el8", Version: "4.18.0-2.el8", VerdictState: "cleared_vendor_fix"},
			}},
		// Low severity but known exploited, owner-set score, no claim class.
		{FindingID: "f2", FaultlineID: "fl-2", CVE: "CVE-2026-0002", Stage: "triage", BaseScore: 20, OwnerSet: true, KnownExploited: true,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/bash@4.4-1.el8", "4.4-1.el8", "")}},
		// Decided away.
		{FindingID: "f3", FaultlineID: "fl-3", CVE: "CVE-2026-0003", Stage: "triage", BaseScore: 95, Stance: domain.StanceNotAffected,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/zlib@1.2-1.el8", "1.2-1.el8", "carrier")}},
		// Knowledge has no row for it: unknown.
		{FindingID: "f4", FaultlineID: "fl-4", CVE: "CVE-2026-0004", Stage: "triage", BaseScore: 95,
			Components: []domain.MatchedComponent{open("pkg:npm/left-pad@1.0.0", "1.0.0", "carrier")}},
		// Compared, nothing published.
		{FindingID: "f5", FaultlineID: "fl-5", CVE: "CVE-2026-0005", Stage: "triage", BaseScore: 95,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/curl@7.61-1.el8", "7.61-1.el8", "carrier")}},
		// A resolved Finding is not looked at.
		{FindingID: "f6", FaultlineID: "fl-6", CVE: "CVE-2026-0006", Stage: domain.StageResolved, BaseScore: 95,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/glibc@2.28-1.el8", "2.28-1.el8", "carrier")}},
		{FindingID: "f7", FaultlineID: "fl-7", CVE: "CVE-2026-0007", Stage: domain.StageArchived, BaseScore: 95,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/glibc@2.28-1.el8", "2.28-1.el8", "carrier")}},
	}}
}

func rebuildFixVerdicts() fixVerdicts {
	return fixVerdicts{rows: []app.ReleaseFixVerdict{
		{FaultlineID: "fl-1", PURL: "pkg:rpm/redhat/kernel@4.18.0-1.el8", Fix: domain.RebuildFixKnown, FixedVersions: []string{"0:4.18.0-2.el8"}},
		{FaultlineID: "fl-2", PURL: "pkg:rpm/redhat/bash@4.4-1.el8", Fix: domain.RebuildFixKnown, FixedVersions: []string{"0:4.4-9.el8"}},
		{FaultlineID: "fl-3", PURL: "pkg:rpm/redhat/zlib@1.2-1.el8", Fix: domain.RebuildFixKnown, FixedVersions: []string{"0:1.2-9.el8"}},
		{FaultlineID: "fl-5", PURL: "pkg:rpm/redhat/curl@7.61-1.el8", Fix: domain.RebuildFixNone},
		{FaultlineID: "fl-6", PURL: "pkg:rpm/redhat/glibc@2.28-1.el8", Fix: domain.RebuildFixKnown, FixedVersions: []string{"0:2.28-9.el8"}},
	}}
}

// Step R2 part 1: the judgement lists what counts and why, says what it left out, and names the
// outcome the effective mode gives. Nothing is stored or sent.
func TestRebuildEvaluation(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 11, 28, 12, 0, 0, 123456789, time.UTC)
	policy := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithTags(taggedRelease("rebuild:auto"))
	facts := rebuildFixture()
	svc := app.NewRebuildEvaluationService(policy, facts, rebuildFixVerdicts(), rebuildClock{at})

	got, err := svc.Evaluate(ctx, " rel-1 ")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Default installation policy is `ask`, the tag says auto: the lowest is ask.
	if got.Outcome != domain.RebuildOutcomeRecommend || got.Policy.EffectiveMode != domain.RebuildModeAsk ||
		facts.asked != "rel-1" || !got.FixVerdictsRead || !got.EvaluatedAt.Equal(at.Truncate(time.Microsecond)) {
		t.Fatalf("judgement = %+v", got)
	}
	if got.Considered != 5 || len(got.Targeted) != 2 {
		t.Fatalf("considered %d targeted %+v", got.Considered, got.Targeted)
	}
	k := got.Targeted[0]
	if k.FindingID != "f1" || k.CurrentVersion != "4.18.0-1.el8" || len(k.FixedVersions) != 1 || k.FixedVersions[0] != "0:4.18.0-2.el8" ||
		k.FixSource != app.RebuildFixSourceVerdict || k.Severity != domain.SLABucketHigh || k.Score != 80 ||
		k.ScoreSource != app.RebuildScoreSourceBase || k.AssessmentState != app.RebuildAssessmentNotAssessed ||
		len(k.CountedBecause) != 1 || k.CountedBecause[0] != domain.RebuildCountedSeverityFloor {
		t.Errorf("kernel entry = %+v", k)
	}
	b := got.Targeted[1]
	if b.FindingID != "f2" || b.ScoreSource != app.RebuildScoreSourceOwner || !b.KnownExploited ||
		len(b.CountedBecause) != 1 || b.CountedBecause[0] != domain.RebuildCountedKnownExploited {
		t.Errorf("bash entry = %+v", b)
	}
	if got.Skipped[domain.RebuildSkippedDecided] != 1 || got.Skipped[domain.RebuildSkippedFixUnknown] != 1 ||
		got.Skipped[domain.RebuildSkippedNoFix] != 1 || len(got.Skipped) != 3 {
		t.Errorf("skipped = %+v", got.Skipped)
	}
}

// The mode decides the outcome; what counts does not change with it.
func TestRebuildEvaluationOutcomeFollowsTheMode(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		installMode domain.RebuildMode
		tags        []string
		want        string
	}{
		{"auto and auto", domain.RebuildModeAuto, []string{"rebuild:auto"}, domain.RebuildOutcomeRequest},
		{"no tag", domain.RebuildModeAuto, nil, domain.RebuildOutcomeNone},
		{"installation off", domain.RebuildModeOff, []string{"rebuild:auto"}, domain.RebuildOutcomeNone},
	}
	for _, c := range cases {
		st := &fakeRebuildPolicyStore{}
		policy := app.NewRebuildPolicyService(st, rebuildClock{}).WithTags(taggedRelease(c.tags...))
		if _, err := policy.PutInstallation(ctx, policyWith(c.installMode, domain.SLABucketHigh), "alice"); err != nil {
			t.Fatal(err)
		}
		got, err := app.NewRebuildEvaluationService(policy, rebuildFixture(), rebuildFixVerdicts(), rebuildClock{}).Evaluate(ctx, "rel-1")
		if err != nil || got.Outcome != c.want || len(got.Targeted) != 2 {
			t.Errorf("%s: outcome %s targeted %d err %v", c.name, got.Outcome, len(got.Targeted), err)
		}
	}
}

// D30: when Knowledge cannot be asked every fix is unknown, so nothing counts under
// fix_required — and the read says so instead of failing. With fix_required off a component
// counts with no fix named, and a scope component is said to be outside the assessment.
func TestRebuildEvaluationWithoutFixVerdicts(t *testing.T) {
	ctx := context.Background()
	policy := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithTags(taggedRelease("rebuild:ask"))
	for name, fixes := range map[string]app.ReleaseFixVerdictReader{"no seam": nil, "knowledge down": fixVerdicts{err: errors.New("down")}} {
		got, err := app.NewRebuildEvaluationService(policy, rebuildFixture(), fixes, rebuildClock{}).Evaluate(ctx, "rel-1")
		if err != nil || got.FixVerdictsRead || len(got.Targeted) != 0 || got.Outcome != domain.RebuildOutcomeNone ||
			got.Skipped[domain.RebuildSkippedFixUnknown] != 4 {
			t.Errorf("%s: %+v err %v", name, got, err)
		}
	}

	st := &fakeRebuildPolicyStore{}
	loose := app.NewRebuildPolicyService(st, rebuildClock{}).WithTags(taggedRelease("rebuild:ask"))
	p := domain.DefaultRebuildPolicy()
	p.FixRequired, p.CarrierOnly = false, false
	if _, err := loose.PutInstallation(ctx, p, "alice"); err != nil {
		t.Fatal(err)
	}
	facts := &rebuildFacts{rows: []app.RebuildFindingFacts{{
		FindingID: "f1", FaultlineID: "fl-1", CVE: "CVE-2026-0001", Stage: "triage", BaseScore: 95,
		Components: []domain.MatchedComponent{{PURL: "pkg:rpm/redhat/python3-libs@3.6-1.el8", Version: "3.6-1.el8", ClaimClass: domain.ClaimScope}},
	}}}
	got, err := app.NewRebuildEvaluationService(loose, facts, nil, rebuildClock{}).Evaluate(ctx, "rel-1")
	if err != nil || len(got.Targeted) != 1 {
		t.Fatalf("loose policy: %+v err %v", got, err)
	}
	if e := got.Targeted[0]; e.FixSource != "" || e.FixedVersions != nil || e.AssessmentState != app.RebuildAssessmentNotEligible {
		t.Errorf("entry = %+v", e)
	}
}

func TestRebuildEvaluationRefusals(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("db down")
	tagged := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithTags(taggedRelease("rebuild:ask"))

	var unwired *app.RebuildEvaluationService
	for name, svc := range map[string]*app.RebuildEvaluationService{
		"nil service": unwired,
		"no policy":   app.NewRebuildEvaluationService(nil, rebuildFixture(), nil, rebuildClock{}),
		"no facts":    app.NewRebuildEvaluationService(tagged, nil, nil, rebuildClock{}),
		// The policy can be read but the tags cannot: no effective mode, so no judgement.
		"no tag reader": app.NewRebuildEvaluationService(
			app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithIdentity(releaseOwner{product: map[string]string{"rel-1": "prod-1"}}),
			rebuildFixture(), nil, rebuildClock{}),
	} {
		if _, err := svc.Evaluate(ctx, "rel-1"); !errors.Is(err, app.ErrRebuildEvaluationUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	down := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithTags(releaseTags{err: boom})
	if _, err := app.NewRebuildEvaluationService(down, rebuildFixture(), nil, rebuildClock{}).Evaluate(ctx, "rel-1"); !errors.Is(err, app.ErrRebuildPolicyIdentityUnavailable) {
		t.Errorf("registry down: %v", err)
	}
	if _, err := app.NewRebuildEvaluationService(tagged, &rebuildFacts{err: boom}, nil, rebuildClock{}).Evaluate(ctx, "rel-1"); !errors.Is(err, boom) {
		t.Errorf("store down: %v", err)
	}
}

// KN-BEHIND-MODULE-1: a component whose fix lives only in another module stream is not targeted
// and is listed apart, with the builds of the other stream.
func TestRebuildEvaluationListsOtherStream(t *testing.T) {
	ctx := context.Background()
	policy := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithTags(taggedRelease("rebuild:ask"))
	facts := &rebuildFacts{rows: []app.RebuildFindingFacts{{
		FindingID: "f1", FaultlineID: "fl-1", CVE: "CVE-2026-0001", Stage: "triage", BaseScore: 80,
		Components: []domain.MatchedComponent{{PURL: "pkg:rpm/redhat/python3-ply@3.9-9.el8", Version: "3.9-9.el8", VerdictState: "open"}},
	}}}
	fixes := fixVerdicts{rows: []app.ReleaseFixVerdict{{
		FaultlineID: "fl-1", PURL: "pkg:rpm/redhat/python3-ply@3.9-9.el8",
		Fix: domain.RebuildFixOtherStream, FixedVersions: []string{"0:3.11-10.module+el8.10.0+1+a"},
	}}}
	got, err := app.NewRebuildEvaluationService(policy, facts, fixes, rebuildClock{}).Evaluate(ctx, "rel-1")
	if err != nil || len(got.Targeted) != 0 || got.Outcome != domain.RebuildOutcomeNone || len(got.OtherStream) != 1 ||
		got.Skipped[domain.RebuildSkippedOtherStream] != 1 {
		t.Fatalf("judgement = %+v err %v", got, err)
	}
	if e := got.OtherStream[0]; e.FindingID != "f1" || e.CurrentVersion != "3.9-9.el8" || len(e.FixedVersions) != 1 ||
		e.FixSource != app.RebuildFixSourceVerdict || e.Severity != domain.SLABucketHigh {
		t.Errorf("entry = %+v", e)
	}
}

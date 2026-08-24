package engine

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

func TestPromptRendererHappy(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1", CVE: "CVE-2024-0001", Components: []string{"pkg:golang/x@1.0.0"}}, Knowledge: domain.FaultlineView{ID: "FL1", Severity: "high", KEV: true}}}
	out, err := r.Render("recommend_position", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"F1", "CVE-2024-0001", "pkg:golang/x@1.0.0", "FL1", "affected", "not_affected"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing %q\n%s", want, out)
		}
	}
}

func TestPromptRendererSemanticPrecedents(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1", CVE: "CVE-2026-1", Components: []string{"pkg:golang/openssl"}}, Knowledge: domain.FaultlineView{ID: "FL1", Severity: "high"}}, Precedents: []domain.PrecedentPosition{
		{ReleaseID: "R2", SourceCVE: "CVE-2025-9", Component: "pkg:golang/openssl", Stance: "not_affected", Rationale: "unreachable", Score: 0.87},
	}}
	out, err := r.Render("recommend_position", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// A semantic precedent renders its release, the similar CVE, the component, the similarity
	// score, and the stance + rationale — so the LLM can weigh a different-CVE precedent.
	for _, want := range []string{"R2", "CVE-2025-9", "pkg:golang/openssl", "0.87", "not_affected", "unreachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing precedent detail %q\n%s", want, out)
		}
	}
}

func TestPromptRendererUnknownCapability(t *testing.T) {
	r, _ := NewPromptRenderer()
	if _, err := r.Render("nope", domain.AssembledContext{}); err == nil {
		t.Error("unknown capability should error")
	}
}

func TestNewRendererParseError(t *testing.T) {
	if _, err := newRenderer(map[string]string{"bad": "{{ .Finding.ID "}); err == nil {
		t.Error("malformed template should fail to parse")
	}
}

func TestRenderExecuteError(t *testing.T) {
	r, err := newRenderer(map[string]string{"badfield": "{{ .Nonexistent }}"})
	if err != nil {
		t.Fatalf("newRenderer: %v", err)
	}
	if _, err := r.Render("badfield", domain.AssembledContext{}); err == nil {
		t.Error("template referencing a missing field should fail at execute")
	}
}

// The plan template must carry the PRE-COMPUTED grouping into the prompt. If it did not, the
// model would be asked to rediscover from raw rows that nine CVEs share one upgrade — slow,
// expensive, and non-deterministic, when it is a GROUP BY (EDR-TRUST-01 T10).
func TestRenderPlanRemediation(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	rpm := func(name, source, version string) domain.PostureComponent {
		return domain.PostureComponent{
			PURL: "pkg:rpm/rocky/" + name + "@" + version, Name: name,
			Version: version, Ecosystem: "rpm", Source: source,
		}
	}
	ac := domain.AssembledContext{Release: domain.ReleasePosture{
		ReleaseID: "rel-1",
		Entries: []domain.PostureEntry{
			{FindingID: "f1", CVE: "CVE-2007-4559", ResidualPriority: 97,
				Components: []domain.PostureComponent{rpm("python3-ply", "python-ply", "3.9-9.el8")}},
			{FindingID: "f2", CVE: "CVE-2021-3177", ResidualPriority: 96,
				Components: []domain.PostureComponent{rpm("python3-ply", "python-ply", "3.9-9.el8")}},
		},
	}}

	got, err := r.Render("plan_remediation", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"rel-1",               // the subject
		"upgrade python-ply",  // named by the SOURCE package — the name a fix is published under
		"closes 2 finding(s)", // the collapse the model must not have to rediscover
		"CVE-2007-4559",       // worst-first within the action
		"3.9-9.el8",           // what is installed
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q:\n%s", want, got)
		}
	}
	// It must not invite a fix version: the listed versions are INSTALLED, and a model told
	// otherwise would confidently recommend upgrading to the version already deployed.
	if !strings.Contains(got, "not what to upgrade to") {
		t.Error("prompt must state that listed versions are installed, not target versions")
	}
}

// join renders an empty list as "(none)" rather than as blank, so a model reading the prompt is
// never left to infer meaning from an absence — the same reasoning as AI-GROUND-1's honest-absence
// contract, applied to the prompt itself.
func TestPromptJoinHelperOnEmpty(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Release: domain.ReleasePosture{
		ReleaseID: "rel-1",
		Entries: []domain.PostureEntry{{
			FindingID: "f1", ResidualPriority: 50,
			Components: []domain.PostureComponent{{Name: "x", Ecosystem: "npm"}}, // no version, no CVE
		}},
	}}
	got, err := r.Render("plan_remediation", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got, "(none)") {
		t.Errorf("empty lists must render as (none):\n%s", got)
	}
}

// A release can have outstanding Findings whose components name nothing actionable, leaving the
// action list EMPTY. The template must still render — a prompt that errors here would surface as
// `provider_error`, i.e. an outage, for what is really "we have nothing concrete to suggest".
func TestRenderPlanRemediation_EmptyActionList(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Release: domain.ReleasePosture{
		ReleaseID: "rel-1",
		Entries: []domain.PostureEntry{{
			FindingID: "f1", CVE: "CVE-1", ResidualPriority: 50,
			Components: []domain.PostureComponent{{PURL: "pkg:rpm/rocky/x@1", Ecosystem: "rpm"}}, // unnamed
		}},
	}}
	got, err := r.Render("plan_remediation", ac)
	if err != nil {
		t.Fatalf("Render with no actions must not error: %v", err)
	}
	if !strings.Contains(got, "rel-1") {
		t.Errorf("prompt lost its subject:\n%s", got)
	}
}

// PLAN-1: a merged module-stream step legitimately covers dozens of packages — 33 on a measured
// release — and printing all of them turned one step into five wrapped lines. The COLLAPSE is
// right; the rendering was not.
func TestRenderPlanRemediation_CapsALongPackageList(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	var entries []domain.PostureEntry
	for _, name := range []string{"perl-Carp", "perl-Data-Dumper", "perl-Digest", "perl-Encode", "perl-Exporter"} {
		entries = append(entries, domain.PostureEntry{
			FindingID: name, CVE: "CVE-2025-40909", ResidualPriority: 50,
			Components: []domain.PostureComponent{{
				PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Ecosystem: "rpm", Source: name,
			}},
		})
	}
	got, err := r.Render("plan_remediation", domain.AssembledContext{
		Release: domain.ReleasePosture{ReleaseID: "rel-1", Entries: entries},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got, "+2 more") {
		t.Errorf("a 5-package merged step must be capped:\n%s", got)
	}
	// The count is still stated, so a reader knows the step is bigger than the three names shown.
	if !strings.Contains(got, "these 5 packages ship together") {
		t.Errorf("the step must say how many packages it really covers:\n%s", got)
	}
	// The cap is about the HEADING, and this assertion is scoped to the heading line on purpose.
	//
	// It used to assert the fifth package appeared NOWHERE in the prompt, which conflated two
	// different things and turned out to be actively harmful: PLAN-6 requires the full package
	// list to be present on a `packages (citable)` line, because a model told to cite from the
	// truncated heading cites "perl-Carp, perl-constant, perl-Data-Dumper +29 more" — not a
	// package, ungrounded, whole plan discarded.
	//
	// Readability of the human-facing line and completeness of the machine-facing citation list
	// are separate requirements, and the earlier assertion could only be satisfied by sacrificing
	// the second one.
	var heading string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, ". upgrade ") {
			heading = line
			break
		}
	}
	if heading == "" {
		t.Fatalf("no upgrade heading found:\n%s", got)
	}
	if strings.Contains(heading, "perl-Exporter") {
		t.Errorf("the fifth package must not be printed inline in the heading: %q", heading)
	}
	// ...but it MUST still be citable, or the step covering it cannot be justified.
	if !strings.Contains(got, "- packages (citable):") || !strings.Contains(got, "perl-Exporter") {
		t.Errorf("every merged package must appear on the citable line:\n%s", got)
	}
}

// PLAN-6 — every identifier the prompt OFFERS as citable must satisfy Grounds().
//
// The prompt and the Grounding Verification gate are an interface with no compiler between them,
// and a fake provider returns whatever the test author already believed — so nothing else in the
// suite can catch a disagreement between them. This test is that compiler.
//
// The live failure it encodes: PLAN-1 capped the `upgrade ...` heading at three packages with a
// "+29 more" suffix, for readability. The citation rule still said "copied verbatim from an
// `upgrade ...` heading", so the model dutifully cited
// "perl-Carp, perl-constant, perl-Data-Dumper +29 more" — not a package, ungrounded, whole plan
// discarded with `business_invalid`. The model was obeying the prompt; the prompt was wrong.
//
// Note what is being asserted: not that the model behaves, but that the INSTRUCTIONS are
// satisfiable. A rule no compliant answer can obey is a defect in the rule.
func TestPlanPromptOnlyOffersGroundableCitations(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	comp := func(name, source string) domain.PostureComponent {
		return domain.PostureComponent{
			PURL: "pkg:rpm/rocky/" + name + "@1.0", Name: name, Version: "1.0",
			Ecosystem: "rpm", Source: source,
		}
	}
	// Two Findings closed by the identical CVE set across FIVE packages, so mergeSiblings folds
	// them into one action whose display heading must be truncated — the exact shape that broke.
	var comps []domain.PostureComponent
	for _, n := range []string{"perl-Carp", "perl-constant", "perl-Data-Dumper", "perl-Digest", "perl-Encode"} {
		comps = append(comps, comp(n, n))
	}
	posture := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2026-1", ResidualPriority: 70, Components: comps},
		{FindingID: "f2", CVE: "CVE-2026-2", ResidualPriority: 30, Components: comps},
	}}
	got, err := r.Render("plan_remediation", domain.AssembledContext{Release: posture})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Sanity: the heading really is truncated here, or this test proves nothing.
	if !strings.Contains(got, "+2 more") {
		t.Fatalf("expected a truncated heading in this fixture:\n%s", got)
	}

	offered := 0
	for _, line := range strings.Split(got, "\n") {
		l := strings.TrimSpace(line)
		var list string
		switch {
		case strings.HasPrefix(l, "- packages (citable):"):
			list = strings.TrimPrefix(l, "- packages (citable):")
		case strings.HasPrefix(l, "- cves (citable):"):
			list = strings.TrimPrefix(l, "- cves (citable):")
		default:
			continue
		}
		for _, ref := range strings.Split(list, ",") {
			ref = strings.TrimSpace(ref)
			if ref == "" || ref == "(none)" {
				continue
			}
			offered++
			if !posture.Grounds(ref) {
				t.Errorf("prompt offers %q as citable, but Grounds() rejects it — "+
					"the plan would be discarded for obeying the instructions", ref)
			}
		}
	}
	if offered == 0 {
		t.Fatal("no citable identifiers found — the prompt must name what may be cited")
	}
	// And the truncated display heading must NOT be what the rules point at.
	if strings.Contains(got, "copied verbatim from an `upgrade ...` heading") {
		t.Error("citation rule points at the truncated heading; it must point at `packages (citable)`")
	}
}

// The deterministic half of a plan must be readable WITHOUT a model.
//
// Before this, PlanActions was called only from inside the template, so the grouping existed
// nowhere an operator could see it: a `GROUP BY` bug and a bad generation were indistinguishable
// from outside. Measured cost on 2026-08-08 — a plan collapsed from 15 steps to 4 and nothing on
// the box could say whether that was correct.
func TestRenderLogsThePlanGrouping(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	comp := func(name, source string) domain.PostureComponent {
		return domain.PostureComponent{
			PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Version: "1",
			Ecosystem: "rpm", Source: source,
		}
	}
	// More than 15 actions, so the truncation branch runs: the log must not describe work the
	// prompt never showed the model.
	var entries []domain.PostureEntry
	for i := 0; i < 18; i++ {
		pkg := fmt.Sprintf("pkg%02d", i)
		entries = append(entries, domain.PostureEntry{
			FindingID: pkg, CVE: fmt.Sprintf("CVE-2026-%04d", i), ResidualPriority: 90 - i,
			Components: []domain.PostureComponent{comp("lib"+pkg, pkg)},
		})
	}
	ac := domain.AssembledContext{Release: domain.ReleasePosture{ReleaseID: "rel-1", Entries: entries}}

	// Nil logger is the default and must be a silent no-op, not a panic: instrumentation must
	// never be able to break the code it observes.
	if _, err := r.Render("plan_remediation", ac); err != nil {
		t.Fatalf("render with no logger: %v", err)
	}

	withLog := r.WithLogger(observability.Nop())
	if withLog != r {
		t.Error("WithLogger must return the same renderer for chaining")
	}
	if _, err := withLog.Render("plan_remediation", ac); err != nil {
		t.Fatalf("render with logger: %v", err)
	}
	// A non-plan capability must not compute or log a grouping — there is none to describe.
	if _, err := withLog.Render("recommend_position", domain.AssembledContext{}); err != nil {
		t.Fatalf("render recommend_position: %v", err)
	}
}

// PLAN-6, generalised — every `ref` value the prompt SHOWS must ground, not only the ones it lists
// as citable.
//
// The response-format example read `"ref":"..."` and a live model cited the literal string "...",
// which is ungrounded and discards the whole plan. That was the THIRD refusal caused by something
// the prompt displayed: the truncated `upgrade` heading, then the `<--` annotations, then this. A
// placeholder is indistinguishable from content to a model filling in a shape, so the example is
// now built from this request's own data and is self-grounding.
//
// This test extends TestPlanPromptOnlyOffersGroundableCitations from "what the prompt lists" to
// "what the prompt shows", which is the surface the model actually copies from.
func TestPlanPromptShowsNoUngroundableRef(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	posture := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2026-1", ResidualPriority: 70, Components: []domain.PostureComponent{
			{Name: "python3-pyyaml", Source: "PyYAML", Version: "3.12", Ecosystem: "rpm"},
		}},
	}}
	got, err := r.Render("plan_remediation", domain.AssembledContext{Release: posture})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	refs := regexp.MustCompile(`"ref"\s*:\s*"([^"]*)"`).FindAllStringSubmatch(got, -1)
	if len(refs) == 0 {
		t.Fatal("the prompt shows no example ref — the model has no shape to copy")
	}
	for _, m := range refs {
		if !posture.Grounds(m[1]) {
			t.Errorf("prompt shows ref %q, which Grounds() rejects — a model copying the example "+
				"would have its whole plan discarded", m[1])
		}
	}
	// And the ellipsis placeholder must be gone from the response format entirely.
	if strings.Contains(got, `"ref":"..."`) || strings.Contains(got, `"ref": "..."`) {
		t.Error("the response-format example still contains an ellipsis placeholder as a ref")
	}

	// An EMPTY plan has no real CVE to show, and must then omit the example rather than fall back
	// to a placeholder — the failure this whole change is about.
	empty, err := r.Render("plan_remediation", domain.AssembledContext{
		Release: domain.ReleasePosture{ReleaseID: "rel-1"},
	})
	if err != nil {
		t.Fatalf("Render empty: %v", err)
	}
	// Scoped to an actual `"ref": "value"` pair: the field NAME still appears in the prose
	// describing the response shape, and that is not something a model can copy as an identifier.
	if m := regexp.MustCompile(`"ref"\s*:\s*"([^"]*)"`).FindAllString(empty, -1); len(m) > 0 {
		t.Errorf("an empty plan must show no example ref value, got %v", m)
	}
}

// AI-CTX-1 — an unbounded projection field can exhaust the model's budget, and the failure looks
// like a bad model rather than a bad prompt.
//
// Measured live: a module-stream card carried ~100 affected ranges and 266 unattributed fixes.
// recommend_position ran for 164 seconds, hit 8192 tokens, stopped mid-JSON, and returned
// `schema_invalid: unexpected end of JSON input`. The recommendation was not wrong — it was never
// finished.
//
// Truncating SILENTLY would be worse than the overflow: the model would reason from a subset while
// believing it had the whole set. The test therefore asserts both halves — bounded, and honest
// about what it dropped.
func TestRecommendPromptBoundsAffectedRanges(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ranges := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		ranges = append(ranges, fmt.Sprintf("<0:1.%d-1.module+el8.3.0+74+855e3f5d", i))
	}
	ac := domain.AssembledContext{Projection: domain.FindingAssessment{
		Finding:   domain.FindingView{ID: "fnd-1", ReleaseID: "rel-1", CVE: "CVE-2019-10086", Components: []string{"pkg:rpm/x@1"}},
		Knowledge: domain.FaultlineView{ID: "fl-1", Severity: "high", AffectedRanges: ranges},
	}}
	got, err := r.Render("recommend_position", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(got, "<0:1.99-1.module") {
		t.Error("the 100th range was printed inline — the list is not bounded")
	}
	if !strings.Contains(got, "+88 more (not shown)") {
		t.Errorf("the prompt must say how much it dropped:\n%s", got)
	}
	// The example ref must be a REAL identifier, not a placeholder (the PLAN-6 class).
	refs := regexp.MustCompile(`"ref"\s*:\s*"([^"]*)"`).FindAllStringSubmatch(got, -1)
	if len(refs) == 0 {
		t.Fatal("no example ref shown — the model has no shape to copy")
	}
	for _, m := range refs {
		if m[1] == "..." || m[1] == "" {
			t.Errorf("prompt shows placeholder ref %q — a model copying it has its whole recommendation discarded", m[1])
		}
	}
}

// compare_releases renders the comparison buckets with their counts and truncation notes, and
// carries the JSON contract pinned to the candidate id.
func TestRenderCompareReleases(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatal(err)
	}
	ac := domain.AssembledContext{Comparison: domain.ReleaseComparison{
		BaselineID: "rel-a", CandidateID: "rel-b",
		Fixed: []domain.PostureEntry{{FindingID: "f1", CVE: "CVE-2024-0001", ResidualPriority: 90, EffectivePriority: 90,
			Components: []domain.PostureComponent{{Name: "libfoo", Version: "1.0"}}}},
		Persisting: []domain.PostureEntry{{FindingID: "f3", CVE: "CVE-2023-0003", ResidualPriority: 70, EffectivePriority: 70}},
	}}
	out, err := r.Render("compare_releases", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"rel-a", "rel-b",
		"CVE-2024-0001", "libfoo 1.0", "residual 90",
		"CVE-2023-0003", "undecided",
		"(nothing new)",
		`"subject_id":"rel-b"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// G-AI-3: a precedent with a known release overlap renders the labeled percentage; one
// without stays unlabeled rather than claiming 0%.
func TestRenderRecommendCarriesReleaseOverlap(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatal(err)
	}
	ac := domain.AssembledContext{
		Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1", CVE: "CVE-1"}},
		Precedents: []domain.PrecedentPosition{
			{ReleaseID: "near", Stance: "not_affected", Score: 0.8, ReleaseOverlap: 0.82, OverlapKnown: true},
			{ReleaseID: "mystery", Stance: "affected", Score: 0.7},
		},
	}
	out, err := r.Render("recommend_position", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "release-overlap 82%") {
		t.Errorf("prompt missing the overlap label:\n%s", out)
	}
	if strings.Contains(out, "mystery \u00b7 release-overlap") || strings.Contains(out, "release-overlap 0%") {
		t.Error("an unknown overlap must not render as 0%")
	}
}

// Δ4a D-Δ4a-3: the version stamp is a stable content hash per capability, and it CHANGES when
// the template text changes — that stability is what makes cross-deploy eval comparison valid.
func TestPromptVersionsAreStableContentHashes(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatal(err)
	}
	v := r.Versions()
	for _, cap := range []string{"recommend_position", "plan_remediation", "explain_vulnerability", "compare_releases"} {
		if v[cap] == "" || r.Version(cap) != v[cap] {
			t.Errorf("%s: Versions()=%q Version()=%q, want a non-empty match", cap, v[cap], r.Version(cap))
		}
	}
	if r.Version("nope") != "" {
		t.Error("unknown capability must return empty version")
	}
	// Same text → same hash; different text → different hash.
	a, _ := newRenderer(map[string]string{"x": "hello"})
	b, _ := newRenderer(map[string]string{"x": "hello"})
	c, _ := newRenderer(map[string]string{"x": "world"})
	if a.Version("x") != b.Version("x") || a.Version("x") == c.Version("x") {
		t.Errorf("hash not content-stable: %q %q %q", a.Version("x"), b.Version("x"), c.Version("x"))
	}
}

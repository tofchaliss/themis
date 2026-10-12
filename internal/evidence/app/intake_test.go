package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// ---- fakes for the intake ports -------------------------------------------------

type fakeResolver struct {
	id string
	// toCreate is resolution's other answer (B7's step 4): the version does not exist
	// yet, under this project. It wins over id, exactly as the real resolver's two
	// answers are exclusive.
	toCreate           bool
	projectID, version string
	err                error

	calls                                            int
	gotProduct, gotProject, gotVersion, gotReleaseID string
	gotCreateRelease                                 bool
	gotConfined                                      bool
}

func (f *fakeResolver) Resolve(_ context.Context, req app.ResolveRequest) (app.Resolution, error) {
	f.calls++
	f.gotProduct, f.gotProject, f.gotVersion, f.gotReleaseID = req.Product, req.Project, req.Version, req.ReleaseID
	f.gotCreateRelease, f.gotConfined = req.CreateRelease, req.Confined()
	if f.toCreate {
		return app.Resolution{ProjectID: f.projectID, Version: f.version}, f.err
	}
	return app.Resolution{ReleaseID: f.id}, f.err
}

// fakeProvisioner is Registry's find-or-create as the app sees it: the FIRST call for a
// version creates it, every later call finds the same id. Simulating that rather than
// always answering `created=true` is what lets a test tell "created once" from
// "created twice", which is the property B2's idempotence exists for.
type fakeProvisioner struct {
	err   error
	calls int
	// known is the estate the fake accumulates, and answers records what it ANSWERED
	// per call: the app discards `created` (a receipt's `created` is about the
	// evidence), so the answer is only observable here.
	known                    map[string]string
	answers                  []bool
	ids                      []string
	gotProjectID, gotVersion string
}

func (f *fakeProvisioner) FindOrCreateRelease(_ context.Context, projectID, version string) (string, bool, error) {
	f.calls++
	f.gotProjectID, f.gotVersion = projectID, version
	if f.err != nil {
		return "", false, f.err
	}
	if f.known == nil {
		f.known = map[string]string{}
	}
	key := projectID + "\x00" + version
	id, existed := f.known[key]
	if !existed {
		id = fmt.Sprintf("rel-created-%d", len(f.known)+1)
		f.known[key] = id
	}
	f.answers, f.ids = append(f.answers, !existed), append(f.ids, id)
	return id, !existed, nil
}

type fakeInventory struct {
	has   bool
	err   error
	calls int
}

func (f *fakeInventory) HasInventory(context.Context, string) (bool, error) {
	f.calls++
	return f.has, f.err
}

type fakeReports struct {
	kind, dialect string
	detectErr     error

	curated                   []byte
	stats                     app.ReportStats
	convertedBy, sourceDigest string
	convertErr                error

	convertCalls  int
	gotDialect    string
	gotObservedAt time.Time
}

func (f *fakeReports) Detect(string, []byte) (string, string, error) {
	return f.kind, f.dialect, f.detectErr
}

func (f *fakeReports) Convert(dialect string, _ []byte, observedAt time.Time) ([]byte, app.ReportStats, string, string, error) {
	f.convertCalls++
	f.gotDialect, f.gotObservedAt = dialect, observedAt
	return f.curated, f.stats, f.convertedBy, f.sourceDigest, f.convertErr
}

type fakeRegistrar struct {
	res   app.RegisterResult
	err   error
	calls int
	got   app.RegisterCommand
}

func (f *fakeRegistrar) Register(_ context.Context, cmd app.RegisterCommand) (app.RegisterResult, error) {
	f.calls++
	f.got = cmd
	return f.res, f.err
}

// ---- harness --------------------------------------------------------------------

type intakeRig struct {
	svc       *app.IntakeService
	resolver  *fakeResolver
	provision *fakeProvisioner
	inventory *fakeInventory
	reports   *fakeReports
	registrar *fakeRegistrar
}

// newRig is the happy path, which each test then breaks in exactly one place: a
// curated Cortex conversion for a release that already has an inventory.
func newRig(maxBytes int64) *intakeRig {
	rig := &intakeRig{
		resolver:  &fakeResolver{id: "rel-1"},
		provision: &fakeProvisioner{},
		inventory: &fakeInventory{has: true},
		reports: &fakeReports{
			kind:         "vuln-report",
			dialect:      "cortex-json",
			curated:      []byte(`{"findings":[{"cve":"CVE-2024-2961"}]}`),
			stats:        app.ReportStats{FindingsTotal: 1},
			convertedBy:  "cortex@1",
			sourceDigest: "sha256:abc",
		},
		registrar: &fakeRegistrar{res: app.RegisterResult{ID: "ev-1", Created: true}},
	}
	rig.svc = app.NewIntakeService(maxBytes, rig.resolver, rig.provision, rig.inventory, rig.reports, rig.registrar)
	return rig
}

func (rig *intakeRig) intake(t *testing.T, cmd app.IntakeCommand) *domain.Receipt {
	t.Helper()
	r, err := rig.svc.Intake(context.Background(), cmd)
	if err != nil {
		t.Fatalf("intake returned an infrastructure error: %v", err)
	}
	if r == nil {
		t.Fatal("intake returned no receipt — every attempt is addressable (D9)")
	}
	return r
}

// assertRefused checks the receipt refused by the named reason AND that nothing was
// created or filed. The second half is the one that matters: steps 1-6 are
// side-effect-free, so a refused intake must leave a receipt and nothing else — no
// evidence (D13) and no Release (B2/B3's "nothing is created on any refusal"). It is
// asserted on EVERY refusal rather than in one test, because the create sits one line
// above the filing step and a reordering would otherwise pass.
func (rig *intakeRig) assertRefused(t *testing.T, r *domain.Receipt, want domain.RejectReason) {
	t.Helper()
	if r.Status() != domain.ReceiptRejected {
		t.Fatalf("status = %q, want rejected (detail=%q)", r.Status(), r.Detail())
	}
	if r.Reason() != want {
		t.Errorf("reason = %q, want %q (detail=%q)", r.Reason(), want, r.Detail())
	}
	if r.Detail() == "" {
		t.Error("a refusal must elaborate — the reason and the detail are two fields, and both are read")
	}
	if r.EvidenceID() != "" {
		t.Errorf("a refused intake named evidence %q", r.EvidenceID())
	}
	if rig.registrar.calls != 0 {
		t.Errorf("a refused intake wrote: %d register call(s)", rig.registrar.calls)
	}
	if rig.provision.calls != 0 {
		t.Errorf("a refused intake created a version: %d find-or-create call(s)", rig.provision.calls)
	}
}

// ---- step 0: the parameters (EDR-INTAKE-01 B2/B5, B7's step 1) -------------------

// TestCreateReleaseWithReleaseIDIsRefused — the caller named the release two ways and
// intake will not guess which one it meant (B2, status row 5).
func TestCreateReleaseWithReleaseIDIsRefused(t *testing.T) {
	rig := newRig(1 << 20)
	r := rig.intake(t, app.IntakeCommand{
		Body:          []byte(`[{"vulnerability_id":"CVE-1"}]`),
		ReleaseID:     "rel-1",
		CreateRelease: true,
		Product:       "OAMP", Project: "oamp-core", Version: "R1917.256",
	})
	rig.assertRefused(t, r, domain.ReasonCreateReleaseConflict)
	if rig.resolver.calls != 0 {
		t.Error("a request refused on its parameters resolved a release; step 1 is side-effect-free and comes first")
	}
}

// TestCreateReleaseNeedsTheWholeTriple — a partial name is not something a version can
// be created from, so it is a malformed request (B2, status row 6). Each part is
// checked on its own, because "the triple is incomplete" asserted once would pass with
// two of the three branches missing.
func TestCreateReleaseNeedsTheWholeTriple(t *testing.T) {
	for _, tc := range []struct{ name, product, project, version string }{
		{"no product", "", "oamp-core", "R1917.256"},
		{"no project", "OAMP", "", "R1917.256"},
		{"no version", "OAMP", "oamp-core", ""},
		{"nothing at all", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRig(1 << 20)
			r := rig.intake(t, app.IntakeCommand{
				Body:          []byte(`[{"vulnerability_id":"CVE-1"}]`),
				CreateRelease: true,
				Product:       tc.product, Project: tc.project, Version: tc.version,
			})
			rig.assertRefused(t, r, domain.ReasonIncompleteReleaseTriple)
			if rig.resolver.calls != 0 {
				t.Error("an incomplete triple reached resolution")
			}
		})
	}
}

// TestIncompleteTripleWithoutCreateReleaseIsUnchanged — the other half of B2's note on
// rows 5-6 versus row 4: WITHOUT `create_release` a partial name is a lookup, and "not
// found" is the honest answer, so it keeps today's `unknown_release` and does NOT
// become a parameter fault. No existing response moves.
func TestIncompleteTripleWithoutCreateReleaseIsUnchanged(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.err = domain.Reject(domain.ReasonUnknownRelease,
		`name the release either by release_id or by the whole {product, project, version} triple`)

	r := rig.intake(t, app.IntakeCommand{
		Body:    []byte(`[{"vulnerability_id":"CVE-1"}]`),
		Product: "OAMP", Version: "R1917.256", // no project
	})
	rig.assertRefused(t, r, domain.ReasonUnknownRelease)
	if rig.resolver.calls != 1 {
		t.Error("the partial triple never reached resolution; without create_release it is a lookup, not a malformed request")
	}
}

// TestBuildIDOverTheBoundIsRefusedNotTruncated — B5. The assertion is two-part: the
// refusal names `build_id_invalid`, and NOTHING was filed, because the alternative a
// reviewer should worry about is not a wrong status code but a silently shortened
// provenance value landing on an evidence row.
func TestBuildIDOverTheBoundIsRefusedNotTruncated(t *testing.T) {
	rig := newRig(1 << 20)
	tooLong := strings.Repeat("a", 257)

	r := rig.intake(t, app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1", BuildID: tooLong,
	})
	rig.assertRefused(t, r, domain.ReasonBuildIDInvalid)
	if !strings.Contains(r.Detail(), "257") || !strings.Contains(r.Detail(), "never truncated") {
		t.Errorf("detail = %q, want it to state the count and that nothing was truncated", r.Detail())
	}
}

// TestBuildIDBoundCountsCodePointsNotBytes — the UNIT is the decision (B5): 256 is the
// number OpenAPI's `maxLength` counts, so the check is `utf8.RuneCountInString`, never
// `len`. 256 x "é" is 512 bytes and is ACCEPTED; `len` would refuse it, and the spec
// and the code would disagree about what "256" means.
func TestBuildIDBoundCountsCodePointsNotBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		buildID  string
		accepted bool
	}{
		{"256 two-byte code points (512 bytes)", strings.Repeat("é", 256), true},
		{"257 two-byte code points", strings.Repeat("é", 257), false},
		{"256 ASCII", strings.Repeat("a", 256), true},
		{"257 ASCII", strings.Repeat("a", 257), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRig(1 << 20)
			r := rig.intake(t, app.IntakeCommand{
				Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1", BuildID: tc.buildID,
			})
			if tc.accepted {
				if r.Status() != domain.ReceiptFiled {
					t.Fatalf("status = %q (reason=%q detail=%q), want filed", r.Status(), r.Reason(), r.Detail())
				}
				return
			}
			rig.assertRefused(t, r, domain.ReasonBuildIDInvalid)
		})
	}
}

// TestBuildIDInvalidUTF8IsRefused — a code-point count of malformed bytes is not a
// defined quantity, so the same reason refuses it (B5). Repaired would be worse:
// provenance is the worst place to discover a silent rewrite.
func TestBuildIDInvalidUTF8IsRefused(t *testing.T) {
	rig := newRig(1 << 20)
	r := rig.intake(t, app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1", BuildID: "build-" + string([]byte{0xff}),
	})
	rig.assertRefused(t, r, domain.ReasonBuildIDInvalid)
	if !strings.Contains(r.Detail(), "UTF-8") {
		t.Errorf("detail = %q, want it to say which of the two faults it is", r.Detail())
	}
}

// TestParameterValidationPrecedesTheSizeBound — B7's first stated consequence, as a
// test so the order is a decision rather than an accident of code layout. Both halves
// matter: the new parameter wins over the bound, AND a request using no new parameter
// still reports `payload_too_large`, so no existing answer moved.
func TestParameterValidationPrecedesTheSizeBound(t *testing.T) {
	oversized := []byte(strings.Repeat("x", 64))

	t.Run("an oversized body with a malformed build_id reports the build_id", func(t *testing.T) {
		rig := newRig(8)
		r := rig.intake(t, app.IntakeCommand{Body: oversized, ReleaseID: "rel-1", BuildID: strings.Repeat("é", 257)})
		rig.assertRefused(t, r, domain.ReasonBuildIDInvalid)
	})

	t.Run("an oversized body with no new parameter still reports the bound", func(t *testing.T) {
		rig := newRig(8)
		r := rig.intake(t, app.IntakeCommand{Body: oversized, ReleaseID: "rel-1"})
		rig.assertRefused(t, r, domain.ReasonPayloadTooLarge)
	})
}

// TestTheCallersProductAuthorityReachesResolution — authorization happens at the step
// the resolved product is known (B7's step 4), so what this ring owes it is the
// caller's confinement, unchanged, on BOTH roads. A nil authorizer is the explicit
// statement that none applies (`admin`, or an auth-disabled node).
func TestTheCallersProductAuthorityReachesResolution(t *testing.T) {
	body := []byte(`[{"vulnerability_id":"CVE-1"}]`)

	rig := newRig(1 << 20)
	rig.intake(t, app.IntakeCommand{Body: body, ReleaseID: "rel-1"})
	if rig.resolver.gotConfined {
		t.Error("a command with no authorizer was reported as confined; nil means no confinement applies")
	}

	rig = newRig(1 << 20)
	rig.intake(t, app.IntakeCommand{
		Body: body, ReleaseID: "rel-1",
		Authorize: func(string) bool { return true },
	})
	if !rig.resolver.gotConfined {
		t.Error("the caller's product confinement did not reach resolution")
	}
}

// TestCreateReleaseReachesResolutionAndTheCreateWaits — with the whole triple,
// `create_release=true` is carried to resolution, and a refusal from resolution
// creates nothing: the Product and the Project are human-owned, so a name that does
// not resolve is still `unknown_release` and never a creation (B2). Only an absent
// VERSION becomes "to be created", and even then the create waits for step 8.
func TestCreateReleaseReachesResolutionAndTheCreateWaits(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.err = domain.Reject(domain.ReasonUnknownRelease, `no release version named "R1917.256" is registered`)

	r := rig.intake(t, app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), CreateRelease: true,
		Product: "OAMP", Project: "oamp-core", Version: "R1917.256",
	})
	rig.assertRefused(t, r, domain.ReasonUnknownRelease)
	if !rig.resolver.gotCreateRelease {
		t.Error("create_release did not reach resolution")
	}
}

// ---- step 1: size ---------------------------------------------------------------

func TestIntake_PayloadTooLarge_Refused(t *testing.T) {
	rig := newRig(8)
	r := rig.intake(t, app.IntakeCommand{Body: []byte(`{"findings":[]}`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonPayloadTooLarge)

	// Refused BEFORE the body was looked at, which is the point of a bound.
	if rig.reports.convertCalls != 0 {
		t.Error("an oversized body was converted")
	}
	if rig.resolver.gotReleaseID != "" {
		t.Error("an oversized body resolved its release")
	}
}

func TestIntake_ZeroMaxBytes_TakesTheDefaultBound(t *testing.T) {
	rig := newRig(0)
	// 64 MiB is the default, so an ordinary body is admitted rather than refused by a
	// bound of zero.
	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	if r.Status() != domain.ReceiptFiled {
		t.Fatalf("status = %q, want filed (detail=%q)", r.Status(), r.Detail())
	}
}

// ---- step 2: detect -------------------------------------------------------------

func TestIntake_UnrecognisedFormat_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.detectErr = domain.Reject(domain.ReasonUnrecognisedFormat,
		"the body matches no known SBOM or vulnerability-report dialect")

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`{"what":1}`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonUnrecognisedFormat)
	if rig.resolver.gotReleaseID != "" {
		t.Error("an unnameable body resolved its release — detection is the cheapest discriminator and comes first")
	}
}

// TestIntake_DetectMalformedBody_KeepsThePortsReason — detection reports the reason it
// found, not the reason of the step it failed in: a body that opens as JSON and does
// not parse is `malformed_body`, which sends the operator somewhere useful.
func TestIntake_DetectMalformedBody_KeepsThePortsReason(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.detectErr = domain.Reject(domain.ReasonMalformedBody, "body opens as a JSON array but does not parse")

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonMalformedBody)
}

// TestIntake_DetectInfrastructureError_FallsBackToTheStepsReason — an error carrying
// no reason is not a refusal anybody named, so the step it failed in is the most
// honest thing that can be said about it.
func TestIntake_DetectInfrastructureError_FallsBackToTheStepsReason(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.detectErr = errors.New("detector exploded")

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`{}`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonUnrecognisedFormat)
}

// TestIntake_DetectedKindEvidenceCannotFile_Refused — the ACL's table yields `sbom`
// and `vuln-report` only, so a third kind is a defect behind the port. It is still
// refused by name: filing a document under a kind nobody chose is how an unreadable
// one lands.
func TestIntake_DetectedKindEvidenceCannotFile_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.kind = "vex-ish"

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`{}`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonUnrecognisedFormat)
}

// ---- step 3: resolve ------------------------------------------------------------

func TestIntake_UnknownRelease_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.err = domain.Reject(domain.ReasonUnknownRelease, `no project named "oamp-core" under product "OAMP"`)

	r := rig.intake(t, app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), Product: "OAMP", Project: "oamp-core", Version: "R1917.256",
	})
	rig.assertRefused(t, r, domain.ReasonUnknownRelease)
	if rig.reports.convertCalls != 0 {
		t.Error("converted for a release that does not exist — wasted work on the common typo")
	}
	if rig.resolver.gotProduct != "OAMP" || rig.resolver.gotProject != "oamp-core" || rig.resolver.gotVersion != "R1917.256" {
		t.Errorf("the triple did not reach the resolver: %+v", rig.resolver)
	}
}

func TestIntake_ResolverInfrastructureError_FallsBackToUnknownRelease(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.err = errors.New("registry: dial tcp: connection refused")

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonUnknownRelease)
}

// ---- step 4: convert ------------------------------------------------------------

// TestIntake_ConverterRefusals_AreReportedByTheirOwnName walks the taxonomy the
// converter ACL owns. Each reason is the ACL's, carried across the port — the app
// never re-diagnoses a fault the converter already named.
func TestIntake_ConverterRefusals_AreReportedByTheirOwnName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason domain.RejectReason
		detail string
	}{
		{"MalformedBody", domain.ReasonMalformedBody, "CSV has no header row"},
		{"SourceInvalid", domain.ReasonSourceInvalid, "element 47 is not an object"},
		{"EmptyReport", domain.ReasonEmptyReport, "the body is an empty JSON array"},
		{"ObservedAtUnderivable", domain.ReasonObservedAtUnderivable, "no row carried last_observed, and none was supplied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRig(1 << 20)
			rig.reports.convertErr = domain.Reject(tc.reason, tc.detail)

			r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
			rig.assertRefused(t, r, tc.reason)
			if r.Detail() != tc.detail {
				t.Errorf("detail = %q, want the converter's own %q", r.Detail(), tc.detail)
			}
			if rig.inventory.calls != 0 {
				t.Error("a report that never converted was checked for an inventory")
			}
		})
	}
}

func TestIntake_ConversionFailed_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.convertErr = errors.New("cortex: no finding survived translation")

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonConversionFailed)
}

// TestIntake_SuppliedObservedAt_ReachesTheConverter — a supplied timestamp is the
// caller's assertion about WHICH observation this is (D3), so it has to reach the
// pure function, or the same source submitted twice with different timestamps would
// dedup into one.
func TestIntake_SuppliedObservedAt_ReachesTheConverter(t *testing.T) {
	rig := newRig(1 << 20)
	at := time.Date(2026, 9, 29, 7, 23, 22, 0, time.UTC)

	rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1", ObservedAt: at})
	if !rig.reports.gotObservedAt.Equal(at) {
		t.Errorf("observedAt = %v, want %v", rig.reports.gotObservedAt, at)
	}
	if rig.reports.gotDialect != "cortex-json" {
		t.Errorf("dialect = %q, want the detected one", rig.reports.gotDialect)
	}
}

// ---- step 5: validate what will be filed (E1) -----------------------------------

// TestIntake_SchemaInvalid_Refused_TopLevelArray is the 2026-10-05 class at the app
// ring: a converter that produced a bare array must not get a document filed.
func TestIntake_SchemaInvalid_Refused_TopLevelArray(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.curated = []byte(` [{"cve":"CVE-2024-2961"}]`)

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
}

func TestIntake_SchemaInvalid_Refused_MissingFindings(t *testing.T) {
	for _, doc := range []string{`{"results":[]}`, `{"findings":null}`, `{"findings":{}}`, ``} {
		rig := newRig(1 << 20)
		rig.reports.curated = []byte(doc)

		r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
		rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
	}
}

func TestIntake_SchemaInvalid_Refused_FindingIsNotAnObject(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.curated = []byte(`{"findings":[{"cve":"CVE-1"},"nope"]}`)
	rig.reports.stats = app.ReportStats{FindingsTotal: 2}

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
}

func TestIntake_EmptyReport_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.curated = []byte(`{"findings":[]}`)
	rig.reports.stats = app.ReportStats{}

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonEmptyReport)
}

// TestIntake_Ordering_SchemaInvalidBeatsNoInventory is the ordering assertion
// (design.md step 6): a report that is both invalid AND early reports the invalidity,
// because that is the more actionable fault. Fixing the upload order on a document
// that would be refused anyway is two round trips to the same refusal.
func TestIntake_Ordering_SchemaInvalidBeatsNoInventory(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.curated = []byte(`[{"cve":"CVE-2024-2961"}]`) // invalid
	rig.inventory.has = false                                 // and early

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
	if rig.inventory.calls != 0 {
		t.Error("the inventory was read for a document that was never fileable")
	}
}

// ---- step 6: SBOM first ---------------------------------------------------------

func TestIntake_NoInventoryForRelease_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.inventory.has = false

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonNoInventoryForRelease)
	if !strings.Contains(r.Detail(), "rel-1") || !strings.Contains(r.Detail(), "allow_without_sbom") {
		t.Errorf("detail = %q; it must name the release and what to do", r.Detail())
	}
}

func TestIntake_AllowWithoutSBOM_SetsProvenanceAndFiles(t *testing.T) {
	rig := newRig(1 << 20)
	rig.inventory.has = false

	r := rig.intake(t, app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1", AllowWithoutSBOM: true,
	})
	if r.Status() != domain.ReceiptFiled {
		t.Fatalf("status = %q, want filed (detail=%q)", r.Status(), r.Detail())
	}
	if !rig.registrar.got.Provenance.WithoutSBOM {
		t.Error("the override was not recorded in provenance — a release whose findings rest on no inventory has to say so")
	}
}

// TestIntake_AllowWithoutSBOM_WithAnInventory_RecordsNothing — the flag records a
// FACT (there was no inventory), not the caller's permission. A release that does
// have an inventory must not be marked as if it did not.
func TestIntake_AllowWithoutSBOM_WithAnInventory_RecordsNothing(t *testing.T) {
	rig := newRig(1 << 20)

	rig.intake(t, app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1", AllowWithoutSBOM: true,
	})
	if rig.registrar.got.Provenance.WithoutSBOM {
		t.Error("provenance claims no inventory for a release that has one")
	}
}

// TestIntake_InventoryUnreadable_Fails — a precondition that could not be EVALUATED
// is not a precondition that failed. Reporting `no_inventory_for_release` here would
// tell the operator to upload an SBOM they have already uploaded.
func TestIntake_InventoryUnreadable_Fails(t *testing.T) {
	rig := newRig(1 << 20)
	rig.inventory.err = errors.New("store: connection reset")

	r, err := rig.svc.Intake(context.Background(), app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1",
	})
	if err == nil {
		t.Fatal("want the cause returned, so the adapter that owns logging can report it")
	}
	if r.Status() != domain.ReceiptFailed {
		t.Fatalf("status = %q, want failed", r.Status())
	}
	if r.Reason() != "" {
		t.Errorf("a failure names no refusal reason, got %q", r.Reason())
	}
	if rig.registrar.calls != 0 {
		t.Error("filed despite an unevaluated precondition")
	}
}

// ---- step 7: file ---------------------------------------------------------------

func TestIntake_Success_FilesOnce_ProvenanceCopied(t *testing.T) {
	rig := newRig(1 << 20)

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1"})
	if r.Status() != domain.ReceiptFiled || !r.IsTerminal() {
		t.Fatalf("status = %q terminal=%v (detail=%q)", r.Status(), r.IsTerminal(), r.Detail())
	}
	if r.EvidenceID() != "ev-1" || !r.Created() {
		t.Errorf("outcome: id=%q created=%v", r.EvidenceID(), r.Created())
	}
	if r.DetectedKind() != "vuln-report" || r.DetectedFormat() != "cortex-json" {
		t.Errorf("detected = %q/%q — the client always sees what Themis decided", r.DetectedKind(), r.DetectedFormat())
	}
	if rig.registrar.calls != 1 {
		t.Fatalf("register calls = %d, want exactly 1", rig.registrar.calls)
	}

	cmd := rig.registrar.got
	if cmd.Kind != domain.KindScannerReport {
		t.Errorf("kind = %q, want scanner-report: a report in any dialect is filed as one kind", cmd.Kind)
	}
	if string(cmd.Raw) != `{"findings":[{"cve":"CVE-2024-2961"}]}` {
		t.Errorf("filed bytes = %q, want the CONVERTED document", cmd.Raw)
	}
	if cmd.SubjectReleaseID != "rel-1" {
		t.Errorf("release = %q, want the resolved id", cmd.SubjectReleaseID)
	}
	if cmd.Provenance.ConvertedBy != "cortex@1" || cmd.Provenance.SourceDigest != "sha256:abc" {
		t.Errorf("conversion provenance lost: %+v", cmd.Provenance)
	}
	if cmd.Provenance.WithoutSBOM {
		t.Error("WithoutSBOM set for a release that has an inventory")
	}
}

// TestIntake_SBOM_PassesThroughUnconverted — an SBOM is identified, never converted:
// its bytes ARE the evidence document, and it cannot be asked for an inventory that
// does not exist yet, because it is the thing that creates one.
func TestIntake_SBOM_PassesThroughUnconverted(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.kind, rig.reports.dialect = "sbom", "spdx"
	rig.inventory.has = false
	body := []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)

	r := rig.intake(t, app.IntakeCommand{Body: body, ReleaseID: "rel-1"})
	if r.Status() != domain.ReceiptFiled {
		t.Fatalf("status = %q, want filed (detail=%q)", r.Status(), r.Detail())
	}
	if rig.reports.convertCalls != 0 {
		t.Error("an SBOM was converted")
	}
	if rig.inventory.calls != 0 {
		t.Error("an SBOM was required to have an inventory before it could create one")
	}
	cmd := rig.registrar.got
	if cmd.Kind != domain.KindSBOM || string(cmd.Raw) != string(body) {
		t.Errorf("kind=%q raw=%q, want the submitted SBOM filed unchanged", cmd.Kind, cmd.Raw)
	}
	if cmd.Format != "spdx" {
		t.Errorf("format = %q, want the detected dialect so the parser ACL can read it", cmd.Format)
	}
	if cmd.Provenance.ConvertedBy != "" || cmd.Provenance.SourceDigest != "" {
		t.Errorf("a pass-through records no conversion: %+v", cmd.Provenance)
	}
}

// TestIntake_SBOM_NotAnObject_Refused — the only structural claim the border makes
// about an SBOM: it is a JSON object. Its per-format structure is the parser ACL's.
func TestIntake_SBOM_NotAnObject_Refused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.reports.kind, rig.reports.dialect = "sbom", "spdx"

	r := rig.intake(t, app.IntakeCommand{Body: []byte(`[{"spdxVersion":"SPDX-2.3"}]`), ReleaseID: "rel-1"})
	rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
}

func TestIntake_RegisterFails_ReceiptFails(t *testing.T) {
	rig := newRig(1 << 20)
	rig.registrar.err = errors.New("evidence: insert: deadlock detected")

	r, err := rig.svc.Intake(context.Background(), app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1",
	})
	if err == nil {
		t.Fatal("want the cause returned")
	}
	if r.Status() != domain.ReceiptFailed || r.Reason() != "" {
		t.Fatalf("status=%q reason=%q, want failed with no reason", r.Status(), r.Reason())
	}
	if r.EvidenceID() != "" {
		t.Errorf("a failed intake named evidence %q", r.EvidenceID())
	}
}

// TestIntake_RegisterReportsNoEvidenceID_Fails — "filed, pointing at nothing" is the
// 2026-10-05 shape, so the receipt refuses to claim an id it does not have.
func TestIntake_RegisterReportsNoEvidenceID_Fails(t *testing.T) {
	rig := newRig(1 << 20)
	rig.registrar.res = app.RegisterResult{ID: "", Created: true}

	r, err := rig.svc.Intake(context.Background(), app.IntakeCommand{
		Body: []byte(`[{"vulnerability_id":"CVE-1"}]`), ReleaseID: "rel-1",
	})
	if err == nil {
		t.Fatal("want the cause returned")
	}
	if r.Status() != domain.ReceiptFailed {
		t.Fatalf("status = %q, want failed", r.Status())
	}
}

// ---- step 7: the version find-or-create (EDR-INTAKE-01 B2, B7's step 8) ---------
//
// The create is the LAST thing before filing, and these tests are about where it sits
// rather than about what it does: Registry owns the upsert, and what intake owes is
// that nothing is created by a request that was going to be refused anyway.

// newCreateRig is the bot road: an SBOM for a version that does not exist yet, under a
// project that does — which is the one resolution answer B2 lets intake act on.
func newCreateRig() *intakeRig {
	rig := newRig(1 << 20)
	rig.reports.kind, rig.reports.dialect = "sbom", "cyclonedx"
	rig.resolver.toCreate = true
	rig.resolver.projectID, rig.resolver.version = "proj-1", "R1917.256"
	return rig
}

// createCmd is one `create_release=true` submission of the whole triple.
func createCmd(body string) app.IntakeCommand {
	return app.IntakeCommand{
		Body: []byte(body), CreateRelease: true,
		Product: "OAMP", Project: "oamp-core", Version: "R1917.256",
	}
}

const createSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5"}`

// TestNothingIsCreatedWhenTheDocumentIsRefused — B3's "nothing is created on any
// refusal", for a refusal that happens AFTER resolution answered "to be created". If
// the create sat with resolution, a bot retrying a malformed report would mint an empty
// Release per attempt, and the estate would fill with versions no evidence ever
// reached.
func TestNothingIsCreatedWhenTheDocumentIsRefused(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.toCreate = true
	rig.resolver.projectID, rig.resolver.version = "proj-1", "R1917.256"
	rig.reports.curated = []byte(`[{"cve":"CVE-2024-2961"}]`) // the 2026-10-05 shape

	r := rig.intake(t, createCmd(`[{"vulnerability_id":"CVE-1"}]`))
	// assertRefused also holds the create: the provisioner must be uncalled.
	rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
	if r.ReleaseID() != "" {
		t.Errorf("the receipt names release %q for a version that was never created", r.ReleaseID())
	}
}

// TestVersionIsCreatedOnlyOnceAcrossTwoRequests — find-or-create is idempotent, and
// the second request FINDS the version rather than forking it. The fake resolver
// answers "to be created" both times on purpose: that is also the real race, two
// requests resolving before either has created anything, and the constraint is what
// settles it (B4) — which is why Registry owns the upsert and intake only asks.
func TestVersionIsCreatedOnlyOnceAcrossTwoRequests(t *testing.T) {
	rig := newCreateRig()

	first := rig.intake(t, createCmd(createSBOM))
	firstFiled := rig.registrar.got.SubjectReleaseID
	second := rig.intake(t, createCmd(createSBOM))

	if rig.provision.calls != 2 {
		t.Fatalf("find-or-create ran %d time(s), want one per request", rig.provision.calls)
	}
	if want := []bool{true, false}; rig.provision.answers[0] != want[0] || rig.provision.answers[1] != want[1] {
		t.Errorf("created answers = %v, want %v — the second request must find the version, not create it", rig.provision.answers, want)
	}
	if rig.provision.ids[0] != rig.provision.ids[1] {
		t.Errorf("two ids for one version: %q and %q", rig.provision.ids[0], rig.provision.ids[1])
	}
	if rig.provision.gotProjectID != "proj-1" || rig.provision.gotVersion != "R1917.256" {
		t.Errorf("created under project %q at version %q, want the resolved project and the submitted version",
			rig.provision.gotProjectID, rig.provision.gotVersion)
	}
	// Both documents are filed against the created release, and the receipt names it:
	// an id resolution never had has to reach both the filing step and the record of
	// the attempt, or the operator cannot find what they just uploaded.
	id := rig.provision.ids[0]
	if firstFiled != id || rig.registrar.got.SubjectReleaseID != id {
		t.Errorf("filed against %q then %q, want both against the created release %q", firstFiled, rig.registrar.got.SubjectReleaseID, id)
	}
	if first.ReleaseID() != id || second.ReleaseID() != id {
		t.Errorf("receipts name releases %q and %q, want the created release %q", first.ReleaseID(), second.ReleaseID(), id)
	}
}

// TestFirstFailureStillWins — D5's precedence is untouched by the new step. A report
// that is both invalid AND early reports the invalidity, never a release-creation
// reason, and it reaches neither the inventory read nor the create: deferring the
// create is what keeps every existing ordering assertion true.
func TestFirstFailureStillWins(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.toCreate = true
	rig.resolver.projectID, rig.resolver.version = "proj-1", "R1917.256"
	rig.reports.curated = []byte(`[{"cve":"CVE-2024-2961"}]`) // invalid
	rig.inventory.has = false                                 // and early

	r := rig.intake(t, createCmd(`[{"vulnerability_id":"CVE-1"}]`))
	rig.assertRefused(t, r, domain.ReasonSchemaInvalid)
	if rig.inventory.calls != 0 {
		t.Error("the inventory was read for a document that was never fileable")
	}
}

// TestReportForANewVersionNeedsAnSBOMFirst — D6 holds for a version that does not
// exist yet, and holds BEFORE the create: a version still to be created has no
// inventory, so the report is refused and nothing is created (B2's consequence for the
// bot author). With B1's two requests this never bites — the SBOM request creates the
// version and the report request finds it.
func TestReportForANewVersionNeedsAnSBOMFirst(t *testing.T) {
	rig := newRig(1 << 20)
	rig.resolver.toCreate = true
	rig.resolver.projectID, rig.resolver.version = "proj-1", "R1917.256"

	r := rig.intake(t, createCmd(`[{"vulnerability_id":"CVE-1"}]`))
	rig.assertRefused(t, r, domain.ReasonNoInventoryForRelease)
	if !strings.Contains(r.Detail(), "R1917.256") || !strings.Contains(r.Detail(), "allow_without_sbom") {
		t.Errorf("detail = %q; it must name the VERSION (there is no release id yet) and what to do", r.Detail())
	}
	if rig.inventory.calls != 0 {
		t.Error("the inventory was read for a release that does not exist yet — the answer is known without a read, and there is no id to read it by")
	}

	t.Run("and with allow_without_sbom the version is created and the report filed", func(t *testing.T) {
		rig := newRig(1 << 20)
		rig.resolver.toCreate = true
		rig.resolver.projectID, rig.resolver.version = "proj-1", "R1917.256"

		cmd := createCmd(`[{"vulnerability_id":"CVE-1"}]`)
		cmd.AllowWithoutSBOM = true
		r := rig.intake(t, cmd)
		if r.Status() != domain.ReceiptFiled {
			t.Fatalf("status = %q, want filed (detail=%q)", r.Status(), r.Detail())
		}
		if rig.provision.calls != 1 {
			t.Fatalf("find-or-create ran %d time(s), want once", rig.provision.calls)
		}
		if rig.registrar.got.SubjectReleaseID != rig.provision.ids[0] {
			t.Errorf("filed against %q, want the created release %q", rig.registrar.got.SubjectReleaseID, rig.provision.ids[0])
		}
		if !rig.registrar.got.Provenance.WithoutSBOM {
			t.Error("the override was not recorded in provenance — a release whose findings rest on no inventory has to say so")
		}
	})
}

// TestVersionCouldNotBeCreated_Fails — the one refusal step 8 can produce is a store
// failure, and it is a statement about Themis rather than about the document: the
// receipt `failed`, the cause is returned so the adapter that owns logging can report
// it, and nothing is filed against a release that was never created.
func TestVersionCouldNotBeCreated_Fails(t *testing.T) {
	rig := newCreateRig()
	rig.provision.err = errors.New("registry: dial tcp: connection refused")

	r, err := rig.svc.Intake(context.Background(), createCmd(createSBOM))
	if err == nil {
		t.Fatal("want the cause returned, so the adapter that owns logging can report it")
	}
	if r.Status() != domain.ReceiptFailed {
		t.Fatalf("status = %q, want failed", r.Status())
	}
	if !strings.Contains(r.Detail(), "R1917.256") {
		t.Errorf("detail = %q; it must name the version that could not be created", r.Detail())
	}
	if rig.registrar.calls != 0 {
		t.Errorf("evidence was filed against a release that was never created (%d register call(s))", rig.registrar.calls)
	}
}

// TestANodeWithNoRegistryWriteSeamRefusesToCreate — a node wired with no write seam
// (the dev-stub posture) answers with a sentence naming the misconfiguration instead
// of panicking inside the one step that writes. On the stub itself this is unreachable
// — it knows no names, so no triple resolves far enough — which is why the stand-in is
// a guard and not a feature.
func TestANodeWithNoRegistryWriteSeamRefusesToCreate(t *testing.T) {
	rig := newCreateRig()
	svc := app.NewIntakeService(1<<20, rig.resolver, nil, rig.inventory, rig.reports, rig.registrar)

	r, err := svc.Intake(context.Background(), createCmd(createSBOM))
	if err == nil {
		t.Fatal("want the cause returned")
	}
	if r.Status() != domain.ReceiptFailed {
		t.Fatalf("status = %q, want failed", r.Status())
	}
	if !strings.Contains(r.Detail(), "registry write seam") {
		t.Errorf("detail = %q; it must name the missing seam, which is the thing an operator can fix", r.Detail())
	}
	if rig.registrar.calls != 0 {
		t.Error("evidence was filed against a release that could not be created")
	}
}

// The structural half of "no parallel writer", asserted at COMPILE time:
// *EvidenceService satisfies the registrar port as-is, so intake cannot acquire a
// second definition of what "filed" means — the trust gate, the fingerprint, the
// aggregate's invariants and the outbox note in one transaction. A change to
// Register's signature breaks this line before it reaches wiring.
var _ app.EvidenceRegistrar = (*app.EvidenceService)(nil)

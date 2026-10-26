package domain_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// TestIntakeReasonTaxonomyIsClosed is the D11 guard (tasks.md 2.3, extended by
// phase3-bot-intake 0.1). It compares the enum against the identifiers written down
// in the EDR — D11's table plus the 2026-10-12 amendment's four — as a SET, so
// growing, shrinking or renaming a reason fails here and the change has to carry the
// spec and the dashboard with it.
//
// #116 is what it costs otherwise: a consumer that knew 6 of 15 reasons asserted
// "no reason given" for the other nine, so refusals the system had named precisely
// reached operators as silence.
func TestIntakeReasonTaxonomyIsClosed(t *testing.T) {
	// EDR-INTAKE-01 D11's table, transcribed. This literal is the contract; it is
	// deliberately NOT derived from the code under test, which would make the test
	// agree with any change.
	want := map[domain.RejectReason]bool{
		"unknown_release":          true,
		"no_inventory_for_release": true,
		"unrecognised_format":      true,
		"declared_format_mismatch": true,
		"malformed_body":           true,
		"source_invalid":           true,
		"schema_invalid":           true,
		"empty_report":             true,
		"observed_at_underivable":  true,
		"observed_at_invalid":      true,
		"conversion_failed":        true,
		"checksum_mismatch":        true,
		"duplicate_other_release":  true,
		"payload_too_large":        true,
		"too_many_records":         true,
		"unauthorized":             true,
		// The 2026-10-12 amendment's four (B2/B4/B5 and the status-code table),
		// landed as vocabulary before anything produces them.
		"create_release_conflict":   true,
		"incomplete_release_triple": true,
		"ambiguous_name":            true,
		"build_id_invalid":          true,
	}

	got := make(map[domain.RejectReason]bool, len(want))
	for _, r := range domain.AllRejectReasons() {
		if got[r] {
			t.Errorf("reason %q appears twice in AllRejectReasons", r)
		}
		got[r] = true
		if !want[r] {
			t.Errorf("reason %q is in the enum but not in EDR-INTAKE-01 D11 — update the EDR, the API spec and the dashboard in the same change", r)
		}
		if !r.Valid() {
			t.Errorf("reason %q is in AllRejectReasons but Valid() refuses it", r)
		}
	}
	for r := range want {
		if !got[r] {
			t.Errorf("reason %q is in EDR-INTAKE-01 D11 but missing from the enum", r)
		}
	}

	// And the absences that are decisions, not omissions (D6): there is no window in
	// which Evidence holds an SBOM whose inventory is pending, so a reason for it
	// could never fire. If SBOM parsing ever becomes asynchronous, THAT change adds
	// the reason — and this line is what makes it notice.
	for _, dead := range []domain.RejectReason{"inventory_not_ready", "", "nope"} {
		if dead.Valid() {
			t.Errorf("%q must not be a reason", dead)
		}
	}
}

// TestReceipt_LegalTransitions_AcceptToFiled walks the whole ladder and asserts the
// receipt reports each step.
func TestReceipt_LegalTransitions_AcceptToFiled(t *testing.T) {
	var r domain.Receipt

	if r.Status() != "" || r.IsTerminal() {
		t.Fatalf("zero receipt: status=%q terminal=%v", r.Status(), r.IsTerminal())
	}

	steps := []struct {
		name string
		do   func() error
		want domain.ReceiptStatus
	}{
		{"accept", r.Accept, domain.ReceiptAccepted},
		{"validating", r.StartValidating, domain.ReceiptValidating},
		{"converting", r.StartConverting, domain.ReceiptConverting},
		{"registering", r.StartRegistering, domain.ReceiptRegistering},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if r.Status() != s.want {
			t.Fatalf("%s: status = %q, want %q", s.name, r.Status(), s.want)
		}
		if r.IsTerminal() {
			t.Fatalf("%s: must not be terminal", s.name)
		}
	}

	if err := r.RecordDetected("vuln-report", "cortex-json"); err != nil {
		t.Fatalf("record detected: %v", err)
	}
	if r.DetectedKind() != "vuln-report" || r.DetectedFormat() != "cortex-json" {
		t.Errorf("detected = %q/%q", r.DetectedKind(), r.DetectedFormat())
	}

	if err := r.Filed("ev-1", true); err != nil {
		t.Fatalf("filed: %v", err)
	}
	if r.Status() != domain.ReceiptFiled || !r.IsTerminal() {
		t.Fatalf("filed: status=%q terminal=%v", r.Status(), r.IsTerminal())
	}
	if r.EvidenceID() != "ev-1" || !r.Created() {
		t.Errorf("filed outcome: id=%q created=%v", r.EvidenceID(), r.Created())
	}
	if r.Reason() != "" || r.Detail() != "" {
		t.Errorf("a filed receipt carries no refusal: reason=%q detail=%q", r.Reason(), r.Detail())
	}
}

// TestReceipt_SkipsConversion_ForAPassThrough is the ladder's one legal skip: an SBOM
// is identified, never converted, so validating → registering must be legal. A
// predecessor table would have forbidden it and made a correct SBOM upload look like
// a state-machine violation.
func TestReceipt_SkipsConversion_ForAPassThrough(t *testing.T) {
	var r domain.Receipt
	for _, step := range []func() error{r.Accept, r.StartValidating, r.StartRegistering} {
		if err := step(); err != nil {
			t.Fatalf("ladder with conversion skipped: %v", err)
		}
	}
	if r.Status() != domain.ReceiptRegistering {
		t.Errorf("status = %q, want registering", r.Status())
	}
}

// TestReceipt_RecordsWhatTheAttemptSaw_EvenWhenItIsThenRefused is the reporting half
// of the receipt: the release it resolved and what the conversion saw are recorded
// BEFORE the outcome is known, so "427 of 427 converted, then refused" survives as a
// fact. The alternative — only reporting counts on success — makes a refusal and an
// unreadable document look identical, and only one of them is actionable.
func TestReceipt_RecordsWhatTheAttemptSaw_EvenWhenItIsThenRefused(t *testing.T) {
	var r domain.Receipt
	mustAccept(t, &r)
	if err := r.RecordRelease("rel-1917"); err != nil {
		t.Fatalf("record release: %v", err)
	}
	if err := r.StartValidating(); err != nil {
		t.Fatalf("validating: %v", err)
	}
	if err := r.StartConverting(); err != nil {
		t.Fatalf("converting: %v", err)
	}
	if err := r.RecordConversion("cortex@1", "abc123", 500, 73); err != nil {
		t.Fatalf("record conversion: %v", err)
	}
	if err := r.RecordComponentsSkipped(42); err != nil {
		t.Fatalf("record components skipped: %v", err)
	}
	if err := r.Rejected(domain.ReasonSchemaInvalid, "findings[2] is not an object"); err != nil {
		t.Fatalf("rejected: %v", err)
	}

	if r.ReleaseID() != "rel-1917" {
		t.Errorf("release = %q, want the resolved release on a refused receipt too", r.ReleaseID())
	}
	if r.ConvertedBy() != "cortex@1" || r.SourceDigest() != "abc123" {
		t.Errorf("converted_by=%q source_digest=%q", r.ConvertedBy(), r.SourceDigest())
	}
	if r.FindingsTotal() != 500 || r.FindingsSkipped() != 73 {
		t.Errorf("counts = %d total / %d skipped, want both reported", r.FindingsTotal(), r.FindingsSkipped())
	}
	if r.ComponentsSkipped() != 42 {
		t.Errorf("components skipped = %d, want 42 reported on a refused receipt too", r.ComponentsSkipped())
	}
}

// TestReceipt_Rejected_CarriesReasonAndDetailSeparately pins the two-field rule: the
// reason a consumer switches on and the detail it displays never become one string.
func TestReceipt_Rejected_CarriesReasonAndDetailSeparately(t *testing.T) {
	var r domain.Receipt
	if err := r.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
	const detail = "finding[0]: 'cve' is required"
	if err := r.Rejected(domain.ReasonSchemaInvalid, detail); err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if r.Status() != domain.ReceiptRejected || !r.IsTerminal() {
		t.Fatalf("status=%q terminal=%v", r.Status(), r.IsTerminal())
	}
	if r.Reason() != domain.ReasonSchemaInvalid {
		t.Errorf("reason = %q", r.Reason())
	}
	if r.Detail() != detail {
		t.Errorf("detail = %q, want the elaboration alone with no reason prefix", r.Detail())
	}
	if r.EvidenceID() != "" {
		t.Errorf("a rejected receipt names no evidence, got %q", r.EvidenceID())
	}
}

// TestReceipt_Rejected_RefusesAnUnnamedReason — an unnamed refusal is the defect the
// closed taxonomy exists to prevent, so the domain will not record one.
func TestReceipt_Rejected_RefusesAnUnnamedReason(t *testing.T) {
	var r domain.Receipt
	if err := r.Rejected("made_up_reason", "whatever"); err == nil {
		t.Fatal("want an error for a reason outside the taxonomy")
	}
	if r.Status() != "" {
		t.Errorf("a refused rejection must not change the status, got %q", r.Status())
	}
}

// TestReceipt_Failed_IsNotARefusal — a failure is a statement about Themis, so it
// carries a detail and NO reason.
func TestReceipt_Failed_IsNotARefusal(t *testing.T) {
	var r domain.Receipt
	if err := r.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := r.Failed("store: connection refused"); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if r.Status() != domain.ReceiptFailed || !r.IsTerminal() {
		t.Fatalf("status=%q terminal=%v", r.Status(), r.IsTerminal())
	}
	if r.Reason() != "" {
		t.Errorf("a failure names no refusal reason, got %q", r.Reason())
	}
	if r.Detail() == "" {
		t.Error("a failure must say what happened")
	}
}

// TestReceipt_Filed_RefusesAnEmptyEvidenceID — "filed, pointing at nothing" is the
// 2026-10-05 shape and must not be representable.
func TestReceipt_Filed_RefusesAnEmptyEvidenceID(t *testing.T) {
	var r domain.Receipt
	if err := r.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := r.Filed("", true); err == nil {
		t.Fatal("want an error when filing names no evidence")
	}
	if r.Status() != domain.ReceiptAccepted {
		t.Errorf("status = %q, want the receipt untouched", r.Status())
	}
}

// TestReceipt_TerminalImmutability_FiledRefuseFurther — a terminal receipt is the
// record of what happened, and a record that can still change is not one.
func TestReceipt_TerminalImmutability_FiledRefuseFurther(t *testing.T) {
	terminals := map[string]func() *domain.Receipt{
		"filed": func() *domain.Receipt {
			r := &domain.Receipt{}
			mustAccept(t, r)
			if err := r.Filed("ev-9", false); err != nil {
				t.Fatalf("filed: %v", err)
			}
			return r
		},
		"rejected": func() *domain.Receipt {
			r := &domain.Receipt{}
			mustAccept(t, r)
			if err := r.Rejected(domain.ReasonEmptyReport, "zero findings"); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			return r
		},
		"failed": func() *domain.Receipt {
			r := &domain.Receipt{}
			mustAccept(t, r)
			if err := r.Failed("boom"); err != nil {
				t.Fatalf("failed: %v", err)
			}
			return r
		},
	}

	for name, build := range terminals {
		t.Run(name, func(t *testing.T) {
			r := build()
			before := *r

			attempts := map[string]func() error{
				"accept":      r.Accept,
				"validating":  r.StartValidating,
				"converting":  r.StartConverting,
				"registering": r.StartRegistering,
				"filed":       func() error { return r.Filed("ev-other", true) },
				"rejected":    func() error { return r.Rejected(domain.ReasonSourceInvalid, "late") },
				"failed":      func() error { return r.Failed("late") },
				"detected":    func() error { return r.RecordDetected("sbom", "spdx") },
				"release":     func() error { return r.RecordRelease("rel-other") },
				"conversion":  func() error { return r.RecordConversion("cortex@2", "deadbeef", 1, 0) },
				"skipped":     func() error { return r.RecordComponentsSkipped(3) },
			}
			for what, attempt := range attempts {
				if err := attempt(); err == nil {
					t.Errorf("%s on a %s receipt: want an error", what, name)
				}
			}
			if *r != before {
				t.Errorf("a terminal receipt was mutated: %+v -> %+v", before, *r)
			}
		})
	}
}

// TestReceipt_IllegalTransitions_ReturnError — the ladder is forward-only, and that
// includes repeating the step you are already on.
func TestReceipt_IllegalTransitions_ReturnError(t *testing.T) {
	cases := []struct {
		name  string
		setUp []func(*domain.Receipt) error
		try   func(*domain.Receipt) error
	}{
		{
			name: "validating before accepted",
			try:  (*domain.Receipt).StartValidating,
		},
		{
			name: "registering before accepted",
			try:  (*domain.Receipt).StartRegistering,
		},
		{
			name:  "accept twice",
			setUp: []func(*domain.Receipt) error{(*domain.Receipt).Accept},
			try:   (*domain.Receipt).Accept,
		},
		{
			name: "converting back to validating",
			setUp: []func(*domain.Receipt) error{
				(*domain.Receipt).Accept,
				(*domain.Receipt).StartValidating,
				(*domain.Receipt).StartConverting,
			},
			try: (*domain.Receipt).StartValidating,
		},
		{
			name: "registering back to accepted",
			setUp: []func(*domain.Receipt) error{
				(*domain.Receipt).Accept,
				(*domain.Receipt).StartValidating,
				(*domain.Receipt).StartRegistering,
			},
			try: (*domain.Receipt).Accept,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &domain.Receipt{}
			for i, step := range c.setUp {
				if err := step(r); err != nil {
					t.Fatalf("setup step %d: %v", i, err)
				}
			}
			before := r.Status()
			if err := c.try(r); err == nil {
				t.Fatalf("want an error, status stayed %q", r.Status())
			}
			if r.Status() != before {
				t.Errorf("a refused transition changed the status: %q -> %q", before, r.Status())
			}
		})
	}
}

// TestRejectError_CarriesTheReasonAcrossAPortBoundary — how a collaborator outside
// the domain reports a refusal BY NAME without the inner rings learning its error
// vocabulary.
func TestRejectError_CarriesTheReasonAcrossAPortBoundary(t *testing.T) {
	err := domain.Reject(domain.ReasonMalformedBody, "body opens as a JSON array but does not parse")

	re, ok := domain.AsReject(err)
	if !ok {
		t.Fatal("AsReject did not recognise its own error")
	}
	if re.Reason != domain.ReasonMalformedBody {
		t.Errorf("reason = %q", re.Reason)
	}
	if re.Detail == "" {
		t.Error("detail lost")
	}
	if got := err.Error(); got != "malformed_body: body opens as a JSON array but does not parse" {
		t.Errorf("Error() = %q", got)
	}

	// Wrapped, because a port implementation will add context.
	if re, ok := domain.AsReject(fmt.Errorf("convert cortex-json: %w", err)); !ok || re.Reason != domain.ReasonMalformedBody {
		t.Errorf("wrapped: ok=%v reason=%q", ok, re.Reason)
	}

	// An error that names no reason is an infrastructure fault, and no reason may be
	// invented for it.
	if _, ok := domain.AsReject(errors.New("dial tcp: connection refused")); ok {
		t.Error("a plain error must not read as a refusal")
	}
}

func mustAccept(t *testing.T, r *domain.Receipt) {
	t.Helper()
	if err := r.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
}

package http

import (
	"net/http"
	"testing"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// TestStatusForReason_IsD11sTableAndNothingElse walks the closed taxonomy against the
// table directly, so a reason added without a status fails HERE — at the mapping —
// and not later as a surprising 422 on the wire.
func TestStatusForReason_IsD11sTableAndNothingElse(t *testing.T) {
	for _, reason := range domain.AllRejectReasons() {
		if _, ok := httpStatusFor[reason]; !ok {
			t.Errorf("reason %q has no status; D11's table and the enum must grow together", reason)
		}
	}
	if len(httpStatusFor) != len(domain.AllRejectReasons()) {
		t.Errorf("the table maps %d reasons and the taxonomy has %d", len(httpStatusFor), len(domain.AllRejectReasons()))
	}
}

// TestStatusForReason_AnUnmappedReasonIs422 — unreachable through the domain, which
// refuses a reason outside the closed taxonomy, and asserted because the alternative
// to a stated fallback is a zero status code. 422 rather than 500: the document was
// understood and declined, and an unmapped reason is a contract gap on our side.
func TestStatusForReason_AnUnmappedReasonIs422(t *testing.T) {
	if got := statusForReason(domain.RejectReason("invented")); got != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", got)
	}
}

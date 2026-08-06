package inbound

import (
	"encoding/json"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Group 3's deliverable is that the trust class survives the seam, so it is asserted on the
// decode itself: nothing downstream consumes it until the constitutional check (group 4), so
// there is no observable Finding change to assert against yet.
func TestFaultlineEnrichedDTO_DecodesTrustClasses(t *testing.T) {
	raw := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2024-1","Severity":"high",` +
		`"HeadlineTrust":"observed","RangeTrust":"asserted","SignalTrust":"inferred"}`)

	var dto faultlineEnrichedDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, tc := range []struct {
		field string
		got   string
		want  value.TrustClass
	}{
		{"HeadlineTrust", dto.HeadlineTrust, value.TrustObserved},
		{"RangeTrust", dto.RangeTrust, value.TrustAsserted},
		{"SignalTrust", dto.SignalTrust, value.TrustInferred},
	} {
		if value.TrustClass(tc.got) != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
}

// A payload published before the trust fields existed must still decode — the change is
// additive on v1, and in-flight events from an older node keep flowing during a rollout.
// The classes come back unset, which is safe: value.MaxTrust reads unset as Inferred, the
// most conservative answer, so nothing downstream can mistake "absent" for "trusted".
func TestFaultlineEnrichedDTO_OlderPayloadDecodesWithUnsetTrust(t *testing.T) {
	raw := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2024-1","Severity":"high","KEV":true,"Score":90}`)

	var dto faultlineEnrichedDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dto.Score != 90 || !dto.KEV {
		t.Fatalf("precondition: older fields lost — Score=%d KEV=%v", dto.Score, dto.KEV)
	}
	if dto.HeadlineTrust != "" || dto.RangeTrust != "" || dto.SignalTrust != "" {
		t.Errorf("expected unset trust on an older payload, got %q / %q / %q",
			dto.HeadlineTrust, dto.RangeTrust, dto.SignalTrust)
	}
	if got := value.MaxTrust(value.TrustClass(dto.HeadlineTrust)); got != value.TrustInferred {
		t.Errorf("unset trust must degrade to %q, got %q", value.TrustInferred, got)
	}
}

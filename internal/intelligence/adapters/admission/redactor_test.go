package admission_test

import (
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/admission"
)

func TestBasicRedactor(t *testing.T) {
	r := admission.NewBasicRedactor()
	cases := map[string]string{
		"the password=hunter2 stays local":      "the password=[REDACTED] stays local",
		"api_key: sk-abc123XYZ used by the tool": "api_key=[REDACTED] used by the tool",
		"reach us at jane.doe@example.com please": "reach us at [REDACTED] please",
		"no secrets in this prompt at all":        "no secrets in this prompt at all",
	}
	for in, want := range cases {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

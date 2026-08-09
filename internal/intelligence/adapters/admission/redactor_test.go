package admission_test

import (
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/admission"
)

func TestBasicRedactor(t *testing.T) {
	r := admission.NewBasicRedactor()
	cases := map[string]string{
		"the password=hunter2 stays local":        "the password=[REDACTED] stays local",
		"api_key: sk-abc123XYZ used by the tool":  "api_key=[REDACTED] used by the tool",
		"reach us at jane.doe@example.com please": "reach us at [REDACTED] please",
		"no secrets in this prompt at all":        "no secrets in this prompt at all",
	}
	for in, want := range cases {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// A purl must survive redaction intact. Measured on a live estate 2026-08-09: the email pattern
// masked the package name out of the middle of its own identifier, and EVERY recommend_position
// on a module-stream component was refused with business_invalid — surfacing as "the AI declined".
func TestRedactLeavesPurlsIntact(t *testing.T) {
	for _, p := range []string{
		// The exact live case: version ends `.module`, which the email pattern read as a TLD.
		"pkg:rpm/rocky/javapackages-filesystem@5.3.0-2.module%2Bel8.3.0%2B125%2B5da1ae29?arch=noarch&distro=rocky-8.10",
		"pkg:rpm/rocky/python3-pyyaml@3.12-12.el8?arch=x86_64",
		"pkg:maven/org.springframework/spring-core@5.3.0.RELEASE",
		"pkg:pypi/setuptools@39.2.0",
		"pkg:npm/%40scope/pkg@1.0.0",
	} {
		if got := (admission.BasicRedactor{}).Redact(p); got != p {
			t.Errorf("purl was altered:\n  in:  %s\n  out: %s", p, got)
		}
	}
	// A purl embedded in prose keeps its shape while real PII beside it is still masked.
	in := "component pkg:rpm/rocky/javapackages-filesystem@5.3.0-2.module reported by alice@example.com"
	got := (admission.BasicRedactor{}).Redact(in)
	if !strings.Contains(got, "pkg:rpm/rocky/javapackages-filesystem@5.3.0-2.module") {
		t.Errorf("purl mangled in prose: %s", got)
	}
	if strings.Contains(got, "alice@example.com") {
		t.Errorf("a real email must still be masked: %s", got)
	}
}

// Protecting purls must not become a hiding place for the OTHER pattern: a key/value secret in
// ordinary prose is still masked, and several purls in one prompt are each restored correctly.
func TestRedactStillMasksSecretsAroundPurls(t *testing.T) {
	in := "pkg:pypi/a@1.0 password=hunter2 pkg:pypi/b@2.0 token: abc123 pkg:pypi/c@3.0"
	got := (admission.BasicRedactor{}).Redact(in)
	for _, want := range []string{"pkg:pypi/a@1.0", "pkg:pypi/b@2.0", "pkg:pypi/c@3.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("purl %s lost: %s", want, got)
		}
	}
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abc123") {
		t.Errorf("secrets must still be masked: %s", got)
	}
}

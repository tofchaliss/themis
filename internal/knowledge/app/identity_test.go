package app_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// EDR-IDENTITY-01 D1: Knowledge must be able to tell an IDENTITY from a string. It could not
// before — `value.NewPURL` was called only in Evidence — which is how `app:httpd` travelled all
// the way to a Governance rejection that halts the Knowledge→Governance stream.
func TestUsablePURL(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
		why  string
	}{
		{"pkg:rpm/rocky/httpd@2.4.57", true, "the measured good twin"},
		{"pkg:pypi/setuptools@39.2.0", true, "an ordinary language package"},
		{"  pkg:rpm/rocky/httpd@2.4.57  ", true, "surrounding whitespace is not a defect"},
		{"app:httpd", false, "THE measured bad identifier — non-empty and not an identity"},
		{"", false, "an empty PURL is not an identity (D1), and collapses to the same outcome"},
		{"httpd", false, "a bare name is a name, not an identity"},
		{"pkg:", false, "a scheme alone identifies nothing"},
	} {
		if got := app.UsablePURL(c.in); got != c.want {
			t.Errorf("UsablePURL(%q) = %v, want %v — %s", c.in, got, c.want, c.why)
		}
	}
}

// EDR-IDENTITY-01 D2: resolve onto an unambiguous twin; abstain otherwise. The measured basis is
// one SPDX document carrying the same httpd package twice — once with a proper rpm purl, once
// with no externalRefs at all, same name, same versionInfo.
func TestResolveIdentity(t *testing.T) {
	good := app.InventoryComponent{
		PURL: "pkg:rpm/rocky/httpd@2.4.57", Name: "httpd", Version: "2.4.57", Ecosystem: "rpm",
	}
	obs := app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"}

	t.Run("exactly one candidate resolves — the measured case", func(t *testing.T) {
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{good})
		if purl != good.PURL || reason != "" {
			t.Errorf("= %q/%q, want the twin's purl and no reason", purl, reason)
		}
	})

	t.Run("case differs on the name but not the version", func(t *testing.T) {
		upper := app.InventoryComponent{PURL: "app:HTTPD", Name: "HTTPD", Version: "2.4.57"}
		if purl, _ := app.ResolveIdentity(upper, []app.InventoryComponent{good}); purl != good.PURL {
			t.Errorf("= %q, want the twin — a distro is inconsistent about case", purl)
		}
	})

	t.Run("two DISTINCT purls abstain — no tie-break is invented", func(t *testing.T) {
		other := good
		other.PURL = "pkg:rpm/rhel/httpd@2.4.57"
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{good, other})
		if purl != "" || reason != app.ReasonAmbiguous {
			t.Errorf("= %q/%q, want abstain/ambiguous", purl, reason)
		}
	})

	t.Run("the SAME purl twice is not ambiguity", func(t *testing.T) {
		if purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{good, good}); purl != good.PURL {
			t.Errorf("= %q/%q, want the twin — one identity observed twice is still one", purl, reason)
		}
	})

	t.Run("zero candidates abstain — the scanner-only release (D8)", func(t *testing.T) {
		purl, reason := app.ResolveIdentity(obs, nil)
		if purl != "" || reason != app.ReasonNoCandidate {
			t.Errorf("= %q/%q, want abstain/no_candidate", purl, reason)
		}
	})

	t.Run("a different VERSION is a different build and must never resolve", func(t *testing.T) {
		older := good
		older.Version, older.PURL = "2.4.53", "pkg:rpm/rocky/httpd@2.4.53"
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{older})
		if purl != "" || reason != app.ReasonNoCandidate {
			t.Errorf("= %q/%q, want abstain — resolving onto another build is the one error to avoid", purl, reason)
		}
	})

	t.Run("a candidate with no usable purl cannot lend one", func(t *testing.T) {
		twinless := app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"}
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{twinless})
		if purl != "" || reason != app.ReasonNoCandidate {
			t.Errorf("= %q/%q, want abstain — two unidentified rows do not make an identity", purl, reason)
		}
	})

	t.Run("a name alone is never enough", func(t *testing.T) {
		for _, bad := range []app.InventoryComponent{
			{PURL: "app:httpd", Name: "httpd"},
			{PURL: "app:httpd", Version: "2.4.57"},
		} {
			// Matching on a name alone would merge every version of a package onto one
			// identity — the same shape as the empty-purl primary-key collapse.
			if purl, reason := app.ResolveIdentity(bad, []app.InventoryComponent{good}); purl != "" || reason != app.ReasonNoCandidate {
				t.Errorf("%+v = %q/%q, want abstain", bad, purl, reason)
			}
		}
	})

	t.Run("no synthesized purl appears anywhere (D3)", func(t *testing.T) {
		purl, _ := app.ResolveIdentity(obs, nil)
		if purl != "" {
			t.Errorf("abstention returned %q — a synthesized identity is the one thing D3 forbids", purl)
		}
	})
}

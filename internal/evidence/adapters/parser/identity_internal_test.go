package parser

import (
	"testing"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func mustPURL(t *testing.T, s string) value.PURL {
	t.Helper()
	p, err := value.NewPURL(s)
	if err != nil {
		t.Fatalf("purl %q: %v", s, err)
	}
	return p
}

// EDR-IDENTITY-01 D2 at the document door. The measured basis: one SPDX file carries httpd twice
// — once with a proper rpm purl, once with no externalRefs at all, same name and versionInfo.
func TestResolveTwins(t *testing.T) {
	httpd := domain.Component{
		PURL: mustPURL(t, "pkg:rpm/rocky/httpd@2.4.57"), Name: "httpd", Version: "2.4.57", Ecosystem: "rpm",
	}

	t.Run("exactly one identified twin resolves", func(t *testing.T) {
		resolved, unresolved := resolveTwins([]domain.Component{httpd},
			[]pendingPackage{{ID: "SPDXRef-App-httpd", Name: "httpd", Version: "2.4.57"}})
		if len(unresolved) != 0 {
			t.Fatalf("unresolved = %+v, want none", unresolved)
		}
		if got := resolved["SPDXRef-App-httpd"]; got.String() != httpd.PURL.String() {
			t.Errorf("resolved to %q, want the twin's purl", got.String())
		}
	})

	t.Run("case differs on the name, never on the version", func(t *testing.T) {
		resolved, _ := resolveTwins([]domain.Component{httpd},
			[]pendingPackage{{ID: "ref", Name: "HTTPD", Version: "2.4.57"}})
		if _, ok := resolved["ref"]; !ok {
			t.Error("a case difference must not prevent resolution")
		}
		_, unresolved := resolveTwins([]domain.Component{httpd},
			[]pendingPackage{{ID: "ref", Name: "httpd", Version: "2.4.53"}})
		if len(unresolved) != 1 {
			t.Error("a DIFFERENT version must never resolve — that would be another build")
		}
	})

	t.Run("two distinct identities abstain", func(t *testing.T) {
		other := httpd
		other.PURL = mustPURL(t, "pkg:rpm/rhel/httpd@2.4.57")
		resolved, unresolved := resolveTwins([]domain.Component{httpd, other},
			[]pendingPackage{{ID: "ref", Name: "httpd", Version: "2.4.57"}})
		if len(resolved) != 0 || len(unresolved) != 1 {
			t.Errorf("resolved=%v unresolved=%v, want abstain — no tie-break is invented", resolved, unresolved)
		}
	})

	t.Run("the same identity twice is not ambiguity", func(t *testing.T) {
		resolved, unresolved := resolveTwins([]domain.Component{httpd, httpd},
			[]pendingPackage{{ID: "ref", Name: "httpd", Version: "2.4.57"}})
		if len(resolved) != 1 || len(unresolved) != 0 {
			t.Errorf("resolved=%v unresolved=%v, want one resolution", resolved, unresolved)
		}
	})

	t.Run("no twin abstains, and is RETAINED for counting", func(t *testing.T) {
		resolved, unresolved := resolveTwins([]domain.Component{httpd},
			[]pendingPackage{{ID: "ref", Name: "nginx", Version: "1.24.0", RawPURL: "app:nginx"}})
		if len(resolved) != 0 || len(unresolved) != 1 {
			t.Fatalf("resolved=%v unresolved=%v, want abstain", resolved, unresolved)
		}
		if w := unresolvedWarning(unresolved[0]); w == "" {
			t.Error("an unresolved entry must produce an operator-facing warning (D6)")
		}
	})

	t.Run("a name or version alone is never enough", func(t *testing.T) {
		_, unresolved := resolveTwins([]domain.Component{httpd}, []pendingPackage{
			{ID: "a", Name: "httpd"},
			{ID: "b", Version: "2.4.57"},
		})
		if len(unresolved) != 2 {
			t.Error("matching on a name alone would merge every version onto one identity")
		}
	})

	t.Run("nothing pending is free", func(t *testing.T) {
		resolved, unresolved := resolveTwins([]domain.Component{httpd}, nil)
		if resolved != nil || unresolved != nil {
			t.Error("no pending entries must allocate nothing")
		}
	})

	t.Run("the warning names the raw identifier when there is one", func(t *testing.T) {
		with := unresolvedWarning(pendingPackage{Name: "httpd", Version: "2.4.57", RawPURL: "app:httpd"})
		without := unresolvedWarning(pendingPackage{Name: "httpd", Version: "2.4.57"})
		if with == without {
			t.Error("an offered-but-unusable identifier must be distinguishable from none at all")
		}
	})
}

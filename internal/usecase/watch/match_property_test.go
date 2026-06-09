package watch

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/testutil/gen"
)

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestCompareVersionsLawsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := gen.DottedVersion(t)
		b := gen.DottedVersion(t)
		c := gen.DottedVersion(t)

		if domain.CompareVersions(a, a) != 0 {
			t.Fatalf("not reflexive: compareVersions(%q,%q) != 0", a, a)
		}
		if sign(domain.CompareVersions(a, b)) != -sign(domain.CompareVersions(b, a)) {
			t.Fatalf("not antisymmetric: a=%q b=%q ab=%d ba=%d",
				a, b, domain.CompareVersions(a, b), domain.CompareVersions(b, a))
		}
		if domain.CompareVersions(a, b) == 0 && domain.CompareVersions(b, c) == 0 && domain.CompareVersions(a, c) != 0 {
			t.Fatalf("equality not transitive: a=%q b=%q c=%q", a, b, c)
		}
	})
}

func TestVersionMatchesConsistencyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := gen.DottedVersion(t)
		bound := gen.DottedVersion(t)

		if !VersionMatches(nil, v) {
			t.Fatalf("empty affected should match: v=%q", v)
		}
		if !VersionMatches([]string{"*"}, v) {
			t.Fatalf("wildcard should match: v=%q", v)
		}
		if !VersionMatches([]string{v}, v) {
			t.Fatalf("exact should match: v=%q", v)
		}

		cmp := domain.CompareVersions(v, bound)
		cases := []struct {
			op   string
			want bool
		}{
			{"< ", cmp < 0},
			{"<= ", cmp <= 0},
			{"> ", cmp > 0},
			{">= ", cmp >= 0},
		}
		for _, tc := range cases {
			got := VersionMatches([]string{tc.op + bound}, v)
			if got != tc.want {
				t.Fatalf("VersionMatches(%q%q, %q)=%v want=%v (cmp=%d)",
					tc.op, bound, v, got, tc.want, cmp)
			}
		}
	})
}

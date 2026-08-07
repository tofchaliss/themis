package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

// FixKeys exists because one component genuinely has SEVERAL names across naming authorities,
// and a fix is published under exactly one of them. Rocky ships binary `python3-pyyaml` built
// from source `PyYAML`; Maven's pkg:maven/org.eclipse.jetty/jetty-http is published as
// `org.eclipse.jetty:jetty-http`. Matching on one name alone silently finds nothing, which reads
// as "no fix published" for a component whose fix is right there (AI-GROUND-1).
func TestMatchedComponentFixKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    domain.MatchedComponent
		want []string
	}{
		{
			name: "distro component resolves through its SOURCE package first",
			c: domain.MatchedComponent{
				PURL: "pkg:rpm/rocky/python3-pyyaml@3.12-12.el8", Name: "python3-pyyaml", Source: "PyYAML",
			},
			// "rocky:python3-pyyaml" is the distro qualifier occupying the namespace slot. It is
			// harmless noise — no feed publishes under it — and dropping it would cost a branch
			// for nothing.
			want: []string{"PyYAML", "rocky:python3-pyyaml", "python3-pyyaml"},
		},
		{
			name: "maven resolves through groupId:artifactId",
			c: domain.MatchedComponent{
				PURL: "pkg:maven/org.eclipse.jetty/jetty-http@12.0.27", Name: "jetty-http",
			},
			want: []string{"org.eclipse.jetty:jetty-http", "jetty-http"},
		},
		{
			name: "namespace-less purl yields the bare name only",
			c:    domain.MatchedComponent{PURL: "pkg:pypi/urllib3@1.26.20", Name: "urllib3"},
			want: []string{"urllib3"},
		},
		{
			name: "a purl that is not a purl contributes no namespace",
			c:    domain.MatchedComponent{PURL: "urllib3@1.26.20", Name: "urllib3"},
			want: []string{"urllib3"},
		},
		{
			name: "a purl with no path at all contributes no namespace",
			c:    domain.MatchedComponent{PURL: "pkg:rpm", Name: "glibc"},
			want: []string{"glibc"},
		},
		{
			name: "no name and no source yields no keys — better than matching everything",
			c:    domain.MatchedComponent{PURL: "pkg:maven/org.eclipse.jetty/jetty-http@1"},
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.c.FixKeys()
			if len(got) != len(tc.want) {
				t.Fatalf("FixKeys() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("FixKeys()[%d] = %q, want %q (order is most-specific-first)", i, got[i], tc.want[i])
				}
			}
		})
	}
}

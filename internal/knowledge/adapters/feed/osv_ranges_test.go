package feed

import (
	"reflect"
	"testing"
)

// 2026-10-14: an OSV range is an ORDERED event list, and reading one event at a time split
// `{introduced: 0}, {fixed: 1.4.3}` into `>=0` and `<1.4.3` — two OR'd rules, the first of
// which matches every version ever written. Every stdlib card carried one, so no Go Finding
// could ever be provably out of range.
func TestPairedRanges(t *testing.T) {
	cases := []struct {
		name   string
		events []osvEvent
		want   []string
	}{
		{"introduced then fixed", []osvEvent{{Introduced: "0"}, {Fixed: "1.4.3"}}, []string{">=0,<1.4.3"}},
		{"two intervals", []osvEvent{{Introduced: "0"}, {Fixed: "1.17.12"}, {Introduced: "1.18.0-0"}, {Fixed: "1.18.4"}}, []string{">=0,<1.17.12", ">=1.18.0-0,<1.18.4"}},
		{"last_affected closes", []osvEvent{{Introduced: "1.0"}, {LastAffected: "1.4.2"}}, []string{">=1.0,<=1.4.2"}},
		{"open-ended", []osvEvent{{Introduced: "2.0"}}, []string{">=2.0"}},
		{"closed then open-ended", []osvEvent{{Introduced: "0"}, {Fixed: "1.0"}, {Introduced: "3.0"}}, []string{">=0,<1.0", ">=3.0"}},
		{"two introduceds in a row", []osvEvent{{Introduced: "0"}, {Introduced: "2.0"}, {Fixed: "2.1"}}, []string{">=0", ">=2.0,<2.1"}},
		{"bound with no opening", []osvEvent{{Fixed: "1.0"}}, []string{"<1.0"}},
		{"same event carries both", []osvEvent{{Introduced: "0", Fixed: "1.0"}}, []string{">=0,<1.0"}},
		{"empty", nil, nil},
	}
	for _, c := range cases {
		if got := pairedRanges(c.events); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

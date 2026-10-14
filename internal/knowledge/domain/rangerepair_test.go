package domain_test

import (
	"reflect"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestRepairSplitRanges(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		changed bool
	}{
		{"the measured shape", []string{">=0", "<1.4.3"}, []string{">=0,<1.4.3"}, true},
		{"two intervals", []string{">=0", "<1.17.12", ">=1.18.0-0", "<1.18.4"}, []string{">=0,<1.17.12", ">=1.18.0-0,<1.18.4"}, true},
		{"last_affected upper", []string{">=1.0", "<=1.4.2"}, []string{">=1.0,<=1.4.2"}, true},
		{"already paired", []string{">=0,<1.4.3"}, []string{">=0,<1.4.3"}, false},
		{"open-ended stays", []string{">=2.0"}, []string{">=2.0"}, false},
		{"upper alone stays", []string{"<1.0"}, []string{"<1.0"}, false},
		{"mixed", []string{"<=1.4.2", ">=0", "<1.4.3", ">=3.0"}, []string{"<=1.4.2", ">=0,<1.4.3", ">=3.0"}, true},
		{"empty", nil, []string{}, false},
	}
	for _, c := range cases {
		got, changed := domain.RepairSplitRanges(c.in)
		if !reflect.DeepEqual(got, c.want) || changed != c.changed {
			t.Errorf("%s: %v changed=%v, want %v changed=%v", c.name, got, changed, c.want, c.changed)
		}
	}
}

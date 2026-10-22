package domain_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/registry/domain"
)

func TestNormalizeTags(t *testing.T) {
	got, err := domain.NormalizeTags([]string{" Team:Payments ", "env:prod", "team:payments", "customer-facing"})
	if err != nil || fmt.Sprint(got) != "[customer-facing env:prod team:payments]" {
		t.Fatalf("normalize = %v %v", got, err)
	}
	if got, err := domain.NormalizeTags(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty = %v %v", got, err)
	}
	for _, bad := range []string{"", "has space", "emoji✓", strings.Repeat("a", domain.MaxTagLength+1)} {
		if _, err := domain.NormalizeTags([]string{bad}); !errors.Is(err, domain.ErrInvalidTag) {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, domain.MaxTags+1)
	for i := range many {
		many[i] = fmt.Sprintf("t%d", i)
	}
	if _, err := domain.NormalizeTags(many); !errors.Is(err, domain.ErrInvalidTag) {
		t.Fatal("too many tags accepted")
	}
}

func TestUnionAndHasTag(t *testing.T) {
	u := domain.UnionTags([]string{"b", "a"}, nil, []string{"a", "c"})
	if fmt.Sprint(u) != "[a b c]" {
		t.Fatalf("union = %v", u)
	}
	if !domain.HasTag(u, " B ") || domain.HasTag(u, "z") || !domain.HasTag(nil, "") {
		t.Fatal("HasTag")
	}
}

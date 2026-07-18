package subjectref_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
)

func TestStub_ReleaseExists(t *testing.T) {
	s := subjectref.NewStub("rel-1", "rel-2")

	for _, id := range []string{"rel-1", "rel-2"} {
		ok, err := s.ReleaseExists(context.Background(), id)
		if err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v, want true/nil", id, ok, err)
		}
	}
	ok, err := s.ReleaseExists(context.Background(), "nope")
	if err != nil || ok {
		t.Errorf("nope: ok=%v err=%v, want false/nil", ok, err)
	}
}

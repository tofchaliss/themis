package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestStage_Valid(t *testing.T) {
	for _, s := range []domain.Stage{
		domain.StageCreated, domain.StageEnriched, domain.StageCorrelated, domain.StageMature, domain.StageSuperseded,
	} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if domain.Stage("bogus").Valid() {
		t.Error("bogus stage reported valid")
	}
}

package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestSupportedSBOMFormats(t *testing.T) {
	formats := domain.SupportedSBOMFormats()
	if len(formats) != 5 {
		t.Fatalf("SupportedSBOMFormats() len = %d, want 5", len(formats))
	}
	want := map[string]bool{
		domain.SBOMFormatCycloneDX: true,
		domain.SBOMFormatSPDX:      true,
		domain.SBOMFormatTrivy:     true,
		domain.SBOMFormatGrype:     true,
		domain.SBOMFormatSyft:      true,
	}
	for _, format := range formats {
		if !want[format] {
			t.Fatalf("unexpected format %q", format)
		}
	}
}

func TestParseStatusConstants(t *testing.T) {
	if domain.ParseStatusAccepted == "" || domain.ParseStatusRejected == "" || domain.ParseStatusFailed == "" {
		t.Fatal("parse status constants must be non-empty")
	}
}

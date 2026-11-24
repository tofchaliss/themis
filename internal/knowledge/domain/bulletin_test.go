package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// EDR-PSIRT-01 revision 3: the admin's input is trimmed and checked; the CVE is canonical; the
// report date is a day; Type is derived; only an admin edits today.
func TestNormalizeBulletin(t *testing.T) {
	got, err := domain.NormalizeBulletin(domain.BulletinInput{
		BulletinID: " BUL-0001 ", Title: " A flaw ", BulletinURL: "https://example.com/b/1",
		AlertURL: "http://example.com/a", Note: " n ", CVE: " cve-2026-1234 ",
		ReportDate: time.Date(2026, 11, 24, 15, 4, 0, 0, time.FixedZone("x", 3600)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.BulletinID != "BUL-0001" || got.Title != "A flaw" || got.Note != "n" || got.CVE != "CVE-2026-1234" ||
		!got.ReportDate.Equal(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("normalized = %+v", got)
	}
	if b := (domain.Bulletin{BulletinInput: got}); b.Type() != domain.BulletinTypeVulnerability {
		t.Errorf("with a CVE: %s", b.Type())
	}
	risk, err := domain.NormalizeBulletin(domain.BulletinInput{BulletinID: "R-1", Title: "Key compromise"})
	if err != nil || risk.CVE != "" || !risk.ReportDate.IsZero() || (domain.Bulletin{BulletinInput: risk}).Type() != domain.BulletinTypeRisk {
		t.Errorf("no CVE: %+v %v", risk, err)
	}

	long := func(n int) string { return strings.Repeat("x", n) }
	for name, in := range map[string]domain.BulletinInput{
		"no id":         {Title: "t"},
		"long id":       {BulletinID: long(65), Title: "t"},
		"no title":      {BulletinID: "b"},
		"long title":    {BulletinID: "b", Title: long(301)},
		"long note":     {BulletinID: "b", Title: "t", Note: long(4001)},
		"script link":   {BulletinID: "b", Title: "t", BulletinURL: "javascript:alert(1)"},
		"relative link": {BulletinID: "b", Title: "t", AlertURL: "/path"},
		"bad url":       {BulletinID: "b", Title: "t", AlertURL: "http://%zz"},
		"long link":     {BulletinID: "b", Title: "t", BulletinURL: "https://example.com/" + long(2000)},
		"bad cve":       {BulletinID: "b", Title: "t", CVE: "not-a-cve"},
	} {
		if _, err := domain.NormalizeBulletin(in); !errors.Is(err, domain.ErrBulletinInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCanEditBulletin(t *testing.T) {
	if !domain.CanEditBulletin(domain.BulletinEditor{Admin: true}) {
		t.Error("an admin edits")
	}
	if domain.CanEditBulletin(domain.BulletinEditor{Products: []string{"p1"}}) {
		t.Error("a product-scoped user does not edit yet (R2)")
	}
}

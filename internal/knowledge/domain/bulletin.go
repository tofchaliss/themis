package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// The PSIRT bulletin register (EDR-PSIRT-01 revision 3). A bulletin is the team's own write-up of
// an issue: an admin types its number, title, links and a note, and may tie it to one CVE. It is
// what a person wrote, so storing it keeps EDR-KNOWLEDGE-01 D5 (the world feed is never stored).

// Bulletin types (R6): derived, never typed.
const (
	BulletinTypeVulnerability = "Vulnerability"
	BulletinTypeRisk          = "Risk"
)

// Field bounds: generous for a person typing, small enough that a page of bulletins stays a page.
const (
	maxBulletinIDLen = 64
	maxTitleLen      = 300
	maxURLLen        = 2000
	maxNoteLen       = 4000
)

// ErrBulletinInvalid is wrapped by every input check, so a caller can answer 400 with the reason.
var ErrBulletinInvalid = errors.New("invalid bulletin")

// BulletinInput is what an admin types (R1), plus the CVE it is about and its report date.
type BulletinInput struct {
	BulletinID  string
	Title       string
	BulletinURL string
	AlertURL    string
	Note        string
	CVE         string
	ReportDate  time.Time // zero: the day it is created
}

// Bulletin is one entry of the register, as stored.
type Bulletin struct {
	ID string
	BulletinInput
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// Type is derived (R6): a bulletin about a CVE is a Vulnerability, one without is a Risk.
func (b Bulletin) Type() string {
	if b.CVE != "" {
		return BulletinTypeVulnerability
	}
	return BulletinTypeRisk
}

// NormalizeBulletin trims and checks an admin's input: a bulletin ID and a title are required;
// links must be absolute http(s) URLs; a CVE, when given, must be a CVE id and is stored in its
// canonical spelling; the report date is kept as a day (UTC midnight).
func NormalizeBulletin(in BulletinInput) (BulletinInput, error) {
	out := BulletinInput{
		BulletinID:  strings.TrimSpace(in.BulletinID),
		Title:       strings.TrimSpace(in.Title),
		BulletinURL: strings.TrimSpace(in.BulletinURL),
		AlertURL:    strings.TrimSpace(in.AlertURL),
		Note:        strings.TrimSpace(in.Note),
	}
	switch {
	case out.BulletinID == "":
		return BulletinInput{}, fmt.Errorf("%w: bulletin_id is required", ErrBulletinInvalid)
	case len(out.BulletinID) > maxBulletinIDLen:
		return BulletinInput{}, fmt.Errorf("%w: bulletin_id is longer than %d characters", ErrBulletinInvalid, maxBulletinIDLen)
	case out.Title == "":
		return BulletinInput{}, fmt.Errorf("%w: title is required", ErrBulletinInvalid)
	case len(out.Title) > maxTitleLen:
		return BulletinInput{}, fmt.Errorf("%w: title is longer than %d characters", ErrBulletinInvalid, maxTitleLen)
	case len(out.Note) > maxNoteLen:
		return BulletinInput{}, fmt.Errorf("%w: note is longer than %d characters", ErrBulletinInvalid, maxNoteLen)
	}
	for name, u := range map[string]string{"bulletin_url": out.BulletinURL, "alert_url": out.AlertURL} {
		if err := checkLink(u); err != nil {
			return BulletinInput{}, fmt.Errorf("%w: %s %v", ErrBulletinInvalid, name, err)
		}
	}
	if c := strings.TrimSpace(in.CVE); c != "" {
		id, err := value.NewCVEID(c)
		if err != nil {
			return BulletinInput{}, fmt.Errorf("%w: cve %q is not a CVE id", ErrBulletinInvalid, c)
		}
		out.CVE = id.String()
	}
	if !in.ReportDate.IsZero() {
		y, m, d := in.ReportDate.UTC().Date()
		out.ReportDate = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	}
	return out, nil
}

// checkLink accepts an empty link or an absolute http(s) URL with a host. Anything else (a
// javascript: or file: link, a relative path) would be rendered as a link on the page.
func checkLink(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > maxURLLen {
		return fmt.Errorf("is longer than %d characters", maxURLLen)
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("must be an http or https link")
	}
	return nil
}

// BulletinEditor is who asks to change the register: an admin, and (a later step, R2) the
// products a product-scoped user may act for.
type BulletinEditor struct {
	Admin    bool
	Products []string
}

// CanEditBulletin is the one edit rule (R2). Today only an admin edits, for every product. A
// later step can let a product-scoped user edit the bulletins of its products, here and only here.
func CanEditBulletin(e BulletinEditor) bool {
	return e.Admin
}

package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EventType is the one event type the connector acts on (D18 item 5).
const EventType = "themis.rebuild.requested.v1"

// SignatureHeader carries "sha256=<hex HMAC-SHA256 of the body>".
const SignatureHeader = "X-Themis-Signature"

// Event is the request as the connector reads it. The fields it does not need are not read.
type Event struct {
	Type string    `json:"type"`
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	Data struct {
		ProductID   string `json:"product_id"`
		ProjectID   string `json:"project_id"`
		ReleaseID   string `json:"release_id"`
		PriorSBOMID string `json:"prior_sbom_id"`
		Attempt     int    `json:"attempt"`
		Targeted    []struct {
			CVE string `json:"cve"`
		} `json:"targeted"`
		Build *struct {
			Job        string         `json:"job"`
			Parameters map[string]any `json:"parameters"`
		} `json:"build"`
	} `json:"data"`
}

// VerifySignature checks the header against the body, in constant time.
func VerifySignature(header string, body []byte, secret string) bool {
	const prefix = "sha256="
	if secret == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// Sign returns the header value for a body. Themis does this on its side; the connector uses
// it in its tests.
func Sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// ParseEvent reads the body. An event with no id cannot be recorded and is an error.
func ParseEvent(body []byte) (Event, error) {
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return Event{}, errors.New("the body is not a JSON event")
	}
	if strings.TrimSpace(ev.ID) == "" || len(ev.ID) > 200 {
		return Event{}, errors.New("the event has no usable id")
	}
	return ev, nil
}

// authorize runs the checks of D18 and D31 on an event and returns the job and the parameters
// to pass. A non-nil error is the reason of a refusal; it never contains a secret.
func (c Config) authorize(ev Event, now time.Time) (job string, params map[string]string, err error) {
	if ev.Type != EventType {
		return "", nil, fmt.Errorf("the event type %q is not known", clip(ev.Type))
	}
	if ev.Time.IsZero() || now.Sub(ev.Time) > time.Duration(c.MaxEventAge) {
		return "", nil, fmt.Errorf("the event is older than %s", time.Duration(c.MaxEventAge))
	}
	if ev.Data.Build == nil || ev.Data.Build.Job == "" {
		return "", nil, errors.New("the build profile names no job")
	}
	job = ev.Data.Build.Job
	if !c.jobAllowed(ev.Data.ProductID, ev.Data.ProjectID, job) {
		return "", nil, fmt.Errorf("the job %q is not allowed for this product and project", clip(job))
	}
	params, err = profileParams(ev.Data.Build.Parameters)
	if err != nil {
		return "", nil, err
	}
	for name := range params {
		if strings.HasPrefix(name, reservedPrefix) {
			return "", nil, fmt.Errorf("parameter %q is set by the connector and cannot come from the build profile", clip(name))
		}
	}
	if err := c.Jobs[job].checkParams(params); err != nil {
		return "", nil, err
	}
	// The facts the connector adds itself. They come from the signed event and are checked
	// like every other value.
	cves := map[string]bool{}
	for _, t := range ev.Data.Targeted {
		if !reCVE.MatchString(t.CVE) {
			return "", nil, errors.New("a targeted entry carries no valid CVE id")
		}
		cves[t.CVE] = true
	}
	list := make([]string, 0, len(cves))
	for cve := range cves {
		list = append(list, cve)
	}
	sort.Strings(list)
	own := map[string]string{
		"THEMIS_INTENT_ID": ev.ID, "THEMIS_PRODUCT_ID": ev.Data.ProductID, "THEMIS_PROJECT_ID": ev.Data.ProjectID,
		"THEMIS_RELEASE_ID": ev.Data.ReleaseID, "THEMIS_PRIOR_SBOM_ID": ev.Data.PriorSBOMID,
		"THEMIS_ATTEMPT": strconv.Itoa(ev.Data.Attempt),
	}
	idRule := ParamRule{Rule: RuleText, MaxLen: 200}
	for name, v := range own {
		if err := idRule.check(v); err != nil {
			return "", nil, fmt.Errorf("%s: %w", name, err)
		}
		params[name] = v
	}
	params["THEMIS_TARGETED_CVES"] = strings.Join(list, ",")
	return job, params, nil
}

// clip keeps a value from an event short before it goes into a reason or a log line.
func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

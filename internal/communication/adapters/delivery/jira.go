package delivery

// jira.go is the REAL issue-tracker sender (N-M1b): the first half of the outward path that
// actually leaves the estate. It talks Jira REST over net/http and JSON — no third-party client,
// because the three calls it makes (search, create, update) are not worth a dependency that would
// also have to be trusted with a credential.
//
// TWO JIRA FLAVOURS, one sender. Cloud and Data Center differ in exactly two places, and both are
// configuration rather than code paths of their own:
//
//   - AUTH. Cloud authenticates an account email + API token as HTTP Basic; Data Center issues a
//     Personal Access Token sent as `Authorization: Bearer` with no user at all. `JiraAuth` selects
//     which, and `basic` stays the default so an existing Cloud deployment needs no new variable.
//   - DESCRIPTION. REST v3 (Cloud) takes the description as an Atlassian Document Format value;
//     REST v2 (Data Center) takes a plain string. `JiraAPIVersion` selects the path prefix AND the
//     description encoding together, because they are not independent — v2 with an ADF object is a
//     400, and v3 with a string is a 400 the other way.
//
// Everything else is shared, deliberately: the same JQL label search, the same full-replace update,
// the same one-ticket-per-Release rule. A flavour that forked the SEARCH would be a flavour where
// one-ticket-per-Release had to be proved twice; both are proved against both.
//
// The base URL may carry a PATH — `https://jira.example.com/jira` is how a self-hosted instance is
// usually mounted — so every endpoint is built by appending to it, never by replacing its path.
//
// ONE TICKET PER RELEASE (RC-2) is realized in two places, and both are needed. The intent
// mapping enqueues one ticket intent per Release-scoped trigger, and this sender LOOKS FOR the
// Release's existing issue before creating one. The lookup is by LABEL — `themis-release-<id>`,
// matched exactly by JQL — rather than by a summary text search: `summary ~ "<uuid>"` depends on
// how Jira tokenizes a hyphenated id, and a near-miss there does not fail, it silently opens a
// second ticket for a Release that already had one.
//
// The update is a FULL REPLACE of the summary and description from the snapshot, which is what
// makes it idempotent by construction: applying it twice leaves the issue in the same state, so
// a retry after a timeout whose PUT actually landed costs nothing.
//
// Honest limit, recorded rather than hidden: first-run idempotence depends on the project being
// SEARCHABLE by the configured credential. A credential that may create but not search will
// create a second issue on the next cycle. The issue key is recorded on the intent's delivery
// result, so the ticket a given intent landed on is always answerable after the fact.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Jira defaults. The issue type is "Task" because every Jira project template has one; a project
// using a different vocabulary sets the knob.
const (
	defaultJiraIssueType = "Task"
	defaultJiraTimeout   = 15 * time.Second
	// defaultJiraAPIVersion is 3 — Jira Cloud, which is what an unconfigured deployment is most
	// likely to be and what shipped first. Data Center sets 2.
	defaultJiraAPIVersion = 3
	// jiraLabelPrefix opens the per-Release label the one-ticket rule is read off.
	jiraLabelPrefix = "themis-release-"
	// jiraLabel marks every issue this sender touches, so an operator can find them all.
	jiraLabel = "themis"
	// excerptLimit caps how much of a refusal body is recorded on the attempt ledger.
	excerptLimit = 240
)

// JiraAuth is how the sender presents its credential. The vocabulary is CLOSED: an unrecognized
// value is refused at configure time rather than silently falling back, because the fallback would
// be "send a Data Center PAT as a Basic password", which authenticates as nobody and reads as a
// permissions problem.
type JiraAuth string

const (
	// JiraAuthBasic is Jira CLOUD: the account email + API token as HTTP Basic. The default.
	JiraAuthBasic JiraAuth = "basic"
	// JiraAuthBearer is Jira DATA CENTER / Server: a Personal Access Token in
	// `Authorization: Bearer`. No user is involved — the token identifies its owner — so
	// THEMIS_COMMUNICATION_JIRA_USER is neither needed nor read.
	JiraAuthBearer JiraAuth = "bearer"
)

// JiraConfig configures the real Jira sender, for either flavour. Every credential comes from the
// environment; none is ever written to a configuration file, a log line or a payload.
type JiraConfig struct {
	// Enabled turns the real sender on. Off (the default) keeps the fake wired: no network.
	Enabled bool
	// BaseURL is where Jira is mounted. Cloud: "https://acme.atlassian.net". Data Center is often
	// behind a path: "https://jira.acme.example/jira" — the path is PRESERVED, so every REST
	// endpoint is appended to it.
	BaseURL string
	// ProjectKey is the project tickets are created in, e.g. "SEC".
	ProjectKey string
	// Auth is how the credential is presented: `basic` (Cloud, default) or `bearer` (Data Center).
	Auth JiraAuth
	// APIVersion is the Jira REST major version: 3 (Cloud, default) or 2 (Data Center). It selects
	// the path prefix AND the description encoding, which are not independent.
	APIVersion int
	// User is the Jira account email the API token belongs to. Required for `basic`; UNUSED for
	// `bearer`, where the token identifies its own owner.
	User string
	// APIToken is the credential: a Cloud API token under `basic`, a Data Center Personal Access
	// Token under `bearer`. SECRET — environment only.
	APIToken string
	// IssueType is the issue type name to create (default "Task").
	IssueType string
	// Timeout bounds one HTTP call (default 15s).
	Timeout time.Duration
}

func jiraFromEnv() JiraConfig {
	return JiraConfig{
		Enabled:    envBool("THEMIS_COMMUNICATION_JIRA_ENABLED", false),
		BaseURL:    strings.TrimRight(getenv("THEMIS_COMMUNICATION_JIRA_BASE_URL"), "/"),
		ProjectKey: getenv("THEMIS_COMMUNICATION_JIRA_PROJECT_KEY"),
		// Auth and APIVersion are resolved to their EFFECTIVE values here rather than left blank for
		// withDefaults, because this is what the startup log line prints: an operator debugging a
		// wrong-flavour deployment must be able to read the flavour the node actually chose.
		Auth:       jiraAuthFromEnv(),
		APIVersion: envInt("THEMIS_COMMUNICATION_JIRA_API_VERSION", defaultJiraAPIVersion),
		User:       getenv("THEMIS_COMMUNICATION_JIRA_USER"),
		APIToken:   getenv("THEMIS_COMMUNICATION_JIRA_API_TOKEN"),
		IssueType:  getenv("THEMIS_COMMUNICATION_JIRA_ISSUE_TYPE"),
		Timeout:    envDuration("THEMIS_COMMUNICATION_JIRA_TIMEOUT", defaultJiraTimeout),
	}
}

// jiraAuthFromEnv reads the auth mode, case-insensitively, defaulting to `basic`. An unrecognized
// value is returned AS GIVEN rather than silently corrected, so checkFlavour can name it back to the
// operator — "bear" must not quietly become "basic".
func jiraAuthFromEnv() JiraAuth {
	raw := strings.ToLower(getenv("THEMIS_COMMUNICATION_JIRA_AUTH"))
	if raw == "" {
		return JiraAuthBasic
	}
	return JiraAuth(raw)
}

func (c JiraConfig) withDefaults() JiraConfig {
	// A trailing slash is trimmed here rather than only when reading the environment, so a
	// hand-built config behaves the same: "…/jira/" + "/rest/api/2" would be a 404 on a path mount.
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if strings.TrimSpace(string(c.Auth)) == "" {
		c.Auth = JiraAuthBasic
	}
	if c.APIVersion == 0 {
		c.APIVersion = defaultJiraAPIVersion
	}
	if strings.TrimSpace(c.IssueType) == "" {
		c.IssueType = defaultJiraIssueType
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultJiraTimeout
	}
	return c
}

// missing lists the environment variables a complete Jira configuration needs and this one lacks.
// It reports NAMES, so the error an operator reads says what to set without quoting what is set.
//
// The USER is required only under `basic`. Demanding it under `bearer` would make an operator invent
// a value for a field the request does not carry.
func (c JiraConfig) missing() []string {
	required := []struct{ name, value string }{
		{"THEMIS_COMMUNICATION_JIRA_BASE_URL", c.BaseURL},
		{"THEMIS_COMMUNICATION_JIRA_PROJECT_KEY", c.ProjectKey},
		{"THEMIS_COMMUNICATION_JIRA_API_TOKEN", c.APIToken},
	}
	if c.Auth != JiraAuthBearer {
		required = append(required, struct{ name, value string }{"THEMIS_COMMUNICATION_JIRA_USER", c.User})
	}
	var out []string
	for _, k := range required {
		if strings.TrimSpace(k.value) == "" {
			out = append(out, k.name)
		}
	}
	return out
}

// checkFlavour refuses an auth mode or an API version this sender does not speak.
//
// Both vocabularies are closed and neither falls back, because both fallbacks fail in a way that
// does not look like a configuration error: an unknown auth mode defaulting to `basic` sends a Data
// Center PAT as a password (401, reads as "the token is wrong"), and an unknown API version
// defaulting to 3 sends ADF to a v2 instance (400 on every attempt, reads as "Jira rejects our
// ticket"). A refusal at startup names the variable instead.
func (c JiraConfig) checkFlavour() error {
	switch c.Auth {
	case JiraAuthBasic, JiraAuthBearer:
	default:
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_JIRA_AUTH %q is not supported (use %q for Jira Cloud "+
			"or %q for Jira Data Center / Server)", c.Auth, JiraAuthBasic, JiraAuthBearer)
	}
	if c.APIVersion != 2 && c.APIVersion != 3 {
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_JIRA_API_VERSION %d is not supported "+
			"(use 3 for Jira Cloud or 2 for Jira Data Center / Server)", c.APIVersion)
	}
	return nil
}

// apiBase is the REST prefix for the configured version, appended to whatever path the base URL
// already carries.
func (c JiraConfig) apiBase() string {
	return "/rest/api/" + strconv.Itoa(c.APIVersion)
}

// checkTransport refuses to carry the API token over a channel that does not protect it.
//
// Jira's credential rides every call, as a Basic password or as a Bearer token, so a `http://` base
// URL puts it on the wire in base64 — which is an encoding, not protection, and a Data Center PAT is
// not even that. This is the same rule the
// mail sender applies to an SMTP password without STARTTLS, drawn in the same place: plain HTTP is
// allowed only to a LOOPBACK host, where the bytes never leave the machine (and where an httptest
// server lives). A scheme that is neither http nor https is refused outright rather than handed to
// net/http to fail later with a message about an unsupported protocol.
//
// Refusing here rather than at send time is deliberate: a misconfiguration that leaks a credential
// must not be discovered by having leaked it once per retry.
func (c JiraConfig) checkTransport() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_JIRA_BASE_URL (%q) is not an absolute URL with a host "+
			"(expected e.g. https://acme.atlassian.net or https://jira.acme.example/jira)", c.BaseURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("delivery: refusing to send the Jira API token to %q over clear-text http — "+
			"the credential rides every request (set THEMIS_COMMUNICATION_JIRA_BASE_URL to https://…; "+
			"plain http is accepted only for a loopback host)", u.Host)
	default:
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_JIRA_BASE_URL scheme %q is not supported (use https)", u.Scheme)
	}
}

// String renders the Jira knobs for a log line: the token's PRESENCE, never the token. The auth mode
// and API version are included because they are the two knobs a wrong-flavour deployment turns on,
// and an operator reading one startup line should be able to tell Cloud from Data Center.
func (c JiraConfig) String() string {
	return fmt.Sprintf("enabled=%t base_url=%q project=%q auth=%s api_version=%d user=%q issue_type=%q api_token=%s timeout=%s",
		c.Enabled, c.BaseURL, c.ProjectKey, c.Auth, c.APIVersion, c.User, c.IssueType, secretState(c.APIToken), c.Timeout)
}

// RealJiraDeliverer creates or updates one Jira issue per Release.
type RealJiraDeliverer struct {
	cfg    JiraConfig
	http   *http.Client
	logger *observability.Logger
}

// NewRealJiraDeliverer builds the sender, refusing an incomplete or credential-exposing
// configuration AT CONFIGURE TIME: a sender that cannot possibly succeed must not be wired as one
// that can, and one that would succeed by putting a token on the wire in the clear must not be
// wired at all.
func NewRealJiraDeliverer(cfg JiraConfig, logger *observability.Logger) (*RealJiraDeliverer, error) {
	cfg = cfg.withDefaults()
	if err := cfg.checkFlavour(); err != nil {
		return nil, err
	}
	if missing := cfg.missing(); len(missing) > 0 {
		return nil, fmt.Errorf("delivery: jira configuration incomplete, unset: %s", strings.Join(missing, ", "))
	}
	if err := cfg.checkTransport(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = observability.Nop()
	}
	return &RealJiraDeliverer{
		cfg:    cfg,
		http:   &http.Client{Timeout: cfg.Timeout},
		logger: logger.Component("jira"),
	}, nil
}

// DeliverIntent sends the intent's materialized ticket: it finds the Release's existing issue and
// replaces its content, or creates it. The payload is never rendered here — an intent without one
// is refused (ErrNoPayload).
func (d *RealJiraDeliverer) DeliverIntent(ctx context.Context, in app.Intent) (Result, error) {
	summary, description := app.SplitPayload(in.PayloadBytes)
	if summary == "" || len(description) == 0 {
		return Result{Excerpt: "jira: no materialized payload"}, ErrNoPayload
	}
	if strings.TrimSpace(in.ReleaseID) == "" {
		return Result{Excerpt: "jira: intent names no release"}, app.ErrNoSubject
	}
	label := jiraLabelPrefix + in.ReleaseID

	fields := []observability.Field{
		observability.String("intent_id", in.ID),
		observability.String("release_id", in.ReleaseID),
		observability.String("project", d.cfg.ProjectKey),
	}

	key, found, err := d.search(ctx, label)
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}
	if found {
		if err := d.update(ctx, key, summary, description); err != nil {
			return Result{Excerpt: excerpt(err.Error())}, err
		}
		d.logger.Info("jira issue updated", append(fields, observability.String("jira_issue_key", key))...)
		return jiraResult(http.StatusNoContent, key, "updated"), nil
	}

	key, err = d.create(ctx, summary, description, label)
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}
	d.logger.Info("jira issue created", append(fields, observability.String("jira_issue_key", key))...)
	return jiraResult(http.StatusCreated, key, "created"), nil
}

// jiraResult is the outcome metadata recorded on the intent — the issue key, so "which ticket did
// this obligation land on" is answerable from Themis alone.
func jiraResult(status int, key, action string) Result {
	return Result{
		StatusCode: status,
		Excerpt:    "jira: issue " + action + " " + key,
		Metadata: map[string]string{
			"transport":      "jira",
			"jira_issue_key": key,
			"jira_action":    action,
		},
	}
}

// search looks for the Release's existing issue by exact label match. Nothing found is not an
// error — it is the create path.
func (d *RealJiraDeliverer) search(ctx context.Context, label string) (string, bool, error) {
	// The JQL is identical on both flavours: `labels = "…"` is an exact match in v2 and v3 alike,
	// which is what lets one-ticket-per-Release be one rule rather than one rule per flavour.
	jql := fmt.Sprintf("project = %q AND labels = %q ORDER BY created ASC", d.cfg.ProjectKey, label)
	endpoint := fmt.Sprintf("%s?maxResults=1&fields=key&jql=%s",
		d.endpoint("/search"), url.QueryEscape(jql))

	var out struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := d.call(ctx, http.MethodGet, endpoint, nil, &out); err != nil {
		return "", false, err
	}
	if len(out.Issues) == 0 || out.Issues[0].Key == "" {
		return "", false, nil
	}
	return out.Issues[0].Key, true, nil
}

// create opens the Release's ticket, labelled so the next cycle finds it.
func (d *RealJiraDeliverer) create(ctx context.Context, summary string, description []byte, label string) (string, error) {
	body := map[string]any{"fields": map[string]any{
		"project":     map[string]string{"key": d.cfg.ProjectKey},
		"issuetype":   map[string]string{"name": d.cfg.IssueType},
		"summary":     summary,
		"labels":      []string{jiraLabel, label},
		"description": d.description(description),
	}}
	var out struct {
		Key string `json:"key"`
	}
	if err := d.call(ctx, http.MethodPost, d.endpoint("/issue"), body, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", fmt.Errorf("jira: issue created but the response carried no key")
	}
	return out.Key, nil
}

// update replaces the issue's summary and description with the snapshot — a full replace, so the
// operation is idempotent however many times a retry repeats it.
func (d *RealJiraDeliverer) update(ctx context.Context, key, summary string, description []byte) error {
	body := map[string]any{"fields": map[string]any{
		"summary":     summary,
		"description": d.description(description),
	}}
	return d.call(ctx, http.MethodPut, d.endpoint("/issue/"+url.PathEscape(key)), body, nil)
}

// endpoint builds one REST URL: whatever path the base URL already carries, then the version prefix,
// then the resource. Appending rather than rebuilding is what makes a path-mounted Data Center
// instance (`https://jira.acme.example/jira`) work without a second code path.
func (d *RealJiraDeliverer) endpoint(resource string) string {
	return d.cfg.BaseURL + d.cfg.apiBase() + resource
}

// description encodes the ticket body for the configured API version: an Atlassian Document Format
// object on v3 (Cloud), a plain string on v2 (Data Center). The two are not interchangeable — each
// instance 400s on the other's shape — which is why one knob chooses both the prefix and this.
func (d *RealJiraDeliverer) description(text []byte) any {
	plain := strings.TrimRight(string(text), "\n")
	if d.cfg.APIVersion == 2 {
		return plain
	}
	return adfFromText(plain)
}

// call performs one Jira request. The Authorization header is set here and nowhere else, and the
// error it returns carries the status and a bounded excerpt of Jira's own body — never the
// request's headers, because an error path is the easiest place for a credential to escape.
func (d *RealJiraDeliverer) call(ctx context.Context, method, endpoint string, body, into any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	d.authorize(req)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("jira: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, excerptLimit))
		return fmt.Errorf("jira: %s %s: status %d: %s", method, pathOf(endpoint), resp.StatusCode, excerpt(string(detail)))
	}
	if into == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("jira: %s %s: decode: %w", method, pathOf(endpoint), err)
	}
	return nil
}

// authorize presents the credential the configured flavour expects, and is the ONLY place in this
// file that touches the Authorization header — so "where could the token escape" has one answer.
//
// Bearer is Data Center's Personal Access Token, which identifies its own owner: there is no user to
// send, and sending one as Basic beside it would be a second, failing credential.
func (d *RealJiraDeliverer) authorize(req *http.Request) {
	if d.cfg.Auth == JiraAuthBearer {
		req.Header.Set("Authorization", "Bearer "+d.cfg.APIToken)
		return
	}
	req.SetBasicAuth(d.cfg.User, d.cfg.APIToken)
}

// adfDoc is the Atlassian Document Format wrapper REST v3 requires for a rich-text field. The
// ticket body is plain text, so the document is one paragraph per line — the minimal faithful
// encoding, and the one that survives a round trip through Jira's editor.
type adfDoc struct {
	Type    string     `json:"type"`
	Version int        `json:"version"`
	Content []adfBlock `json:"content"`
}

type adfBlock struct {
	Type    string    `json:"type"`
	Content []adfText `json:"content,omitempty"`
}

type adfText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func adfFromText(text string) adfDoc {
	doc := adfDoc{Type: "doc", Version: 1}
	for _, line := range strings.Split(text, "\n") {
		block := adfBlock{Type: "paragraph"}
		if line != "" {
			block.Content = []adfText{{Type: "text", Text: line}}
		}
		doc.Content = append(doc.Content, block)
	}
	return doc
}

// pathOf reduces a URL to its path for an error message: the query string of a JQL search is
// noise in a ledger row, and a base URL may itself be estate detail.
func pathOf(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		return u.Path
	}
	return endpoint
}

// excerpt bounds a recorded response/error string: the attempt ledger wants a clue, not a page.
func excerpt(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= excerptLimit {
		return s
	}
	return s[:excerptLimit] + "…"
}

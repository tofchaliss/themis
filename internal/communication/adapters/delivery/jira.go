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
	"sort"
	"strconv"
	"strings"
	"sync"
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
	// IssueType is the issue type NAME to create (default "Task"). Ignored when IssueTypeID is set.
	IssueType string
	// IssueTypeID is the issue type ID to create, e.g. "10501". When set it is sent INSTEAD of the
	// name: a project whose issue types are renamed, localized or ambiguous ("Task" exists twice
	// under different schemes) can only be addressed by id, and an id is what a Jira admin reads off
	// the screen that worked manually.
	IssueTypeID string
	// ExtraFieldsJSON is a JSON OBJECT merged into every create's `fields` — the project-specific
	// required fields (a priority custom field, a version, a category) that a Jira screen demands and
	// Themis has no opinion about. It is carried as raw text and parsed when the sender is built, so
	// invalid JSON refuses the sender at startup instead of failing every create at run time.
	ExtraFieldsJSON string
	// Timeout bounds one HTTP call (default 15s).
	Timeout time.Duration
}

func jiraFromEnv() JiraConfig {
	return JiraConfig{
		Enabled:    envBool("THEMIS_COMMUNICATION_JIRA_ENABLED", false),
		BaseURL:    strings.TrimRight(getenv("THEMIS_COMMUNICATION_JIRA_BASE_URL"), "/"),
		ProjectKey: getenv("THEMIS_COMMUNICATION_JIRA_PROJECT_KEY"),
		// Auth, APIVersion and IssueType are resolved to their EFFECTIVE values here rather than left
		// blank for withDefaults, because this is what the startup log line prints: an operator
		// debugging a wrong-flavour deployment must be able to read what the node actually chose.
		//
		// IssueType was the one left out, and the cost was a real estate visit: the node logged
		// `issue_type=""` while the sender had defaulted it to "Task" internally, so the startup line
		// disagreed with the request and sent an operator looking for a configuration gap that was not
		// there. A default that only one half of the node knows about is a default that lies.
		Auth:            jiraAuthFromEnv(),
		APIVersion:      envInt("THEMIS_COMMUNICATION_JIRA_API_VERSION", defaultJiraAPIVersion),
		User:            getenv("THEMIS_COMMUNICATION_JIRA_USER"),
		APIToken:        getenv("THEMIS_COMMUNICATION_JIRA_API_TOKEN"),
		IssueType:       envDefaulted("THEMIS_COMMUNICATION_JIRA_ISSUE_TYPE", defaultJiraIssueType),
		IssueTypeID:     getenv("THEMIS_COMMUNICATION_JIRA_ISSUE_TYPE_ID"),
		ExtraFieldsJSON: getenv("THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS"),
		Timeout:         envDuration("THEMIS_COMMUNICATION_JIRA_TIMEOUT", defaultJiraTimeout),
	}
}

// envDefaulted reads a knob, falling back to its documented default.
func envDefaulted(key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
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

// issueTypeRef is the `issuetype` value a create carries: an ID when one is configured, else the
// name. By ID is how a Jira admin reads it off the screen that worked manually, and it is the only
// way to address a project whose type names are renamed, localized or duplicated across schemes.
func (c JiraConfig) issueTypeRef() map[string]string {
	if id := strings.TrimSpace(c.IssueTypeID); id != "" {
		return map[string]string{"id": id}
	}
	return map[string]string{"name": c.IssueType}
}

// reservedJiraFields are the create fields THEMIS owns. Extra fields may add to a create; they may
// never take one of these over, because each is either the ticket's identity (project, issuetype) or
// its snapshotted content (summary, description, labels) — and a configuration file silently
// replacing the body of a security ticket is the one thing this seam must not permit.
var reservedJiraFields = []string{"project", "issuetype", "summary", "description", "labels"}

// parseExtraFields decodes the configured extra fields and strips any reserved key.
//
// Invalid JSON is an ERROR, not an empty map: these fields exist because a Jira screen REQUIRES them,
// so ignoring a typo would turn one startup refusal into a create that fails for every Release
// forever. A reserved key is DROPPED with its name reported, so an operator who tried to set the
// summary from configuration is told rather than left wondering why it had no effect.
func parseExtraFields(raw string) (map[string]any, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil, nil
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, nil, fmt.Errorf("delivery: THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS is not a JSON object: %w", err)
	}
	var dropped []string
	for _, reserved := range reservedJiraFields {
		if _, taken := fields[reserved]; taken {
			delete(fields, reserved)
			dropped = append(dropped, reserved)
		}
	}
	if len(fields) == 0 {
		fields = nil
	}
	return fields, dropped, nil
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
	issueType := fmt.Sprintf("issue_type=%q", c.IssueType)
	if id := strings.TrimSpace(c.IssueTypeID); id != "" {
		issueType = fmt.Sprintf("issue_type_id=%q", id) // the name is not sent when an id is
	}
	return fmt.Sprintf("enabled=%t base_url=%q project=%q auth=%s api_version=%d user=%q %s extra_fields=%d api_token=%s timeout=%s",
		c.Enabled, c.BaseURL, c.ProjectKey, c.Auth, c.APIVersion, c.User, issueType,
		len(c.extraFieldNames()), secretState(c.APIToken), c.Timeout)
}

// extraFieldNames lists the configured extra field names for the startup line — the NAMES only. A
// project's field VALUES can carry estate detail (a version number, a customer category), and a
// startup line is read in a terminal somebody else may be looking at.
func (c JiraConfig) extraFieldNames() []string {
	fields, _, err := parseExtraFields(c.ExtraFieldsJSON)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ReleaseTicketIndex answers "which Jira issue did Themis already record for this Release?" from
// Themis's OWN store — the `jira_issue_key` on an earlier delivered intent for the same Release.
//
// It is declared here, at the consumer, and the delivery-intent store implements it. It is the FIRST
// place the one-ticket rule looks, ahead of asking Jira: Themis's own record of what it did is more
// trustworthy than a search whose index may lag, whose permissions may differ, and whose label may
// never have been applied at all (which is exactly the ME project's case — see labels below).
type ReleaseTicketIndex interface {
	JiraIssueKeyForRelease(ctx context.Context, releaseID string) (string, bool, error)
}

// RealJiraDeliverer creates or updates one Jira issue per Release.
type RealJiraDeliverer struct {
	cfg         JiraConfig
	extraFields map[string]any
	tickets     ReleaseTicketIndex
	http        *http.Client
	logger      *observability.Logger

	// locks serializes everything per Release, so two intents for one Release — which the
	// finding_opened proxy produces by the dozen — cannot both look, both miss, and both create.
	// The lock is held across lookup AND create: checking first and creating later with no lock in
	// between is the race, not a fix for it.
	locks sync.Map // releaseID -> *sync.Mutex
	// known is this process's memo of the issue key per Release. It exists because the durable
	// record arrives too late to help: the key reaches the store when the WORKER marks the intent
	// delivered, which is after DeliverIntent has returned — so the second intent of the same batch
	// would find nothing durable and open a second ticket. It is a cache, never the truth.
	known sync.Map // releaseID -> issue key
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
	extraFields, dropped, err := parseExtraFields(cfg.ExtraFieldsJSON)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = observability.Nop()
	}
	logger = logger.Component("jira")
	if len(dropped) > 0 {
		logger.Warn("THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS tried to set fields Themis owns; they were IGNORED",
			observability.String("ignored_fields", strings.Join(dropped, ",")))
	}
	return &RealJiraDeliverer{
		cfg:         cfg,
		extraFields: extraFields,
		http:        &http.Client{Timeout: cfg.Timeout},
		logger:      logger,
	}, nil
}

// WithTicketIndex gives the sender Themis's own record of which issue a Release already has, which it
// consults AHEAD of asking Jira. Without it the sender falls back to the label search alone — which is
// all a project that permits labels on create ever needed.
func (d *RealJiraDeliverer) WithTicketIndex(tickets ReleaseTicketIndex) *RealJiraDeliverer {
	d.tickets = tickets
	return d
}

// DeliverIntent sends the intent's materialized ticket: it finds the Release's existing issue and
// replaces its content, or creates it. The payload is never rendered here — an intent without one
// is refused (ErrNoPayload).
//
// The whole sequence runs under a per-Release lock. The ME project made the reason concrete: with
// labels unavailable on create, the only index a freshly created ticket has is Themis's own record,
// and that record is written after this function returns — so two intents racing for one Release
// must be serialized, not merely deduplicated afterwards.
func (d *RealJiraDeliverer) DeliverIntent(ctx context.Context, in app.Intent) (Result, error) {
	summary, description := app.SplitPayload(in.PayloadBytes)
	if summary == "" || len(description) == 0 {
		return Result{Excerpt: "jira: no materialized payload"}, ErrNoPayload
	}
	if strings.TrimSpace(in.ReleaseID) == "" {
		return Result{Excerpt: "jira: intent names no release"}, app.ErrNoSubject
	}
	unlock := d.lockRelease(in.ReleaseID)
	defer unlock()

	fields := []observability.Field{
		observability.String("intent_id", in.ID),
		observability.String("release_id", in.ReleaseID),
		observability.String("project", d.cfg.ProjectKey),
	}

	key, source, err := d.find(ctx, in.ReleaseID)
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}
	if key != "" {
		if err := d.update(ctx, key, summary, description); err != nil {
			return Result{Excerpt: excerpt(err.Error())}, err
		}
		d.remember(in.ReleaseID, key)
		// The label edit is retried on EVERY update, which is how a create whose label edit failed
		// heals: adding a label that is already there is a no-op, and the next cycle tries again.
		labels := d.ensureLabels(ctx, key, in.ReleaseID, fields)
		d.logger.Info("jira issue updated", append(fields,
			observability.String("jira_issue_key", key), observability.String("found_by", source))...)
		return jiraResult(http.StatusNoContent, key, "updated", source, labels), nil
	}

	key, err = d.create(ctx, summary, description)
	if err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}
	// Remembered BEFORE the label edit: from here on, a second intent for this Release must find
	// this ticket whatever the label edit does. Losing the key to a failed follow-up call is how a
	// Release ends up with two tickets.
	d.remember(in.ReleaseID, key)
	labels := d.ensureLabels(ctx, key, in.ReleaseID, fields)
	d.logger.Info("jira issue created", append(fields,
		observability.String("jira_issue_key", key), observability.String("labels", labels))...)
	return jiraResult(http.StatusCreated, key, "created", "created", labels), nil
}

// find locates the Release's ticket, in order of how much the answer can be trusted:
//
//  1. this process's memo — the ticket it created or found moments ago, before the store could know;
//  2. THEMIS'S OWN RECORD — the `jira_issue_key` on an earlier delivered intent for this Release;
//  3. Jira's label search — the FALLBACK, for a Release whose ticket Themis has no record of.
//
// The order is the point. A search depends on the index having caught up, on the credential being
// allowed to browse, and on the label having been applied — and on the ME project the label CANNOT be
// applied at create time, so a brand-new ticket is unfindable by search for as long as the follow-up
// edit keeps failing. Themis's own record depends on none of that.
//
// A failing record lookup is NOT fatal: it falls through to the search, because an unreachable index
// must not stop a ticket being updated.
func (d *RealJiraDeliverer) find(ctx context.Context, releaseID string) (string, string, error) {
	if memo, ok := d.known.Load(releaseID); ok {
		if key, _ := memo.(string); key != "" {
			return key, "memo", nil
		}
	}
	if d.tickets != nil {
		key, found, err := d.tickets.JiraIssueKeyForRelease(ctx, releaseID)
		switch {
		case err != nil:
			d.logger.Warn("could not read Themis's own ticket record; falling back to the label search",
				observability.String("release_id", releaseID), observability.Err(err))
		case found && key != "":
			return key, "themis_record", nil
		}
	}
	key, found, err := d.search(ctx, jiraLabelPrefix+releaseID)
	if err != nil {
		return "", "", err
	}
	if !found {
		return "", "", nil
	}
	return key, "label_search", nil
}

// lockRelease serializes work on one Release and returns its unlock.
//
// Entries are never evicted: one mutex per Release is bounded by the estate's Releases and costs a
// few dozen bytes each, which is cheaper than the bookkeeping that eviction would need to stay
// correct under the very concurrency this exists to control.
func (d *RealJiraDeliverer) lockRelease(releaseID string) func() {
	value, _ := d.locks.LoadOrStore(releaseID, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (d *RealJiraDeliverer) remember(releaseID, key string) {
	if key != "" {
		d.known.Store(releaseID, key)
	}
}

// jiraResult is the outcome metadata recorded on the intent — the issue key, so "which ticket did
// this obligation land on" is answerable from Themis alone, and HOW it was found, so an operator can
// see whether the record, the memo or the search is carrying the one-ticket rule.
func jiraResult(status int, key, action, foundBy, labels string) Result {
	return Result{
		StatusCode: status,
		Excerpt:    "jira: issue " + action + " " + key,
		Metadata: map[string]string{
			"transport":      "jira",
			"jira_issue_key": key,
			"jira_action":    action,
			"jira_found_by":  foundBy,
			"jira_labels":    labels,
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

// create opens the Release's ticket. It carries NO labels.
//
// Labels are a separate edit because a project can forbid them on create: the ME project's create
// screen has no labels field, and Jira answers "Field 'labels' cannot be set" — it refuses the whole
// create, so a ticket that could not be labelled was a ticket that did not exist. Themis's own record
// is the index now (see find), and the labels are a convenience for a human searching Jira, so they
// are added afterwards and their failure costs nothing.
func (d *RealJiraDeliverer) create(ctx context.Context, summary string, description []byte) (string, error) {
	fields := map[string]any{
		"project":     map[string]string{"key": d.cfg.ProjectKey},
		"issuetype":   d.cfg.issueTypeRef(),
		"summary":     summary,
		"description": d.description(description),
	}
	// The project-specific required fields, merged UNDER Themis's own: reserved keys were dropped when
	// the configuration was parsed, so this cannot overwrite the identity or the snapshot.
	for name, value := range d.extraFields {
		fields[name] = value
	}

	var out struct {
		Key string `json:"key"`
	}
	if err := d.call(ctx, http.MethodPost, d.endpoint("/issue"), map[string]any{"fields": fields}, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", fmt.Errorf("jira: issue created but the response carried no key")
	}
	return out.Key, nil
}

// ensureLabels adds Themis's labels to an issue with an `update`-style edit, and reports what
// happened ("added" or "pending") for the delivery result.
//
// It is BEST EFFORT by design. A failure here is logged and recorded, never returned: the ticket and
// its content have landed, and failing the delivery would retry the whole thing — including the
// create, on an intent whose key the store has not yet recorded. That is the path that opens a second
// ticket, which is the one outcome worth more than a label.
//
// `add` is idempotent (Jira holds labels as a set), so every later update retries this for free.
func (d *RealJiraDeliverer) ensureLabels(ctx context.Context, key, releaseID string, fields []observability.Field) string {
	body := map[string]any{"update": map[string]any{
		"labels": []map[string]string{
			{"add": jiraLabel},
			{"add": jiraLabelPrefix + releaseID},
		},
	}}
	if err := d.call(ctx, http.MethodPut, d.endpoint("/issue/"+url.PathEscape(key)), body, nil); err != nil {
		d.logger.Warn("jira refused the label edit; the ticket stands and the labels will be retried on the next update "+
			"(Themis's own record, not the label, is what keeps one ticket per Release)",
			append(fields, observability.String("jira_issue_key", key), observability.Err(err))...)
		return "pending"
	}
	return "added"
}

// update replaces the issue's summary and description with the snapshot — a full replace, so the
// operation is idempotent however many times a retry repeats it.
//
// The extra fields are NOT re-sent here. They are a project's create-screen requirements, not Themis's
// content: re-asserting a priority or a version on every cycle would overwrite whatever a human
// changed on the ticket, which is the opposite of what a projection should do.
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

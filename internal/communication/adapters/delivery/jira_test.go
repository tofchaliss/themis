package delivery_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// --- N-M1b: the real Jira sender ------------------------------------------------------------

const (
	jiraUser  = "themis-bot@acme.example"
	jiraToken = "JIRA-TOKEN-MUST-NEVER-APPEAR"
)

// jiraStub is a Jira REST v3 double. It records every call so the tests can assert the SHAPE of
// what Themis sends — which is the half a fake provider can never check.
type jiraStub struct {
	mu sync.Mutex

	// existingKey, when set, is what the JQL search finds (the update path).
	existingKey string
	// searchStatus / createStatus override the success status for the refusal paths.
	searchStatus, createStatus, updateStatus int
	// malformedSearch answers the search with unparseable JSON.
	malformedSearch bool
	// keylessCreate answers a create with no issue key.
	keylessCreate bool

	searches, creates, updates int
	jql                        string
	authorization              string
	created, updated           map[string]any
	updatedPath                string
}

func (s *jiraStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.authorization = r.Header.Get("Authorization")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/search":
			s.searches++
			s.jql = r.URL.Query().Get("jql")
			if s.searchStatus != 0 {
				w.WriteHeader(s.searchStatus)
				_, _ = w.Write([]byte(`{"errorMessages":["jql refused"]}`))
				return
			}
			if s.malformedSearch {
				_, _ = w.Write([]byte(`{"issues":[`))
				return
			}
			if s.existingKey == "" {
				_, _ = w.Write([]byte(`{"issues":[],"total":0}`))
				return
			}
			_, _ = w.Write([]byte(`{"issues":[{"key":"` + s.existingKey + `"}],"total":1}`))

		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			s.creates++
			s.created = decodeBody(r)
			if s.createStatus != 0 {
				w.WriteHeader(s.createStatus)
				_, _ = w.Write([]byte(`{"errors":{"issuetype":"not valid"}}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			if s.keylessCreate {
				_, _ = w.Write([]byte(`{"id":"10001"}`))
				return
			}
			_, _ = w.Write([]byte(`{"id":"10001","key":"SEC-7"}`))

		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/rest/api/3/issue/"):
			s.updates++
			s.updatedPath, s.updated = r.URL.Path, decodeBody(r)
			if s.updateStatus != 0 {
				w.WriteHeader(s.updateStatus)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func decodeBody(r *http.Request) map[string]any {
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return out
}

func (s *jiraStub) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.searches, s.creates, s.updates
}

// jiraConfig is a complete Jira configuration against the stub.
func jiraConfig(baseURL string) delivery.JiraConfig {
	return delivery.JiraConfig{
		Enabled: true, BaseURL: baseURL, ProjectKey: "SEC",
		User: jiraUser, APIToken: jiraToken, Timeout: 5 * time.Second,
	}
}

// ticketPayload is a materialized ticket payload shaped like the serializer's: one Subject line,
// then the body with the severity counts and the Critical/High ids.
func ticketPayload() []byte {
	return app.BuildPayload("Themis remediation - Release rel-1", []byte(
		"Release:  rel-1\nFindings: 4\n\nSeverity counts\n"+
			"  Critical: 1\n  High:     1\n  Medium:   1\n  Low:      1\n\n"+
			"Critical (1)\n  CVE-2026-0100\n\nHigh (1)\n  CVE-2026-0200\n"))
}

// fieldsOf reads the `fields` object out of a recorded Jira request body.
func fieldsOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	fields, ok := body["fields"].(map[string]any)
	if !ok {
		t.Fatalf("request carried no fields object: %v", body)
	}
	return fields
}

// adfText flattens an ADF description back to plain text so the content rule can be asserted on
// what Jira will actually show.
func adfText(t *testing.T, description any) string {
	t.Helper()
	doc, ok := description.(map[string]any)
	if !ok {
		t.Fatalf("description is not an ADF document: %v", description)
	}
	if doc["type"] != "doc" || doc["version"] != float64(1) {
		t.Errorf("ADF envelope = %v/%v, want doc/1", doc["type"], doc["version"])
	}
	var lines []string
	blocks, _ := doc["content"].([]any)
	for _, block := range blocks {
		b, _ := block.(map[string]any)
		if b["type"] != "paragraph" {
			t.Errorf("ADF block type = %v, want paragraph", b["type"])
		}
		text := ""
		for _, span := range toSlice(b["content"]) {
			s, _ := span.(map[string]any)
			text += asString(s["text"])
		}
		lines = append(lines, text)
	}
	return strings.Join(lines, "\n")
}

func toSlice(v any) []any {
	out, _ := v.([]any)
	return out
}

func asString(v any) string {
	out, _ := v.(string)
	return out
}

// The create path, end to end through the worker: one search, one POST, the intent delivered, and
// the issue key recorded on the result so the ticket this obligation landed on stays answerable.
func TestRealJiraDelivererCreatesTheReleaseTicket(t *testing.T) {
	stub := &jiraStub{}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	h := newHarness(t, testConfig())
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})
	id := h.seedIntent(t, h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload()))

	if n := h.runOnce(t); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	if searches, creates, updates := stub.counts(); searches != 1 || creates != 1 || updates != 0 {
		t.Errorf("calls = search %d / create %d / update %d, want 1/1/0", searches, creates, updates)
	}

	in := h.intents.get(t, id)
	if in.State != app.IntentDelivered {
		t.Fatalf("state = %s, want delivered", in.State)
	}
	if in.Result["jira_issue_key"] != "SEC-7" || in.Result["jira_action"] != "created" {
		t.Errorf("result = %v, want the issue key", in.Result)
	}

	// The search is by LABEL, exactly — not a summary text match whose near-miss opens a second
	// ticket for a Release that already had one.
	stub.mu.Lock()
	jql, auth, created := stub.jql, stub.authorization, stub.created
	stub.mu.Unlock()
	for _, want := range []string{`project = "SEC"`, `labels = "themis-release-rel-1"`} {
		if !strings.Contains(jql, want) {
			t.Errorf("jql = %q, missing %q", jql, want)
		}
	}

	fields := fieldsOf(t, created)
	if fields["summary"] != "Themis remediation - Release rel-1" {
		t.Errorf("summary = %v", fields["summary"])
	}
	if project, _ := fields["project"].(map[string]any); project["key"] != "SEC" {
		t.Errorf("project = %v", fields["project"])
	}
	if issuetype, _ := fields["issuetype"].(map[string]any); issuetype["name"] != "Task" {
		t.Errorf("issuetype = %v, want the default Task", fields["issuetype"])
	}
	labels := toSlice(fields["labels"])
	if len(labels) != 2 || labels[0] != "themis" || labels[1] != "themis-release-rel-1" {
		t.Errorf("labels = %v", labels)
	}

	// The content rule reaches Jira: counts for all four severities, ids for Critical and High.
	body := adfText(t, fields["description"])
	for _, want := range []string{"Critical: 1", "High:     1", "Medium:   1", "Low:      1", "CVE-2026-0100", "CVE-2026-0200"} {
		if !strings.Contains(body, want) {
			t.Errorf("description is missing %q:\n%s", want, body)
		}
	}

	// The credential travelled as HTTP Basic — and never into a log line.
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte(jiraUser+":"+jiraToken)); auth != want {
		t.Errorf("authorization = %q", auth)
	}
	h.assertNoSecretsInLogs(t, jiraToken)
}

// releaseSeverity is a stub of Governance's posture read, for the end-to-end path below.
type releaseSeverity struct{ rows []app.ReleaseSeverityRow }

func (s releaseSeverity) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	return s.rows, nil
}

// The WHOLE outward path in one test: the intent service materializes the ticket through the real
// outward serializer, the worker claims it, and the real sender puts it in Jira.
//
// This is the test that matters most in this step, for the reason `make e2e-llm` exists: the
// renderer and the sender are an interface with no compiler between them, and a stub payload in a
// sender test asserts only what the test author already believed. Here the bytes Jira receives were
// produced by the serializer from a posture, so "the counts and the Critical/High ids reach the
// ticket" is checked end to end rather than at each end.
func TestOutwardPathFromPostureToJira(t *testing.T) {
	stub := &jiraStub{}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	h := newHarness(t, testConfig())
	svc := app.NewDeliveryIntentService(h.intents, &seqIDs{}, fixedClock{}, app.DeliveryIntentConfig{}).
		WithPayloadRenderer(serializer.NewOutwardRenderer(releaseSeverity{rows: []app.ReleaseSeverityRow{
			{CVE: "CVE-2026-0100", BaseScore: 95}, // Critical
			{CVE: "CVE-2026-0200", BaseScore: 72}, // High
			{CVE: "CVE-2026-0300", BaseScore: 41}, // Medium — counted, never listed
			{CVE: "CVE-2026-0400", BaseScore: 5},  // Low — counted, never listed
		}}))
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})

	in, err := svc.EnqueueJiraForRelease(context.Background(),
		app.IntentLineage{SourceContext: "governance", EventType: "governance.finding_opened", EventID: "env-1"},
		"env-1", "rel-1", "prod-1", "proj-1", map[string]string{"finding_id": "fnd-1"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.PayloadSHA256 == "" {
		t.Fatal("the intent was recorded without a materialized payload")
	}

	if n := h.runOnce(t); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	stored := h.intents.get(t, in.ID)
	if stored.State != app.IntentDelivered || stored.Result["jira_issue_key"] != "SEC-7" {
		t.Fatalf("intent = %+v", stored)
	}
	if searches, creates, updates := stub.counts(); searches != 1 || creates != 1 || updates != 0 {
		t.Errorf("calls = %d/%d/%d, want one search and one create", searches, creates, updates)
	}

	stub.mu.Lock()
	created := stub.created
	stub.mu.Unlock()
	fields := fieldsOf(t, created)
	if fields["summary"] != "Themis remediation - Release rel-1" {
		t.Errorf("summary = %v", fields["summary"])
	}
	body := adfText(t, fields["description"])
	for _, want := range []string{
		"Release:  rel-1", "Project:  proj-1", "Product:  prod-1", "Findings: 4",
		"Critical: 1", "High:     1", "Medium:   1", "Low:      1",
		"CVE-2026-0100", "CVE-2026-0200",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the ticket is missing %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{"CVE-2026-0300", "CVE-2026-0400"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the ticket lists %s, which is below High:\n%s", unwanted, body)
		}
	}
	// The bytes Jira received ARE the snapshot: the digest still addresses them.
	if app.PayloadDigest(stored.PayloadBytes) != stored.PayloadSHA256 {
		t.Error("the stored payload and its digest disagree")
	}
	h.assertNoSecretsInLogs(t, jiraToken)
}

// The update path: the Release already has a ticket, so the content is REPLACED in place and no
// second issue is created. One ticket per Release.
func TestRealJiraDelivererUpdatesTheExistingTicket(t *testing.T) {
	stub := &jiraStub{existingKey: "SEC-3"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	h := newHarness(t, testConfig())
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})
	id := h.seedIntent(t, h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload()))

	h.runOnce(t)

	if searches, creates, updates := stub.counts(); searches != 1 || creates != 0 || updates != 1 {
		t.Errorf("calls = search %d / create %d / update %d, want 1/0/1", searches, creates, updates)
	}
	in := h.intents.get(t, id)
	if in.State != app.IntentDelivered || in.Result["jira_issue_key"] != "SEC-3" || in.Result["jira_action"] != "updated" {
		t.Errorf("intent = %+v", in)
	}

	stub.mu.Lock()
	path, updated := stub.updatedPath, stub.updated
	stub.mu.Unlock()
	if path != "/rest/api/3/issue/SEC-3" {
		t.Errorf("update path = %q", path)
	}
	fields := fieldsOf(t, updated)
	if fields["summary"] != "Themis remediation - Release rel-1" {
		t.Errorf("update summary = %v", fields["summary"])
	}
	if !strings.Contains(adfText(t, fields["description"]), "CVE-2026-0100") {
		t.Error("the update must carry the snapshot description")
	}
}

// The update is a FULL REPLACE, so repeating it is a no-op by construction: two passes over one
// Release leave one ticket holding the same content.
func TestRealJiraDelivererUpdateIsIdempotent(t *testing.T) {
	stub := &jiraStub{existingKey: "SEC-3"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), nil) // nil logger must not panic
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	in := app.Intent{ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload()}

	first, err := jira.DeliverIntent(context.Background(), in)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	stub.mu.Lock()
	firstBody := fieldsOf(t, stub.updated)
	stub.mu.Unlock()

	second, err := jira.DeliverIntent(context.Background(), in)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Metadata["jira_issue_key"] != second.Metadata["jira_issue_key"] {
		t.Errorf("the retry landed on a different issue: %v vs %v", first.Metadata, second.Metadata)
	}
	stub.mu.Lock()
	secondBody := fieldsOf(t, stub.updated)
	stub.mu.Unlock()
	if !jsonEqual(t, firstBody, secondBody) {
		t.Error("the retry sent different content for the same snapshot")
	}
	if _, creates, updates := stub.counts(); creates != 0 || updates != 2 {
		t.Errorf("creates = %d, updates = %d — a retry must update, never create", creates, updates)
	}
}

func jsonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	left, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	right, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(left) == string(right)
}

// Jira's refusals are OUTCOMES: the attempt is recorded with a bounded excerpt, the intent is
// retried and eventually dead-lettered. None of them is a store error, and none carries the token.
func TestRealJiraDelivererRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		stub *jiraStub
		want string
	}{
		{"search refused", &jiraStub{searchStatus: http.StatusBadRequest}, "status 400"},
		{"search unparseable", &jiraStub{malformedSearch: true}, "decode"},
		{"create refused", &jiraStub{createStatus: http.StatusForbidden}, "status 403"},
		{"create returned no key", &jiraStub{keylessCreate: true}, "no key"},
		{"update refused", &jiraStub{existingKey: "SEC-3", updateStatus: http.StatusNotFound}, "status 404"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.stub.handler())
			defer srv.Close()

			cfg := testConfig()
			cfg.MaxAttempts = 1
			h := newHarness(t, cfg)
			jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), h.logger)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}
			h.withDeliverers(cfg, map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})
			id := h.seedIntent(t, h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload()))

			if _, err := h.worker.RunOnce(context.Background()); err != nil {
				t.Fatalf("a channel refusal is an outcome, not a pass failure: %v", err)
			}
			in := h.intents.get(t, id)
			if in.State != app.IntentDeadLetter {
				t.Errorf("state = %s, want dead_letter after the attempt budget", in.State)
			}
			if !strings.Contains(in.LastError, tc.want) {
				t.Errorf("last error = %q, want it to mention %q", in.LastError, tc.want)
			}
			if strings.Contains(in.LastError, jiraToken) {
				t.Error("the token reached the attempt ledger")
			}
			h.assertNoSecretsInLogs(t, jiraToken)
		})
	}
}

// An unreachable Jira is a retry, not a crash — and the error names the method, never the headers.
func TestRealJiraDelivererUnreachable(t *testing.T) {
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig("http://127.0.0.1:1"), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	_, err = jira.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload()})
	if err == nil {
		t.Fatal("want a transport error")
	}
	if strings.Contains(err.Error(), jiraToken) {
		t.Error("the token reached the error")
	}
}

// The two things a real sender refuses outright: an intent with no materialized payload (D-N-3 —
// it will not render one now) and an intent that names no Release.
func TestRealJiraDelivererRefusesAnUnrenderedIntent(t *testing.T) {
	stub := &jiraStub{}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		in   app.Intent
		want error
	}{
		{"no payload at all", app.Intent{ID: "int-1", ReleaseID: "rel-1"}, delivery.ErrNoPayload},
		{"an N-M1a body with no envelope", app.Intent{ID: "int-1", ReleaseID: "rel-1", PayloadBytes: []byte("legacy")}, delivery.ErrNoPayload},
		{"no release", app.Intent{ID: "int-1", PayloadBytes: ticketPayload()}, app.ErrNoSubject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jira.DeliverIntent(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if searches, creates, _ := stub.counts(); searches != 0 || creates != 0 {
		t.Errorf("a refused intent must make no call: search %d create %d", searches, creates)
	}
}

// Configuration is refused AT CONFIGURE TIME, naming the knobs that are missing and never their
// values — a sender that cannot possibly succeed must not be wired as one that can.
func TestJiraConfigRefusesIncompleteConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  delivery.JiraConfig
		want string
	}{
		{"nothing set", delivery.JiraConfig{Enabled: true}, "THEMIS_COMMUNICATION_JIRA_BASE_URL"},
		{"no project", delivery.JiraConfig{Enabled: true, BaseURL: "u", User: "a", APIToken: "t"}, "THEMIS_COMMUNICATION_JIRA_PROJECT_KEY"},
		{"no credential", delivery.JiraConfig{Enabled: true, BaseURL: "u", ProjectKey: "SEC"}, "THEMIS_COMMUNICATION_JIRA_API_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := delivery.NewRealJiraDeliverer(tc.cfg, nil)
			if err == nil {
				t.Fatal("an incomplete configuration must be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), "t") && strings.Contains(err.Error(), "token=") {
				t.Errorf("err = %v, must not quote values", err)
			}
		})
	}
}

// The token must not cross an unencrypted channel. Jira's credential is HTTP Basic — the token is
// in EVERY request — so a plain-http base URL is refused at configure time, exactly as an SMTP
// password without STARTTLS is. Loopback is the one exception, because those bytes never leave the
// machine (and it is where an httptest server lives).
func TestJiraConfigRefusesAClearTextBaseURL(t *testing.T) {
	complete := func(baseURL string) delivery.JiraConfig {
		return delivery.JiraConfig{Enabled: true, BaseURL: baseURL, ProjectKey: "SEC",
			User: jiraUser, APIToken: jiraToken}
	}
	for _, tc := range []struct {
		name    string
		baseURL string
		want    string
	}{
		{"plain http to a remote site", "http://jira.acme.example", "clear-text http"},
		{"plain http with a port", "http://10.0.0.5:8080", "clear-text http"},
		{"no scheme at all", "jira.acme.example", "not an absolute URL"},
		{"a scheme that is not http(s)", "ftp://jira.acme.example", "is not supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := delivery.NewRealJiraDeliverer(complete(tc.baseURL), nil)
			if err == nil {
				t.Fatalf("%q must be refused", tc.baseURL)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), jiraToken) {
				t.Errorf("err = %v leaked the token", err)
			}
		})
	}

	for _, allowed := range []string{
		"https://acme.atlassian.net",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		if _, err := delivery.NewRealJiraDeliverer(complete(allowed), nil); err != nil {
			t.Errorf("%q must be accepted: %v", allowed, err)
		}
	}
}

// And the refusal reaches the SELECTION: an operator who enabled Jira against a plain-http site
// keeps the fake sender and is told at ERROR — nothing is sent, and no token is put on the wire.
func TestNewDeliverersRefusesAClearTextJira(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := observability.New(zap.New(core))
	deliverers := delivery.NewDeliverers(delivery.Config{
		Enabled: true,
		Jira: delivery.JiraConfig{Enabled: true, BaseURL: "http://jira.acme.example",
			ProjectKey: "SEC", User: jiraUser, APIToken: jiraToken},
	}, logger)

	if _, fake := deliverers[app.IntentJiraIssue].(*delivery.FakeJiraDeliverer); !fake {
		t.Errorf("jira deliverer = %T, want the fake — the real one would leak the token", deliverers[app.IntentJiraIssue])
	}
	if !hasFieldValue(logs, "clear-text http") {
		t.Error("the refusal must be logged with its reason")
	}
	for _, e := range logs.All() {
		if strings.Contains(fmt.Sprint(e.ContextMap()), jiraToken) {
			t.Fatal("the token reached the logs")
		}
	}
}

// The config's String() is a startup log line: it reports that a credential is SET, never what it
// is. This is the one place an operator reads the whole outward configuration at a glance.
func TestJiraConfigStringHidesTheToken(t *testing.T) {
	got := jiraConfig("https://acme.atlassian.net").String()
	if strings.Contains(got, jiraToken) {
		t.Fatalf("String() leaked the token: %s", got)
	}
	for _, want := range []string{"api_token=set", `project="SEC"`, `base_url="https://acme.atlassian.net"`} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %s, missing %q", got, want)
		}
	}
	if unset := (delivery.JiraConfig{}).String(); !strings.Contains(unset, "api_token=unset") {
		t.Errorf("an unset token must read as unset: %s", unset)
	}
}

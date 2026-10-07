package delivery_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// jiraStub is a Jira REST double for EITHER flavour. It records every call so the tests can assert
// the SHAPE of what Themis sends — which is the half a fake provider can never check.
//
// It answers ONLY at `<basePath>/rest/api/<apiVersion>/…` and 404s anywhere else, deliberately: that
// is what makes "we called the right URL for this flavour, including the instance's own path mount"
// an assertion rather than an assumption. A Cloud stub is the zero value (no base path, v3).
type jiraStub struct {
	mu sync.Mutex

	// basePath is the path the instance is mounted under: "" for Cloud, "/jira" for the owner's
	// self-hosted Data Center at https://almsbx.radisys.com/jira.
	basePath string
	// apiVersion is the REST major version this instance serves; 0 means 3 (Cloud).
	apiVersion int

	// existingKey, when set, is what the JQL search finds (the update path).
	existingKey string
	// searchStatus / createStatus / updateStatus override the success status for the refusal paths.
	searchStatus, createStatus, updateStatus int
	// labelStatus refuses the LABEL edit only — the ME project's shape, where a create succeeds and
	// the follow-up label edit does not.
	labelStatus int
	// refuseLabelsOnCreate reproduces the ME project exactly: a create that carries `labels` is
	// refused with Jira's own message, so a sender that still sent them on create fails here.
	refuseLabelsOnCreate bool
	// malformedSearch answers the search with unparseable JSON.
	malformedSearch bool
	// keylessCreate answers a create with no issue key.
	keylessCreate bool

	// updates counts CONTENT edits (a `fields` PUT); labelEdits counts label edits (an `update` PUT).
	// They are counted apart because the whole change is that one create became a create plus a
	// separate, best-effort label edit.
	searches, creates, updates, labelEdits int
	jql                                    string
	authorization                          string
	created, updated, labelEdit            map[string]any
	updatedPath, labelPath                 string
}

// prefix is where this instance answers; anything outside it is a 404.
func (s *jiraStub) prefix() string {
	version := s.apiVersion
	if version == 0 {
		version = 3
	}
	return s.basePath + "/rest/api/" + strconv.Itoa(version)
}

func (s *jiraStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.authorization = r.Header.Get("Authorization")

		resource, under := strings.CutPrefix(r.URL.Path, s.prefix())
		if !under {
			// The wrong version prefix, or the base path dropped: the two ways a flavour can be
			// mis-addressed, and both must be visible as a failure rather than quietly tolerated.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorMessages":["no such endpoint"]}`))
			return
		}

		switch {
		case r.Method == http.MethodGet && resource == "/search":
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

		case r.Method == http.MethodPost && resource == "/issue":
			s.creates++
			s.created = decodeBody(r)
			if s.refuseLabelsOnCreate {
				if fields, ok := s.created["fields"].(map[string]any); ok {
					if _, sent := fields["labels"]; sent {
						// Jira's own wording, verbatim: the ME project's create screen has no labels
						// field, and this refuses the WHOLE create, not just the field.
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"errorMessages":[],"errors":{"labels":"Field 'labels' cannot be set. It is not on the appropriate screen, or unknown."}}`))
						return
					}
				}
			}
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

		case r.Method == http.MethodPut && strings.HasPrefix(resource, "/issue/"):
			body := decodeBody(r)
			if _, isLabelEdit := body["update"]; isLabelEdit {
				s.labelEdits++
				s.labelPath, s.labelEdit = r.URL.Path, body
				if s.labelStatus != 0 {
					w.WriteHeader(s.labelStatus)
					_, _ = w.Write([]byte(`{"errors":{"labels":"Field 'labels' cannot be set."}}`))
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			s.updates++
			s.updatedPath, s.updated = r.URL.Path, body
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

// labelCount is how many LABEL edits the stub saw — the follow-up that replaced labels-on-create.
func (s *jiraStub) labelCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.labelEdits
}

// labelAdds reads the label names an `update` edit asked Jira to add.
func labelAdds(t *testing.T, body map[string]any) []string {
	t.Helper()
	update, ok := body["update"].(map[string]any)
	if !ok {
		t.Fatalf("not a label edit: %v", body)
	}
	var out []string
	for _, op := range toSlice(update["labels"]) {
		entry, _ := op.(map[string]any)
		if add, ok := entry["add"]; ok {
			out = append(out, asString(add))
		} else {
			t.Errorf("label operation %v is not an `add` — Themis never removes a label it did not set", entry)
		}
	}
	return out
}

// jiraConfig is a complete Jira CLOUD configuration against the stub: Basic auth, REST v3, and both
// flavour knobs left unset so the defaults are what is exercised.
func jiraConfig(baseURL string) delivery.JiraConfig {
	return delivery.JiraConfig{
		Enabled: true, BaseURL: baseURL, ProjectKey: "SEC",
		User: jiraUser, APIToken: jiraToken, Timeout: 5 * time.Second,
	}
}

// jiraDataCenterConfig is the owner's self-hosted flavour: a Personal Access Token as Bearer, REST
// v2, NO user, and a base URL mounted under a path.
func jiraDataCenterConfig(baseURL string) delivery.JiraConfig {
	return delivery.JiraConfig{
		Enabled: true, BaseURL: baseURL + jiraDCPath, ProjectKey: "SEC",
		Auth: delivery.JiraAuthBearer, APIVersion: 2,
		APIToken: jiraToken, Timeout: 5 * time.Second,
	}
}

// jiraDCPath is the path a self-hosted instance is usually mounted under (the owner's is
// https://almsbx.radisys.com/jira).
const jiraDCPath = "/jira"

// jiraFlavour is one deployment shape: how the stub answers, how the sender is configured, and the
// two things that differ on the wire. Every behavioural Jira test runs over BOTH, because a flavour
// that is only tested one way is a flavour that works one way.
type jiraFlavour struct {
	name string
	// stub prepares the server side (base path + version it serves).
	stub func(*jiraStub)
	// config builds the matching sender configuration against the server URL.
	config func(baseURL string) delivery.JiraConfig
	// wantPrefix is the REST prefix every call must land on, base path included.
	wantPrefix string
	// wantAuth checks the Authorization header the flavour presents.
	wantAuth func(t *testing.T, header string)
	// description reads the description field back as plain text, whichever shape it arrived in.
	description func(t *testing.T, field any) string
}

func jiraFlavours() []jiraFlavour {
	return []jiraFlavour{
		{
			name:       "cloud (basic, v3, ADF)",
			stub:       func(*jiraStub) {},
			config:     jiraConfig,
			wantPrefix: "/rest/api/3",
			wantAuth: func(t *testing.T, header string) {
				t.Helper()
				want := "Basic " + base64.StdEncoding.EncodeToString([]byte(jiraUser+":"+jiraToken))
				if header != want {
					t.Errorf("authorization = %q, want HTTP Basic", header)
				}
			},
			description: adfText,
		},
		{
			name:       "data center (bearer PAT, v2, plain text, path mount)",
			stub:       func(s *jiraStub) { s.basePath, s.apiVersion = jiraDCPath, 2 },
			config:     jiraDataCenterConfig,
			wantPrefix: jiraDCPath + "/rest/api/2",
			wantAuth: func(t *testing.T, header string) {
				t.Helper()
				if header != "Bearer "+jiraToken {
					t.Errorf("authorization = %q, want a Bearer PAT", header)
				}
				if strings.HasPrefix(header, "Basic ") {
					t.Error("a Data Center PAT must not be sent as a Basic password — it authenticates as nobody")
				}
			},
			description: plainText,
		},
	}
}

// plainText reads a REST v2 description: a JSON string, not a document. Asserting the TYPE is the
// point — an ADF object here is the 400 the owner's instance would return.
func plainText(t *testing.T, field any) string {
	t.Helper()
	text, ok := field.(string)
	if !ok {
		t.Fatalf("v2 description must be a plain string, got %T (%v)", field, field)
	}
	return text
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

// The create path, end to end through the worker, on BOTH flavours: one search, one POST, the intent
// delivered, and the issue key recorded on the result so the ticket this obligation landed on stays
// answerable.
//
// Everything asserted outside the flavour's own three hooks is SHARED on purpose — the label search,
// the labels, the summary, the content rule. That is the claim worth making: Cloud and Data Center
// differ in the credential and the description encoding, and in nothing that decides which ticket a
// Release gets.
func TestRealJiraDelivererCreatesTheReleaseTicket(t *testing.T) {
	for _, flavour := range jiraFlavours() {
		t.Run(flavour.name, func(t *testing.T) {
			stub := &jiraStub{}
			flavour.stub(stub)
			srv := httptest.NewServer(stub.handler())
			defer srv.Close()

			h := newHarness(t, testConfig())
			jira, err := delivery.NewRealJiraDeliverer(flavour.config(srv.URL), h.logger)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}
			h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})
			id := h.seedIntent(t, h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload()))

			if n := h.runOnce(t); n != 1 {
				t.Fatalf("delivered %d, want 1", n)
			}
			if searches, creates, updates := stub.counts(); searches != 1 || creates != 1 || updates != 0 {
				t.Errorf("calls = search %d / create %d / content update %d, want 1/1/0", searches, creates, updates)
			}
			if got := stub.labelCount(); got != 1 {
				t.Errorf("label edits = %d, want 1 (labels are added AFTER the create)", got)
			}

			in := h.intents.get(t, id)
			if in.State != app.IntentDelivered {
				t.Fatalf("state = %s, want delivered", in.State)
			}
			if in.Result["jira_issue_key"] != "SEC-7" || in.Result["jira_action"] != "created" {
				t.Errorf("result = %v, want the issue key", in.Result)
			}
			if in.Result["jira_labels"] != "added" || in.Result["jira_found_by"] != "created" {
				t.Errorf("result = %v, want the label outcome and how the ticket was found", in.Result)
			}

			// The search is by LABEL, exactly — not a summary text match whose near-miss opens a
			// second ticket for a Release that already had one. Identical JQL on both flavours.
			stub.mu.Lock()
			jql, auth, created, labelEdit, labelPath := stub.jql, stub.authorization, stub.created, stub.labelEdit, stub.labelPath
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
			// The create carries NO labels: a project whose create screen has none refuses the whole
			// create over that one field.
			if _, sent := fields["labels"]; sent {
				t.Errorf("the create must not carry labels: %v", fields["labels"])
			}
			// They arrive by a follow-up edit on the SAME issue instead.
			if want := flavour.wantPrefix + "/issue/SEC-7"; labelPath != want {
				t.Errorf("label edit path = %q, want %q", labelPath, want)
			}
			if adds := labelAdds(t, labelEdit); len(adds) != 2 || adds[0] != "themis" || adds[1] != "themis-release-rel-1" {
				t.Errorf("label adds = %v", adds)
			}

			// The content rule reaches Jira in this flavour's own encoding: counts for all four
			// severities, ids for Critical and High.
			body := flavour.description(t, fields["description"])
			for _, want := range []string{"Critical: 1", "High:     1", "Medium:   1", "Low:      1", "CVE-2026-0100", "CVE-2026-0200"} {
				if !strings.Contains(body, want) {
					t.Errorf("description is missing %q:\n%s", want, body)
				}
			}

			// The credential travelled in this flavour's form — and never into a log line.
			flavour.wantAuth(t, auth)
			h.assertNoSecretsInLogs(t, jiraToken)
		})
	}
}

// Every call lands under the instance's OWN path, version prefix included. A Data Center instance is
// usually mounted on a path (the owner's is https://almsbx.radisys.com/jira), and a sender that
// rebuilt the URL instead of appending to it would 404 on every single call.
func TestRealJiraDelivererAddressesTheInstancesOwnPath(t *testing.T) {
	for _, flavour := range jiraFlavours() {
		t.Run(flavour.name, func(t *testing.T) {
			stub := &jiraStub{existingKey: "SEC-3"}
			flavour.stub(stub)
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				stub.handler().ServeHTTP(w, r)
			}))
			defer srv.Close()

			jira, err := delivery.NewRealJiraDeliverer(flavour.config(srv.URL), nil)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}
			if _, err := jira.DeliverIntent(context.Background(), app.Intent{
				ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload(),
			}); err != nil {
				t.Fatalf("deliver: %v", err)
			}

			// Search, then the content edit, then the label edit — all three under the instance's path.
			want := []string{
				flavour.wantPrefix + "/search",
				flavour.wantPrefix + "/issue/SEC-3",
				flavour.wantPrefix + "/issue/SEC-3",
			}
			if strings.Join(paths, " ") != strings.Join(want, " ") {
				t.Errorf("paths = %v, want %v", paths, want)
			}
		})
	}
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
	for _, flavour := range jiraFlavours() {
		t.Run(flavour.name, func(t *testing.T) {
			stub := &jiraStub{}
			flavour.stub(stub)
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
			jira, err := delivery.NewRealJiraDeliverer(flavour.config(srv.URL), h.logger)
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
			if got := stub.labelCount(); got != 1 {
				t.Errorf("label edits = %d, want 1", got)
			}

			stub.mu.Lock()
			created := stub.created
			stub.mu.Unlock()
			fields := fieldsOf(t, created)
			if fields["summary"] != "Themis remediation - Release rel-1" {
				t.Errorf("summary = %v", fields["summary"])
			}
			body := flavour.description(t, fields["description"])
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
		})
	}
}

// The update path on BOTH flavours: the Release already has a ticket, so the content is REPLACED in
// place and no second issue is created. One ticket per Release, whichever Jira this is.
func TestRealJiraDelivererUpdatesTheExistingTicket(t *testing.T) {
	for _, flavour := range jiraFlavours() {
		t.Run(flavour.name, func(t *testing.T) {
			stub := &jiraStub{existingKey: "SEC-3"}
			flavour.stub(stub)
			srv := httptest.NewServer(stub.handler())
			defer srv.Close()

			h := newHarness(t, testConfig())
			jira, err := delivery.NewRealJiraDeliverer(flavour.config(srv.URL), h.logger)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}
			h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})
			id := h.seedIntent(t, h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload()))

			h.runOnce(t)

			if searches, creates, updates := stub.counts(); searches != 1 || creates != 0 || updates != 1 {
				t.Errorf("calls = search %d / create %d / content update %d, want 1/0/1", searches, creates, updates)
			}
			// The labels are re-asserted on every update, which is how a create whose label edit
			// failed heals without anybody tracking that it did.
			if got := stub.labelCount(); got != 1 {
				t.Errorf("label edits = %d, want 1 (the update retries them)", got)
			}
			in := h.intents.get(t, id)
			if in.State != app.IntentDelivered || in.Result["jira_issue_key"] != "SEC-3" || in.Result["jira_action"] != "updated" {
				t.Errorf("intent = %+v", in)
			}
			if in.Result["jira_found_by"] != "label_search" {
				t.Errorf("found_by = %q, want the label search (no Themis record was wired)", in.Result["jira_found_by"])
			}

			stub.mu.Lock()
			path, updated, auth := stub.updatedPath, stub.updated, stub.authorization
			stub.mu.Unlock()
			if want := flavour.wantPrefix + "/issue/SEC-3"; path != want {
				t.Errorf("update path = %q, want %q", path, want)
			}
			flavour.wantAuth(t, auth)
			fields := fieldsOf(t, updated)
			if fields["summary"] != "Themis remediation - Release rel-1" {
				t.Errorf("update summary = %v", fields["summary"])
			}
			if !strings.Contains(flavour.description(t, fields["description"]), "CVE-2026-0100") {
				t.Error("the update must carry the snapshot description")
			}
		})
	}
}

// The update is a FULL REPLACE, so repeating it is a no-op by construction: two passes over one
// Release leave one ticket holding the same content.
// --- The ME project: labels are not on the create screen -------------------------------------

// recordedTickets is Themis's own ticket record: the `jira_issue_key` an earlier delivered intent
// carries for a Release. It can also fail, to prove the search still backs it up.
type recordedTickets struct {
	keys  map[string]string
	err   error
	calls int
}

func (r *recordedTickets) JiraIssueKeyForRelease(_ context.Context, releaseID string) (string, bool, error) {
	r.calls++
	if r.err != nil {
		return "", false, r.err
	}
	key, ok := r.keys[releaseID]
	return key, ok, nil
}

// The ME project refuses a create that carries labels — Jira's own "Field 'labels' cannot be set" —
// so the create must carry none and the labels must arrive by a follow-up edit. The stub FAILS the
// create if labels are sent, which is what makes this a regression test rather than a restatement.
func TestRealJiraDelivererCreatesWithoutLabelsThenAddsThem(t *testing.T) {
	stub := &jiraStub{refuseLabelsOnCreate: true}
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
		t.Fatalf("delivered %d, want 1 — a project without labels on its create screen must still get a ticket", n)
	}
	in := h.intents.get(t, id)
	if in.Result["jira_issue_key"] != "SEC-7" || in.Result["jira_labels"] != "added" {
		t.Errorf("result = %v", in.Result)
	}
	if got := stub.labelCount(); got != 1 {
		t.Errorf("label edits = %d, want 1", got)
	}
}

// A label edit that FAILS after a successful create must not lose the ticket: the key is recorded,
// the delivery succeeds, and the next cycle updates that ticket instead of opening a second one.
// This is the exact sequence the owner asked for, run twice.
func TestRealJiraDelivererRecordsTheKeyWhenTheLabelEditFails(t *testing.T) {
	stub := &jiraStub{refuseLabelsOnCreate: true, labelStatus: http.StatusBadRequest}
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
		t.Fatalf("delivered %d, want 1 — a refused label edit must not fail a delivery whose ticket landed", n)
	}
	in := h.intents.get(t, id)
	if in.Result["jira_issue_key"] != "SEC-7" {
		t.Fatalf("the key must be recorded even when the labels did not land: %v", in.Result)
	}
	if in.Result["jira_labels"] != "pending" {
		t.Errorf("jira_labels = %q, want pending so an operator can see it", in.Result["jira_labels"])
	}
	if !hasMessage(h.logs, "jira refused the label edit") {
		t.Error("a refused label edit must be logged")
	}

	// A SECOND intent for the same Release. The label never landed, so Jira's search cannot find the
	// ticket — only Themis's own answer can. No second create.
	stub.mu.Lock()
	stub.existingKey = "" // the search finds nothing, because the label is not there
	stub.mu.Unlock()
	second := h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload())
	second.ID, second.OriginEventID = "int-second", "env-2"
	h.seedIntent(t, second)

	if n := h.runOnce(t); n != 1 {
		t.Fatalf("second pass delivered %d, want 1", n)
	}
	if _, creates, updates := stub.counts(); creates != 1 || updates != 1 {
		t.Errorf("creates = %d, content updates = %d — the second intent must UPDATE the first ticket", creates, updates)
	}
	if got := h.intents.get(t, "int-second").Result["jira_found_by"]; got != "memo" {
		t.Errorf("found_by = %q, want this process's memo (the store has not been asked yet)", got)
	}
	if got := stub.labelCount(); got != 2 {
		t.Errorf("label edits = %d, want 2 — the update retries the labels that never landed", got)
	}
}

// Themis's OWN RECORD is consulted before Jira, and it is what carries the one-ticket rule across a
// restart: a new process has no memo, and a ticket whose label edit failed is invisible to the search.
func TestRealJiraDelivererPrefersThemisOwnRecordOverTheSearch(t *testing.T) {
	stub := &jiraStub{existingKey: "SEC-999"} // the search would answer, and must not be asked
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	tickets := &recordedTickets{keys: map[string]string{"rel-1": "SEC-42"}}
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	res, err := jira.WithTicketIndex(tickets).DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload(),
	})
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if res.Metadata["jira_issue_key"] != "SEC-42" || res.Metadata["jira_found_by"] != "themis_record" {
		t.Errorf("result = %v, want the recorded key", res.Metadata)
	}
	if tickets.calls != 1 {
		t.Errorf("record reads = %d, want 1", tickets.calls)
	}
	if searches, creates, updates := stub.counts(); searches != 0 || creates != 0 || updates != 1 {
		t.Errorf("calls = search %d / create %d / update %d — the search must not be needed", searches, creates, updates)
	}
}

// The search is the FALLBACK, in both the senses that matter: when Themis has no record for the
// Release, and when the record cannot be read at all. An unreachable index must not stop a ticket
// being updated — and must certainly not cause a second one.
func TestRealJiraDelivererFallsBackToTheLabelSearch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tickets *recordedTickets
	}{
		{"no record for this Release", &recordedTickets{keys: map[string]string{"rel-other": "SEC-1"}}},
		{"the record could not be read", &recordedTickets{err: errors.New("db down")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &jiraStub{existingKey: "SEC-3"}
			srv := httptest.NewServer(stub.handler())
			defer srv.Close()

			jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), nil)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}
			res, err := jira.WithTicketIndex(tc.tickets).DeliverIntent(context.Background(), app.Intent{
				ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload(),
			})
			if err != nil {
				t.Fatalf("deliver: %v", err)
			}
			if res.Metadata["jira_issue_key"] != "SEC-3" || res.Metadata["jira_found_by"] != "label_search" {
				t.Errorf("result = %v, want the searched key", res.Metadata)
			}
			if searches, creates, _ := stub.counts(); searches != 1 || creates != 0 {
				t.Errorf("searches = %d, creates = %d", searches, creates)
			}
		})
	}
}

// Two intents for ONE Release, delivered CONCURRENTLY by two worker goroutines — the shape the
// finding_opened proxy produces by the dozen. Exactly one create, because the create path is
// serialized per Release; without the lock both would search, both would miss, and both would open a
// ticket.
func TestRealJiraDelivererCreatesOnceForConcurrentIntentsOfOneRelease(t *testing.T) {
	stub := &jiraStub{refuseLabelsOnCreate: true}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	cfg := testConfig()
	cfg.Workers = 4
	h := newHarness(t, cfg)
	jira, err := delivery.NewRealJiraDeliverer(jiraConfig(srv.URL), h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(cfg, map[app.IntentType]delivery.IntentDeliverer{app.IntentJiraIssue: jira})

	// Eight intents, one Release — all due now, all in one batch.
	for i := 0; i < 8; i++ {
		in := h.pending(app.IntentJiraIssue, "themis-remediation", ticketPayload())
		in.ID = fmt.Sprintf("int-%d", i)
		in.OriginEventID = fmt.Sprintf("env-%d", i)
		h.seedIntent(t, in)
	}

	if n := h.runOnce(t); n != 8 {
		t.Fatalf("delivered %d, want 8", n)
	}
	_, creates, updates := stub.counts()
	if creates != 1 {
		t.Errorf("creates = %d, want exactly 1 — one Release, one ticket", creates)
	}
	if updates != 7 {
		t.Errorf("content updates = %d, want 7 (the other intents update the one ticket)", updates)
	}
	for i := 0; i < 8; i++ {
		if got := h.intents.get(t, fmt.Sprintf("int-%d", i)).Result["jira_issue_key"]; got != "SEC-7" {
			t.Errorf("intent %d landed on %q, want the one ticket", i, got)
		}
	}
}

// --- The ME project: issue type by ID, and the project's own required fields -----------------

// A project whose issue types are renamed, localized or duplicated can only be addressed by ID — and
// an ID is what a Jira admin reads off the screen that worked manually. When one is set the NAME is
// not sent at all, because sending both lets Jira decide which it believes.
func TestRealJiraDelivererSendsTheIssueTypeByIDWhenConfigured(t *testing.T) {
	stub := &jiraStub{refuseLabelsOnCreate: true}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	cfg := jiraConfig(srv.URL)
	cfg.IssueTypeID = "10501"
	cfg.IssueType = "Task" // present, and deliberately NOT sent
	jira, err := delivery.NewRealJiraDeliverer(cfg, nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if _, err := jira.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload(),
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	stub.mu.Lock()
	created := stub.created
	stub.mu.Unlock()
	issuetype, _ := fieldsOf(t, created)["issuetype"].(map[string]any)
	if issuetype["id"] != "10501" {
		t.Errorf("issuetype = %v, want the configured id", issuetype)
	}
	if _, sentName := issuetype["name"]; sentName {
		t.Errorf("issuetype = %v, must carry the id alone", issuetype)
	}
	if got := cfg.String(); !strings.Contains(got, `issue_type_id="10501"`) || strings.Contains(got, `issue_type=`) {
		t.Errorf("the startup line must report the id in force: %s", got)
	}
}

// The ME project's own required fields, merged into every create verbatim — and only into a CREATE.
// Re-asserting a priority or a version on every cycle would overwrite whatever a human changed.
func TestRealJiraDelivererMergesTheProjectsExtraFields(t *testing.T) {
	stub := &jiraStub{refuseLabelsOnCreate: true}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	cfg := jiraConfig(srv.URL)
	cfg.IssueTypeID = "10501"
	cfg.ExtraFieldsJSON = `{
		"customfield_10911": {"value": "Critical"},
		"customfield_11408": {"value": "Internal"},
		"customfield_11409": {"value": "Implementation"},
		"customfield_10804": {"value": "All"},
		"versions": [{"id": "83572"}]
	}`
	jira, err := delivery.NewRealJiraDeliverer(cfg, nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if _, err := jira.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload(),
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	stub.mu.Lock()
	created := stub.created
	stub.mu.Unlock()
	fields := fieldsOf(t, created)
	for name, want := range map[string]string{
		"customfield_10911": "Critical", "customfield_11408": "Internal",
		"customfield_11409": "Implementation", "customfield_10804": "All",
	} {
		value, _ := fields[name].(map[string]any)
		if value["value"] != want {
			t.Errorf("%s = %v, want %q", name, fields[name], want)
		}
	}
	versions := toSlice(fields["versions"])
	if len(versions) != 1 {
		t.Fatalf("versions = %v", fields["versions"])
	}
	if version, _ := versions[0].(map[string]any); version["id"] != "83572" {
		t.Errorf("versions = %v", fields["versions"])
	}
	// Themis's own fields survive the merge.
	if fields["summary"] != "Themis remediation - Release rel-1" {
		t.Errorf("summary = %v", fields["summary"])
	}

	// The UPDATE carries content only — no extra fields to fight a human with.
	stub.mu.Lock()
	stub.existingKey = "SEC-7"
	stub.mu.Unlock()
	if _, err := jira.DeliverIntent(context.Background(), app.Intent{
		ID: "int-2", Type: app.IntentJiraIssue, ReleaseID: "rel-2", PayloadBytes: ticketPayload(),
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	stub.mu.Lock()
	updated := stub.updated
	stub.mu.Unlock()
	updateFields := fieldsOf(t, updated)
	for _, unwanted := range []string{"customfield_10911", "versions"} {
		if _, sent := updateFields[unwanted]; sent {
			t.Errorf("the update must not re-assert %s: %v", unwanted, updateFields)
		}
	}
}

// Extra fields may ADD to a create; they may never take over a field Themis owns. A configuration
// file silently replacing the summary or the body of a security ticket is the one thing this seam
// must not permit — so a reserved key is dropped and the operator is told it was.
func TestExtraFieldsCannotOverrideThemisOwnFields(t *testing.T) {
	stub := &jiraStub{refuseLabelsOnCreate: true}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	core, logs := observer.New(zapcore.DebugLevel)
	cfg := jiraConfig(srv.URL)
	cfg.ExtraFieldsJSON = `{"summary":"anything","description":"anything","project":{"key":"OTHER"},
		"issuetype":{"id":"1"},"labels":["mine"],"customfield_1":"kept"}`
	jira, err := delivery.NewRealJiraDeliverer(cfg, observability.New(zap.New(core)))
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if _, err := jira.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentJiraIssue, ReleaseID: "rel-1", PayloadBytes: ticketPayload(),
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	stub.mu.Lock()
	created := stub.created
	stub.mu.Unlock()
	fields := fieldsOf(t, created)
	if fields["summary"] != "Themis remediation - Release rel-1" {
		t.Errorf("summary = %v, must be Themis's", fields["summary"])
	}
	if project, _ := fields["project"].(map[string]any); project["key"] != "SEC" {
		t.Errorf("project = %v, must be the configured one", fields["project"])
	}
	if issuetype, _ := fields["issuetype"].(map[string]any); issuetype["name"] != "Task" {
		t.Errorf("issuetype = %v, must be Themis's", fields["issuetype"])
	}
	if _, sent := fields["labels"]; sent {
		t.Errorf("labels must not reach a create at all: %v", fields["labels"])
	}
	if body := adfText(t, fields["description"]); !strings.Contains(body, "CVE-2026-0100") {
		t.Errorf("description must be the snapshot, got %q", body)
	}
	// The one non-reserved field is kept — dropping is targeted, not wholesale.
	if fields["customfield_1"] != "kept" {
		t.Errorf("customfield_1 = %v, want it kept", fields["customfield_1"])
	}
	entry, ok := findMessage(logs, "tried to set fields Themis owns")
	if !ok {
		t.Fatal("an ignored reserved field must be logged")
	}
	for _, name := range reservedFieldNames {
		if !strings.Contains(fmt.Sprint(entry.ContextMap()), name) {
			t.Errorf("the warning must name %s: %v", name, entry.ContextMap())
		}
	}
}

var reservedFieldNames = []string{"project", "issuetype", "summary", "description", "labels"}

// Invalid JSON refuses the sender at CONFIGURE time and keeps the fake wired. These fields exist
// because a Jira screen requires them, so a typo must not be discovered one failed create per
// Release, forever.
func TestExtraFieldsInvalidJSONRefusesTheSender(t *testing.T) {
	cfg := jiraConfig("https://acme.atlassian.net")
	for _, raw := range []string{`{"customfield_1":`, `not json at all`, `["an array, not an object"]`, `"a string"`} {
		cfg.ExtraFieldsJSON = raw
		_, err := delivery.NewRealJiraDeliverer(cfg, nil)
		if err == nil {
			t.Errorf("%q must be refused", raw)
			continue
		}
		if !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS") {
			t.Errorf("err = %v, want it to name the variable", err)
		}
	}

	// And the refusal reaches the SELECTION: the fake stays wired, loudly.
	core, logs := observer.New(zapcore.DebugLevel)
	bad := delivery.Config{Enabled: true, Jira: jiraConfig("https://acme.atlassian.net")}
	bad.Jira.ExtraFieldsJSON = `{broken`
	deliverers := delivery.NewDeliverers(bad, nil, observability.New(zap.New(core)))
	if _, fake := deliverers[app.IntentJiraIssue].(*delivery.FakeJiraDeliverer); !fake {
		t.Errorf("jira deliverer = %T, want the fake", deliverers[app.IntentJiraIssue])
	}
	if !hasFieldValue(logs, "THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS") {
		t.Error("the refusal must name the variable in the log")
	}
}

// An empty or whitespace-only value is NOT a parse error: it means "this project needs nothing extra",
// which is every project that works out of the box.
func TestExtraFieldsEmptyIsNotAnError(t *testing.T) {
	cfg := jiraConfig("https://acme.atlassian.net")
	for _, raw := range []string{"", "   ", "{}"} {
		cfg.ExtraFieldsJSON = raw
		if _, err := delivery.NewRealJiraDeliverer(cfg, nil); err != nil {
			t.Errorf("%q must be accepted: %v", raw, err)
		}
	}
}

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

// The flavour vocabularies are CLOSED, and neither falls back. Both fallbacks fail in a way that
// does not look like a configuration error — a PAT sent as a Basic password reads as "the token is
// wrong", and ADF sent to a v2 instance reads as "Jira rejects our ticket" — so a typo is refused at
// startup with the variable named.
func TestJiraConfigRefusesAnUnknownFlavour(t *testing.T) {
	base := delivery.JiraConfig{
		Enabled: true, BaseURL: "https://jira.acme.example/jira", ProjectKey: "SEC",
		User: jiraUser, APIToken: jiraToken,
	}
	for _, tc := range []struct {
		name string
		edit func(*delivery.JiraConfig)
		want string
	}{
		{"misspelled auth mode", func(c *delivery.JiraConfig) { c.Auth = "bear" }, "THEMIS_COMMUNICATION_JIRA_AUTH"},
		{"an auth mode we do not speak", func(c *delivery.JiraConfig) { c.Auth = "oauth" }, "THEMIS_COMMUNICATION_JIRA_AUTH"},
		{"an API version we do not speak", func(c *delivery.JiraConfig) { c.APIVersion = 7 }, "THEMIS_COMMUNICATION_JIRA_API_VERSION"},
		{"API version 1", func(c *delivery.JiraConfig) { c.APIVersion = 1 }, "THEMIS_COMMUNICATION_JIRA_API_VERSION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			_, err := delivery.NewRealJiraDeliverer(cfg, nil)
			if err == nil {
				t.Fatal("an unsupported flavour must be refused at configure time")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %s", err, tc.want)
			}
			// The refusal must point at both flavours, so an operator knows which value to pick.
			for _, hint := range []string{"Cloud", "Data Center"} {
				if !strings.Contains(err.Error(), hint) {
					t.Errorf("err = %v, want it to name the %s option", err, hint)
				}
			}
			if strings.Contains(err.Error(), jiraToken) {
				t.Errorf("err = %v leaked the token", err)
			}
		})
	}
}

// Under `bearer` the USER is not required and not sent: a Personal Access Token identifies its own
// owner, so demanding an account email would make an operator invent a value for a field the request
// does not carry. Under `basic` it stays required.
func TestJiraConfigUserIsRequiredOnlyForBasicAuth(t *testing.T) {
	dataCenter := delivery.JiraConfig{
		Enabled: true, BaseURL: "https://jira.acme.example/jira", ProjectKey: "SEC",
		Auth: delivery.JiraAuthBearer, APIVersion: 2, APIToken: jiraToken,
	}
	if _, err := delivery.NewRealJiraDeliverer(dataCenter, nil); err != nil {
		t.Errorf("bearer auth needs no user: %v", err)
	}

	cloud := dataCenter
	cloud.Auth, cloud.APIVersion, cloud.User = delivery.JiraAuthBasic, 3, ""
	_, err := delivery.NewRealJiraDeliverer(cloud, nil)
	if err == nil {
		t.Fatal("basic auth without a user must be refused")
	}
	if !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_JIRA_USER") {
		t.Errorf("err = %v, want it to name the user variable", err)
	}

	// The flavour defaults are Cloud's, so an existing deployment that sets neither new variable
	// behaves exactly as it did before.
	defaulted := delivery.JiraConfig{
		Enabled: true, BaseURL: "https://acme.atlassian.net", ProjectKey: "SEC",
		User: jiraUser, APIToken: jiraToken,
	}
	if _, err := delivery.NewRealJiraDeliverer(defaulted, nil); err != nil {
		t.Errorf("the Cloud defaults must need no new variable: %v", err)
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
		{"plain http to a path-mounted instance", "http://jira.acme.example/jira", "clear-text http"},
		{"no scheme at all", "jira.acme.example", "not an absolute URL"},
		// The likeliest paste for a self-hosted instance: host and path, no scheme.
		{"host and path, no scheme", "almsbx.radisys.com/jira", "not an absolute URL"},
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
		"https://almsbx.radisys.com/jira", // a path-mounted Data Center instance over TLS
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
	}, nil, logger)

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

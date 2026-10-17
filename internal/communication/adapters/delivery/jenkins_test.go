package delivery_test

import (
	"context"
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
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

const (
	jenkinsUser  = "themis-ci"
	jenkinsToken = "JENKINS-TOKEN-MUST-NEVER-APPEAR"
)

// jenkinsStub records the one request a build start makes.
type jenkinsStub struct {
	mu       sync.Mutex
	path     string
	user     string
	token    string
	authOK   bool
	form     map[string]string
	bodyText string
	status   int
	delay    time.Duration
}

func (j *jenkinsStub) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if j.delay > 0 {
			time.Sleep(j.delay)
		}
		_ = r.ParseForm()
		j.mu.Lock()
		j.path = r.URL.Path
		j.user, j.token, j.authOK = r.BasicAuth()
		j.form = map[string]string{}
		for k := range r.PostForm {
			j.form[k] = r.PostForm.Get(k)
		}
		j.bodyText = r.PostForm.Encode()
		status := j.status
		j.mu.Unlock()
		if status == 0 {
			w.Header().Set("Location", "http://jenkins.local/queue/item/42/")
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("jenkins says no"))
	}
}

func rebuildIntent() app.Intent {
	payload := app.BuildPayload("Themis rebuild - Release rel-1 - attempt 1", []byte("params"))
	return app.Intent{
		ID: "int-rebuild-1", Type: app.IntentCIRebuild, Destination: "team/build-image", State: app.IntentPending,
		ProductID: "prod-1", ProjectID: "prj-1", ReleaseID: "rel-1",
		PayloadBytes: payload, PayloadSHA256: app.PayloadDigest(payload),
		Snapshot: map[string]string{
			app.SnapshotPriorSBOMID: "ev-1", app.SnapshotTargetedCVEs: "CVE-2026-1,CVE-2026-2", app.SnapshotAttempt: "1",
		},
	}
}

func jenkinsConfig(baseURL string) delivery.JenkinsConfig {
	return delivery.JenkinsConfig{Enabled: true, BaseURL: baseURL, User: jenkinsUser, APIToken: jenkinsToken, Job: "team/build-image"}
}

// N-M2g: the sender POSTs buildWithParameters for the folder job over Basic auth, hands the job the
// snapshot facts as parameters — and nothing else — records the queue item, surfaces a refusal,
// refuses the wrong intent type and an unrendered intent, and will not put the token on a
// clear-text channel.
func TestCIBuildSender_BasicAuth_Params_HTTPSRefusal(t *testing.T) {
	stub := &jenkinsStub{}
	srv := httptest.NewServer(stub.handler())
	t.Cleanup(srv.Close)

	sender, err := delivery.NewRealJenkinsDeliverer(jenkinsConfig(srv.URL+"/jenkins/"), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	res, err := sender.DeliverIntent(context.Background(), rebuildIntent())
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if stub.path != "/jenkins/job/team/job/build-image/buildWithParameters" {
		t.Errorf("path = %q", stub.path)
	}
	if !stub.authOK || stub.user != jenkinsUser || stub.token != jenkinsToken {
		t.Errorf("basic auth = %q/%v", stub.user, stub.authOK)
	}
	want := map[string]string{
		delivery.ParamIntentID: "int-rebuild-1", delivery.ParamProductID: "prod-1", delivery.ParamProjectID: "prj-1",
		delivery.ParamReleaseID: "rel-1", delivery.ParamPriorSBOMID: "ev-1", delivery.ParamTargetedCVEs: "CVE-2026-1,CVE-2026-2",
		delivery.ParamAttempt: "1",
	}
	for k, v := range want {
		if stub.form[k] != v {
			t.Errorf("param %s = %q, want %q", k, stub.form[k], v)
		}
	}
	if len(stub.form) != len(want) {
		t.Errorf("params = %v, want exactly the snapshot facts", stub.form)
	}
	if strings.Contains(stub.bodyText, jenkinsToken) {
		t.Error("the token is in the parameters")
	}
	if res.StatusCode != http.StatusCreated || res.Metadata["queue_item"] != "http://jenkins.local/queue/item/42/" || res.Metadata["job"] != "team/build-image" {
		t.Errorf("result = %+v", res)
	}

	// A refusal from Jenkins is an error with the status and an excerpt, never a silent success.
	stub.status = http.StatusForbidden
	if _, err := sender.DeliverIntent(context.Background(), rebuildIntent()); err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "jenkins says no") {
		t.Errorf("refusal err = %v", err)
	}
	stub.status = 0

	// Wrong type and unrendered intents are refused before any request.
	if _, err := sender.DeliverIntent(context.Background(), app.Intent{Type: app.IntentEmail}); err == nil {
		t.Error("a mail intent must be refused by the rebuild sender")
	}
	bare := rebuildIntent()
	bare.PayloadBytes = nil
	if _, err := sender.DeliverIntent(context.Background(), bare); err == nil {
		t.Error("an unrendered intent must be refused (D-N-3)")
	}

	// Clear-text refusal at configure time, loopback excepted; the error names the variable and
	// never the token.
	for _, bad := range []string{"http://ci.acme.example", "http://10.0.0.5:8080/jenkins", "ci.acme.example", "ftp://ci.acme.example"} {
		_, err := delivery.NewRealJenkinsDeliverer(jenkinsConfig(bad), nil)
		if err == nil {
			t.Errorf("%q must be refused", bad)
			continue
		}
		if !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_JENKINS_URL") || strings.Contains(err.Error(), jenkinsToken) {
			t.Errorf("err = %v", err)
		}
	}
	for _, ok := range []string{"https://ci.acme.example", "https://acme.example/jenkins", "http://127.0.0.1:8080", "http://localhost:8080"} {
		if _, err := delivery.NewRealJenkinsDeliverer(jenkinsConfig(ok), nil); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	incomplete := jenkinsConfig("https://ci.acme.example")
	incomplete.Job, incomplete.APIToken = "", ""
	if _, err := delivery.NewRealJenkinsDeliverer(incomplete, nil); err == nil ||
		!strings.Contains(err.Error(), "THEMIS_COMMUNICATION_JENKINS_JOB") || !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_JENKINS_API_TOKEN") {
		t.Errorf("incomplete config err = %v, want the missing variables named", err)
	}

	// The refusal reaches the SELECTION: the fake stays wired and the reason is logged at ERROR.
	core, logs := observer.New(zapcore.DebugLevel)
	deliverers := delivery.NewDeliverers(delivery.Config{Enabled: true, Jenkins: jenkinsConfig("http://ci.acme.example")}, nil, observability.New(zap.New(core)))
	if _, fake := deliverers[app.IntentCIRebuild].(*delivery.FakeCIRebuildDeliverer); !fake {
		t.Errorf("rebuild deliverer = %T, want the fake", deliverers[app.IntentCIRebuild])
	}
	if !hasFieldValue(logs, "clear-text http") {
		t.Error("the refusal must be logged with its reason")
	}
	for _, e := range logs.All() {
		if strings.Contains(fmt.Sprint(e.ContextMap()), jenkinsToken) {
			t.Fatal("the token reached the logs")
		}
	}
	// And a complete https configuration selects the real sender.
	real := delivery.NewDeliverers(delivery.Config{Enabled: true, Jenkins: jenkinsConfig("https://ci.acme.example")}, nil, nil)
	if _, ok := real[app.IntentCIRebuild].(*delivery.RealJenkinsDeliverer); !ok {
		t.Errorf("rebuild deliverer = %T, want the real sender", real[app.IntentCIRebuild])
	}
	if s := jenkinsConfig("https://ci.acme.example").String(); strings.Contains(s, jenkinsToken) || !strings.Contains(s, "api_token=set") {
		t.Errorf("String() = %s", s)
	}
}

// M1b-6a for this sender: one call is bounded by the configured timeout, so a hung Jenkins
// costs one attempt, not the worker.
func TestCIBuildSender_PerCallTimeout(t *testing.T) {
	stub := &jenkinsStub{delay: 300 * time.Millisecond}
	srv := httptest.NewServer(stub.handler())
	t.Cleanup(srv.Close)
	cfg := jenkinsConfig(srv.URL)
	cfg.Timeout = 50 * time.Millisecond
	sender, err := delivery.NewRealJenkinsDeliverer(cfg, nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	start := time.Now()
	if _, err := sender.DeliverIntent(context.Background(), rebuildIntent()); err == nil {
		t.Fatal("a hung Jenkins must fail the attempt")
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Error("the call outlived its timeout")
	}
}

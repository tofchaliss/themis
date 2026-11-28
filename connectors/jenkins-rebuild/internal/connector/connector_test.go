package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSecret = "signing-secret-for-tests"

var t0 = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{
		"store_dir": "unused", "signing_secret_env": "SIGN",
		"themis": {"callback_url": "https://themis.example/communication/api/v1/callbacks/ci-rebuild", "api_key_env": "KEY"},
		"jenkins": {"url": "https://ci.example", "user": "themis-builder", "token_env": "TOKEN"},
		"allow": [{"product_id": "prod-1", "project_id": "proj-1", "jobs": ["team/build-image"]}],
		"jobs": {"team/build-image": {"parameters": {
			"BRANCH": {"rule": "branch", "required": true},
			"TAG": {"rule": "image_tag"},
			"REGISTRY": {"rule": "registry_path"},
			"MODE": {"rule": "enum", "values": ["full", "quick"]},
			"PUSH": {"rule": "bool"},
			"RETRIES": {"rule": "int"},
			"NOTE": {"rule": "text", "max_len": 20}
		}}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// eventBody is a request for prod-1/proj-1 with the given id, time and build profile.
func eventBody(id string, at time.Time, build string) []byte {
	return []byte(`{"specversion":"1.0","type":"themis.rebuild.requested.v1","id":"` + id + `","time":"` + at.Format(time.RFC3339) + `",
		"source":"themis/communication","data":{"product_id":"prod-1","project_id":"proj-1","release_id":"rel-1",
		"prior_sbom_id":"sbom-1","decision_id":"dec-1","cycle_id":"7","attempt":1,"try":1,
		"targeted":[{"cve":"CVE-2026-0002"},{"cve":"CVE-2026-0001"},{"cve":"CVE-2026-0002"}],"build":` + build + `}}`)
}

const goodBuild = `{"job":"team/build-image","parameters":{"BRANCH":"release/1.2","PUSH":true,"RETRIES":2}}`

// fakeBuilder is a build system that remembers what it was asked.
type fakeBuilder struct {
	mu        sync.Mutex
	submits   []map[string]string
	submitErr error
	submitRef string
	block     chan struct{} // when set, Submit waits for it (or the context)
	entered   chan struct{}
	builds    map[string]string // intent id -> ref, what Find sees
	findErr   error
	complete  bool
	finds     int
	credErr   error
}

func newBuilder() *fakeBuilder {
	return &fakeBuilder{submitRef: "https://ci.example/queue/item/41/", builds: map[string]string{}, complete: true}
}

func (b *fakeBuilder) Submit(ctx context.Context, _ string, params map[string]string) (string, error) {
	b.mu.Lock()
	b.submits = append(b.submits, params)
	block, entered, err, ref := b.block, b.entered, b.submitErr, b.submitRef
	b.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	b.builds[params["THEMIS_INTENT_ID"]] = ref
	b.mu.Unlock()
	return ref, nil
}

func (b *fakeBuilder) Find(_ context.Context, _, intentID string, _ time.Time) (string, bool, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finds++
	if b.findErr != nil {
		return "", false, false, b.findErr
	}
	ref, ok := b.builds[intentID]
	return ref, ok, b.complete, nil
}

func (b *fakeBuilder) CheckCredential(context.Context, []string) error { return b.credErr }

func (b *fakeBuilder) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.submits)
}

type fakeReporter struct {
	mu    sync.Mutex
	sent  []Record
	fails int
}

func (r *fakeReporter) Report(_ context.Context, rec Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fails > 0 {
		r.fails--
		return errors.New("themis down")
	}
	r.sent = append(r.sent, rec)
	return nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type rig struct {
	cfg      Config
	store    *FileStore
	builder  *fakeBuilder
	reporter *fakeReporter
	clock    *clock
	c        *Connector
}

func newRig(t *testing.T) *rig {
	t.Helper()
	store, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{cfg: testConfig(t), store: store, builder: newBuilder(), reporter: &fakeReporter{}, clock: &clock{t: t0}}
	r.c = r.instance("worker-a")
	return r
}

// instance is another connector instance on the same store: a second worker, or the same
// connector after a restart.
func (r *rig) instance(owner string) *Connector {
	return New(r.cfg, testSecret, r.store, r.builder, r.reporter, owner, nil).WithClock(r.clock.now)
}

func (r *rig) receive(t *testing.T, body []byte) {
	t.Helper()
	if status, msg := r.c.Receive(Sign(body, testSecret), body); status != http.StatusAccepted {
		t.Fatalf("receive = %d %s", status, msg)
	}
}

func (r *rig) record(t *testing.T, id string) Record {
	t.Helper()
	rec, found, err := r.store.Get(id)
	if err != nil || !found {
		t.Fatalf("record %s: found %v err %v", id, found, err)
	}
	return rec
}

// The whole path: a signed, allowed request is recorded, submitted once with its parameters as
// values, and Themis is told with the identity the build system gave.
func TestRequestIsSubmittedOnceAndReported(t *testing.T) {
	r := newRig(t)
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	if rec := r.record(t, "intent-1"); rec.State != StateReceived || rec.Job != "team/build-image" {
		t.Fatalf("after receive = %+v", rec)
	}
	r.c.Recover(context.Background())
	rec := r.record(t, "intent-1")
	if rec.State != StateSubmitted || rec.BuildRef != "https://ci.example/queue/item/41/" || !rec.Reported || rec.ClaimCounter != 1 {
		t.Fatalf("after recover = %+v", rec)
	}
	if r.builder.count() != 1 {
		t.Fatalf("builds = %d, want 1", r.builder.count())
	}
	got := r.builder.submits[0]
	want := map[string]string{
		"BRANCH": "release/1.2", "PUSH": "true", "RETRIES": "2",
		"THEMIS_INTENT_ID": "intent-1", "THEMIS_PRODUCT_ID": "prod-1", "THEMIS_PROJECT_ID": "proj-1", "THEMIS_RELEASE_ID": "rel-1",
		"THEMIS_PRIOR_SBOM_ID": "sbom-1", "THEMIS_ATTEMPT": "1", "THEMIS_TARGETED_CVES": "CVE-2026-0001,CVE-2026-0002",
	}
	if len(got) != len(want) {
		t.Fatalf("parameters = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("parameter %s = %q, want %q", k, got[k], v)
		}
	}
	if len(r.reporter.sent) != 1 || r.reporter.sent[0].State != StateSubmitted || r.reporter.sent[0].BuildRef == "" {
		t.Fatalf("reports = %+v", r.reporter.sent)
	}
	// D12 item 2: the same event again is acknowledged and submits nothing.
	body := eventBody("intent-1", t0, goodBuild)
	if status, msg := r.c.Receive(Sign(body, testSecret), body); status != http.StatusAccepted || !strings.Contains(msg, "already recorded as submitted") {
		t.Errorf("repeat = %d %s", status, msg)
	}
	r.c.Recover(context.Background())
	if r.builder.count() != 1 || len(r.reporter.sent) != 1 {
		t.Errorf("after a repeat: builds %d reports %d", r.builder.count(), len(r.reporter.sent))
	}
}

func TestSignatureAndBodyAreChecked(t *testing.T) {
	r := newRig(t)
	body := eventBody("intent-1", t0, goodBuild)
	for name, sig := range map[string]string{
		"none": "", "wrong secret": Sign(body, "other"), "not hex": "sha256=zz", "no prefix": strings.TrimPrefix(Sign(body, testSecret), "sha256="),
		"of another body": Sign([]byte("x"), testSecret),
	} {
		if status, _ := r.c.Receive(sig, body); status != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, status)
		}
	}
	if VerifySignature(Sign(body, ""), body, "") {
		t.Error("an empty secret must verify nothing")
	}
	for name, raw := range map[string]string{"not json": "{", "no id": `{"type":"themis.rebuild.requested.v1"}`, "long id": `{"id":"` + strings.Repeat("x", 201) + `"}`} {
		if status, _ := r.c.Receive(Sign([]byte(raw), testSecret), []byte(raw)); status != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, status)
		}
	}
	if recs, _ := r.store.List(); len(recs) != 0 {
		t.Errorf("nothing may be stored for an unsigned or unreadable request: %+v", recs)
	}
}

// D18, D20, D31: a request that fails a check is recorded as refused, reported, and never
// reaches the build system.
func TestRefusalsByCheck(t *testing.T) {
	old := t0.Add(-25 * time.Hour)
	cases := map[string]struct {
		body []byte
		why  string
	}{
		"unknown type":      {[]byte(`{"type":"themis.other.v1","id":"i","time":"2026-11-28T12:00:00Z"}`), "not known"},
		"too old":           {eventBody("i", old, goodBuild), "older than"},
		"no time":           {[]byte(`{"type":"themis.rebuild.requested.v1","id":"i"}`), "older than"},
		"no build profile":  {eventBody("i", t0, `null`), "names no job"},
		"job not allowed":   {eventBody("i", t0, `{"job":"team/other","parameters":{"BRANCH":"main"}}`), "not allowed for this product"},
		"unknown parameter": {eventBody("i", t0, `{"job":"team/build-image","parameters":{"BRANCH":"main","EXTRA":"x"}}`), `"EXTRA" is not in the schema`},
		"missing required":  {eventBody("i", t0, `{"job":"team/build-image","parameters":{"TAG":"v1"}}`), `required parameter "BRANCH"`},
		"reserved name":     {eventBody("i", t0, `{"job":"team/build-image","parameters":{"BRANCH":"main","THEMIS_INTENT_ID":"x"}}`), "set by the connector"},
		"structured value":  {eventBody("i", t0, `{"job":"team/build-image","parameters":{"BRANCH":["main"]}}`), "not a text"},
		"bad value":         {eventBody("i", t0, `{"job":"team/build-image","parameters":{"BRANCH":"main; rm -rf /"}}`), "not a valid branch"},
		"too long":          {eventBody("i", t0, `{"job":"team/build-image","parameters":{"BRANCH":"main","NOTE":"`+strings.Repeat("a", 21)+`"}}`), "longer than 20"},
		"bad cve":           {[]byte(strings.Replace(string(eventBody("i", t0, goodBuild)), "CVE-2026-0001", "$(id)", 1)), "no valid CVE"},
		"bad release id":    {[]byte(strings.Replace(string(eventBody("i", t0, goodBuild)), "rel-1", "rel;1", 1)), "THEMIS_RELEASE_ID"},
	}
	for name, tc := range cases {
		r := newRig(t)
		r.receive(t, tc.body)
		r.c.Recover(context.Background())
		rec := r.record(t, "i")
		if rec.State != StateRefused || !strings.Contains(rec.Reason, tc.why) || !rec.Reported {
			t.Errorf("%s: %+v", name, rec)
		}
		if r.builder.count() != 0 || len(r.reporter.sent) != 1 || r.reporter.sent[0].State != StateRefused {
			t.Errorf("%s: builds %d reports %+v", name, r.builder.count(), r.reporter.sent)
		}
	}
	// A product that is not in the allow-list at all.
	r := newRig(t)
	r.receive(t, []byte(strings.Replace(string(eventBody("i", t0, goodBuild)), "prod-1", "prod-9", 1)))
	if rec := r.record(t, "i"); rec.State != StateRefused {
		t.Errorf("other product: %+v", rec)
	}
}

// The build system says no: refused, with its reason, and no second call.
func TestBuildSystemRefuses(t *testing.T) {
	r := newRig(t)
	r.builder.submitErr = &RefusedError{Reason: "jenkins refused the build with status 403"}
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	r.c.Recover(context.Background())
	r.c.Recover(context.Background())
	rec := r.record(t, "intent-1")
	if rec.State != StateRefused || !strings.Contains(rec.Reason, "403") || r.builder.count() != 1 || len(r.reporter.sent) != 1 {
		t.Fatalf("record %+v builds %d reports %d", rec, r.builder.count(), len(r.reporter.sent))
	}
}

// D37 item 4: the report is repeated until Themis answers with success, and then no more.
func TestReportIsRepeatedUntilConfirmed(t *testing.T) {
	r := newRig(t)
	r.reporter.fails = 2
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	for i := 0; i < 4; i++ {
		r.c.Recover(context.Background())
	}
	if rec := r.record(t, "intent-1"); !rec.Reported || len(r.reporter.sent) != 1 || r.builder.count() != 1 {
		t.Fatalf("record %+v reports %d builds %d", rec, len(r.reporter.sent), r.builder.count())
	}
}

// D37: stop the connector in each state, start it again, and check the end state and the
// number of builds.
func TestRestartInEachState(t *testing.T) {
	ctx := context.Background()

	t.Run("received", func(t *testing.T) {
		r := newRig(t)
		r.receive(t, eventBody("intent-1", t0, goodBuild)) // stored, answered, then the process stops
		r.instance("after-restart").Recover(ctx)
		if rec := r.record(t, "intent-1"); rec.State != StateSubmitted || r.builder.count() != 1 {
			t.Fatalf("%+v builds %d", rec, r.builder.count())
		}
	})

	t.Run("submitting, the build exists", func(t *testing.T) {
		r := newRig(t)
		r.receive(t, eventBody("intent-1", t0, goodBuild))
		// The call reached the build system and the process stopped before the outcome record.
		if _, ok, _ := r.store.Claim("intent-1", "before-restart", t0, time.Duration(r.cfg.ClaimTTL)); !ok {
			t.Fatal("claim")
		}
		r.builder.builds["intent-1"] = "https://ci.example/job/team/job/build-image/12/"
		after := r.instance("after-restart")
		after.Recover(ctx) // the old claim still runs: nothing happens
		if rec := r.record(t, "intent-1"); rec.State != StateSubmitting || r.builder.finds != 0 {
			t.Fatalf("inside the claim: %+v finds %d", rec, r.builder.finds)
		}
		r.clock.add(time.Duration(r.cfg.ClaimTTL) + claimMargin + time.Second)
		after.Recover(ctx)
		rec := r.record(t, "intent-1")
		if rec.State != StateSubmitted || rec.BuildRef == "" || r.builder.count() != 0 || !rec.Reported {
			t.Fatalf("%+v builds %d", rec, r.builder.count())
		}
	})

	t.Run("submitting, no build, the search is complete", func(t *testing.T) {
		r := newRig(t)
		r.receive(t, eventBody("intent-1", t0, goodBuild))
		if _, ok, _ := r.store.Claim("intent-1", "before-restart", t0, time.Duration(r.cfg.ClaimTTL)); !ok {
			t.Fatal("claim")
		}
		r.clock.add(time.Duration(r.cfg.ClaimTTL) + claimMargin + time.Second)
		r.instance("after-restart").Recover(ctx)
		if rec := r.record(t, "intent-1"); rec.State != StateSubmitted || r.builder.count() != 1 || r.builder.finds != 1 {
			t.Fatalf("%+v builds %d finds %d", rec, r.builder.count(), r.builder.finds)
		}
	})

	t.Run("submitting, no build, the search cannot rule one out", func(t *testing.T) {
		r := newRig(t)
		r.builder.complete = false
		r.receive(t, eventBody("intent-1", t0, goodBuild))
		if _, ok, _ := r.store.Claim("intent-1", "before-restart", t0, time.Duration(r.cfg.ClaimTTL)); !ok {
			t.Fatal("claim")
		}
		r.clock.add(time.Duration(r.cfg.ClaimTTL) + claimMargin + time.Second)
		r.instance("after-restart").Recover(ctx)
		rec := r.record(t, "intent-1")
		if rec.State != StateUncertain || r.builder.count() != 0 || !rec.Reported || r.reporter.sent[0].State != StateUncertain {
			t.Fatalf("%+v builds %d", rec, r.builder.count())
		}
	})

	t.Run("submitting, the build system cannot be asked", func(t *testing.T) {
		r := newRig(t)
		r.builder.findErr = errors.New("jenkins down")
		r.receive(t, eventBody("intent-1", t0, goodBuild))
		if _, ok, _ := r.store.Claim("intent-1", "before-restart", t0, time.Duration(r.cfg.ClaimTTL)); !ok {
			t.Fatal("claim")
		}
		after := r.instance("after-restart")
		for i := 0; i < questionTries; i++ {
			r.clock.add(time.Duration(r.cfg.ClaimTTL) + claimMargin + time.Second)
			after.Recover(ctx)
		}
		rec := r.record(t, "intent-1")
		if rec.State != StateUncertain || r.builder.count() != 0 || r.builder.finds != questionTries {
			t.Fatalf("%+v builds %d finds %d", rec, r.builder.count(), r.builder.finds)
		}
	})

	for _, end := range []string{StateSubmitted, StateRefused, StateUncertain} {
		t.Run(end+", the report was not confirmed", func(t *testing.T) {
			r := newRig(t)
			r.receive(t, eventBody("intent-1", t0, goodBuild))
			rec, _, _ := r.store.Claim("intent-1", "before-restart", t0, time.Duration(r.cfg.ClaimTTL))
			if ok, _ := r.store.Outcome("intent-1", rec.ClaimCounter, end, "ref", "why", t0); !ok {
				t.Fatal("outcome")
			}
			r.instance("after-restart").Recover(ctx)
			if got := r.record(t, "intent-1"); got.State != end || !got.Reported || r.builder.count() != 0 || len(r.reporter.sent) != 1 {
				t.Fatalf("%+v builds %d reports %d", got, r.builder.count(), len(r.reporter.sent))
			}
		})
	}
}

// D39: two workers and two instances on one received record give one call.
func TestTwoWorkersGiveOneCall(t *testing.T) {
	r := newRig(t)
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	var wg sync.WaitGroup
	for _, owner := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		wg.Add(1)
		go func(c *Connector) {
			defer wg.Done()
			c.Recover(context.Background())
		}(r.instance(owner))
	}
	wg.Wait()
	if rec := r.record(t, "intent-1"); rec.State != StateSubmitted || r.builder.count() != 1 || rec.ClaimCounter != 1 {
		t.Fatalf("%+v builds %d", rec, r.builder.count())
	}
	if len(r.reporter.sent) < 1 {
		t.Fatal("the end state must be reported")
	}
}

// D39 items 3 and 4: a worker stopped inside the call, then a take-over. There is no second
// call before the question, and the old worker's late outcome is refused.
func TestStoppedWorkerAndTakeOver(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.builder.block, r.builder.entered = make(chan struct{}), make(chan struct{}, 1)
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	done := make(chan struct{})
	go func() {
		r.c.Recover(ctx) // worker-a enters the call and hangs there
		close(done)
	}()
	<-r.builder.entered

	b := r.instance("worker-b")
	b.Recover(ctx)
	if r.builder.count() != 1 || r.builder.finds != 0 {
		t.Fatalf("inside the claim: calls %d finds %d", r.builder.count(), r.builder.finds)
	}
	// The claim ends. worker-b takes over for the question only. The build system has the
	// build (the hung call was accepted), so nothing is submitted again.
	r.builder.mu.Lock()
	r.builder.builds["intent-1"] = "https://ci.example/queue/item/41/"
	r.builder.mu.Unlock()
	r.clock.add(time.Duration(r.cfg.ClaimTTL) + claimMargin + time.Second)
	b.Recover(ctx)
	rec := r.record(t, "intent-1")
	if rec.State != StateSubmitted || rec.ClaimCounter != 2 || r.builder.count() != 1 || r.builder.finds != 1 {
		t.Fatalf("after the take-over: %+v calls %d finds %d", rec, r.builder.count(), r.builder.finds)
	}
	// worker-a comes back with its answer under the old counter: refused, nothing changes.
	r.builder.mu.Lock()
	r.builder.submitRef = "https://ci.example/queue/item/99/"
	r.builder.mu.Unlock()
	close(r.builder.block)
	<-done
	if got := r.record(t, "intent-1"); got.BuildRef != "https://ci.example/queue/item/41/" || got.State != StateSubmitted {
		t.Fatalf("the late outcome changed the record: %+v", got)
	}
	if ok, _ := r.store.Outcome("intent-1", 1, StateRefused, "", "late", t0); ok {
		t.Error("an outcome with an old counter must be refused")
	}
}

// A call that ends without an answer leaves the record in submitting; nothing is called again
// blindly (D12 item 3).
func TestCallWithoutAnAnswerIsNotRepeated(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.builder.submitErr = errors.New("connection reset")
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	r.c.Recover(ctx)
	r.c.Recover(ctx)
	if rec := r.record(t, "intent-1"); rec.State != StateSubmitting || r.builder.count() != 1 {
		t.Fatalf("%+v calls %d", rec, r.builder.count())
	}
	// After the claim: the build system has no build and says so completely -> one new call.
	r.builder.submitErr = nil
	r.clock.add(time.Duration(r.cfg.ClaimTTL) + claimMargin + time.Second)
	r.c.Recover(ctx)
	if rec := r.record(t, "intent-1"); rec.State != StateSubmitted || r.builder.count() != 2 || r.builder.finds != 1 {
		t.Fatalf("%+v calls %d finds %d", rec, r.builder.count(), r.builder.finds)
	}
}

// D33: the connector does not start when the check fails or cannot be run. Only "too broad"
// can be accepted, by the explicit setting, and then it shows on /status.
func TestCredentialCheckFailsClosed(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	if err := r.c.CheckCredential(ctx); err != nil {
		t.Fatalf("a narrow credential: %v", err)
	}
	r.builder.credErr = errors.New("the credential check could not be run: jenkins answered 500")
	if err := r.c.CheckCredential(ctx); err == nil {
		t.Fatal("a check that cannot be run must stop the start")
	}
	r.builder.credErr = ErrBroadCredential
	if err := r.c.CheckCredential(ctx); !errors.Is(err, ErrBroadCredential) {
		t.Fatalf("a broad credential must stop the start: %v", err)
	}
	r.cfg.Jenkins.AcceptBroadCredential = true
	accepted := r.instance("x")
	if err := accepted.CheckCredential(ctx); err != nil {
		t.Fatalf("accepted by setting: %v", err)
	}
	r.builder.credErr = errors.New("the credential check could not be run")
	if err := r.instance("y").CheckCredential(ctx); err == nil {
		t.Fatal("the setting accepts a broad credential only, never a check that could not be run")
	}
	srv := httptest.NewServer(accepted.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil || !st.BroadCredentialAccepted {
		t.Fatalf("status = %+v %v", st, err)
	}
}

func TestHTTPAddresses(t *testing.T) {
	r := newRig(t)
	srv := httptest.NewServer(r.c.Handler())
	defer srv.Close()
	post := func(body []byte, sig string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/events", strings.NewReader(string(body)))
		req.Header.Set(SignatureHeader, sig)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	body := eventBody("intent-1", t0, goodBuild)
	if code := post(body, Sign(body, testSecret)); code != http.StatusAccepted {
		t.Fatalf("event = %d", code)
	}
	if code := post(body, "sha256=00"); code != http.StatusUnauthorized {
		t.Errorf("bad signature = %d", code)
	}
	big := []byte(strings.Repeat("x", maxEventBytes+1))
	if code := post(big, Sign(big, testSecret)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large = %d", code)
	}
	if resp, err := http.Get(srv.URL + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: %v", err)
	}
	if resp, err := http.Get(srv.URL + "/events"); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /events must not be served: %v", err)
	}
	r.c.Recover(context.Background())
	resp, err := http.Get(srv.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil || st.States[StateSubmitted] != 1 || st.Unreported != 0 || st.BroadCredentialAccepted {
		t.Fatalf("status = %+v %v", st, err)
	}
}

// Run does a pass at start, one on each new request, and stops with the context.
func TestRunLoop(t *testing.T) {
	r := newRig(t)
	r.receive(t, eventBody("intent-0", t0, goodBuild))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.c.Run(ctx)
		close(done)
	}()
	waitFor(t, func() bool { return r.builder.count() == 1 })
	r.receive(t, eventBody("intent-1", t0, goodBuild))
	waitFor(t, func() bool { return r.builder.count() == 2 })
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// Old reported records are removed; open ones and unreported ones never are.
func TestPrune(t *testing.T) {
	r := newRig(t)
	r.receive(t, eventBody("done", t0, goodBuild))
	r.c.Recover(context.Background())
	r.reporter.fails = 1000
	r.receive(t, eventBody("unreported", t0, goodBuild))
	r.c.Recover(context.Background())
	r.clock.add(time.Duration(r.cfg.Retention) + time.Hour)
	r.c.Recover(context.Background())
	recs, _ := r.store.List()
	if len(recs) != 1 || recs[0].IntentID != "unreported" {
		t.Fatalf("after pruning = %+v", recs)
	}
}

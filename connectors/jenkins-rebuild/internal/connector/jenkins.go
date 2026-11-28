package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Builder is the build system as the connector uses it. The reference connector has one
// implementation, for Jenkins (D8, D33 item 5).
type Builder interface {
	// Submit asks for one build. A *RefusedError means the build system said no and nothing
	// was submitted. Any other error means the result is not known.
	Submit(ctx context.Context, job string, params map[string]string) (buildRef string, err error)
	// Find looks for a build that carries the intent id. complete says whether "not found" may
	// be believed (D39 item 5).
	Find(ctx context.Context, job, intentID string, since time.Time) (buildRef string, found, complete bool, err error)
	// CheckCredential asks the build system what the credential can reach (D33). It never
	// starts a job to find out.
	CheckCredential(ctx context.Context, allowed []string) error
}

// RefusedError is the build system's own "no": the request was not accepted.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return e.Reason }

// ErrBroadCredential is why the connector does not start: the credential reaches more than the
// allow-list (D33 item 3).
var ErrBroadCredential = errors.New("the build-system credential can reach jobs outside the allow-list")

// buildsWindow is how many of the newest builds of a job are searched.
const buildsWindow = 100

// folderDepth is how deep the job tree is read for the credential check.
const folderDepth = 6

// Jenkins talks to one Jenkins server with a user name and an API token.
//
// What the search covers (the statement D39 item 5 asks for): the queue, which holds a build
// from the moment Jenkins accepted the request until it starts, and the newest builds of the
// job, running and finished. A build leaves the queue an instant before it shows as a build,
// so the search is made twice, Settle apart, and "not found" needs both passes. It is said to
// be complete only when the builds that were read reach back before the time the request was
// received. Otherwise the answer is "cannot tell".
type Jenkins struct {
	BaseURL string
	User    string
	Token   string
	Client  *http.Client
	// Settle is the pause between the two search passes.
	Settle time.Duration
}

// NewJenkins wires the client.
func NewJenkins(baseURL, user, token string, timeout time.Duration) *Jenkins {
	return &Jenkins{BaseURL: strings.TrimRight(baseURL, "/"), User: user, Token: token,
		Client: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Settle: 3 * time.Second}
}

func (j *Jenkins) do(ctx context.Context, method, path string, form url.Values) (*http.Response, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, j.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(j.User, j.Token)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return j.Client.Do(req)
}

func (j *Jenkins) getJSON(ctx context.Context, path string, into any) error {
	resp, err := j.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jenkins answered %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(into)
}

// Submit starts the job with its parameters as form values. No value is ever part of a
// command or a script (D31).
func (j *Jenkins) Submit(ctx context.Context, job string, params map[string]string) (string, error) {
	path, err := jobPath(job)
	if err != nil {
		return "", &RefusedError{Reason: err.Error()}
	}
	form := url.Values{}
	for name, v := range params {
		form.Set(name, v)
	}
	resp, err := j.do(ctx, http.MethodPost, path+"/buildWithParameters", form)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther:
		if loc := resp.Header.Get("Location"); loc != "" {
			return loc, nil
		}
		return "accepted by jenkins (no queue item named)", nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return "", &RefusedError{Reason: fmt.Sprintf("jenkins refused the build with status %d", resp.StatusCode)}
	default:
		return "", fmt.Errorf("jenkins answered %d", resp.StatusCode)
	}
}

type jenkinsParam struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type jenkinsActions []struct {
	Parameters []jenkinsParam `json:"parameters"`
}

func (a jenkinsActions) carries(intentID string) bool {
	for _, act := range a {
		for _, p := range act.Parameters {
			if v, ok := p.Value.(string); ok && p.Name == "THEMIS_INTENT_ID" && v == intentID {
				return true
			}
		}
	}
	return false
}

// pass searches the queue and the newest builds once.
func (j *Jenkins) pass(ctx context.Context, path, intentID string, since time.Time) (ref string, found, complete bool, err error) {
	var queue struct {
		Items []struct {
			ID      int64          `json:"id"`
			Actions jenkinsActions `json:"actions"`
		} `json:"items"`
	}
	if err := j.getJSON(ctx, "/queue/api/json?tree=items[id,actions[parameters[name,value]]]", &queue); err != nil {
		return "", false, false, err
	}
	for _, it := range queue.Items {
		if it.Actions.carries(intentID) {
			return fmt.Sprintf("%s/queue/item/%d/", j.BaseURL, it.ID), true, true, nil
		}
	}
	var builds struct {
		Builds []struct {
			URL       string         `json:"url"`
			Timestamp int64          `json:"timestamp"`
			Actions   jenkinsActions `json:"actions"`
		} `json:"builds"`
	}
	tree := fmt.Sprintf("builds[url,timestamp,actions[parameters[name,value]]]{0,%d}", buildsWindow)
	if err := j.getJSON(ctx, path+"/api/json?tree="+url.QueryEscape(tree), &builds); err != nil {
		return "", false, false, err
	}
	oldest := time.Time{}
	for _, b := range builds.Builds {
		if b.Actions.carries(intentID) {
			return b.URL, true, true, nil
		}
		if at := time.UnixMilli(b.Timestamp); oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	// Complete when every build of the job was read, or the ones read reach back before the
	// request was received (with a minute of margin for clocks).
	complete = len(builds.Builds) < buildsWindow || oldest.Before(since.Add(-time.Minute))
	return "", false, complete, nil
}

// Find implements Builder.
func (j *Jenkins) Find(ctx context.Context, job, intentID string, since time.Time) (string, bool, bool, error) {
	path, err := jobPath(job)
	if err != nil {
		return "", false, false, err
	}
	ref, found, complete, err := j.pass(ctx, path, intentID, since)
	if err != nil || found {
		return ref, found, complete, err
	}
	select {
	case <-ctx.Done():
		return "", false, false, ctx.Err()
	case <-time.After(j.Settle):
	}
	ref, found, again, err := j.pass(ctx, path, intentID, since)
	return ref, found, complete && again, err
}

type jenkinsJob struct {
	Name string        `json:"name"`
	Jobs *[]jenkinsJob `json:"jobs"`
}

// visibleJobs lists the full names of every job the credential can see. truncated says that a
// folder was deeper than the tree that was read.
func visibleJobs(prefix string, jobs []jenkinsJob, depth int) (names []string, truncated bool) {
	for _, jb := range jobs {
		full := prefix + jb.Name
		if jb.Jobs == nil {
			names = append(names, full)
			continue
		}
		if depth <= 1 {
			truncated = true
			continue
		}
		sub, t := visibleJobs(full+"/", *jb.Jobs, depth-1)
		names, truncated = append(names, sub...), truncated || t
	}
	return names, truncated
}

// CheckCredential implements Builder for Jenkins. Jenkins has no call that lists "the jobs
// this user may build", so the check uses what it can ask: the jobs the credential can SEE.
// Seeing is the wider right, so a credential that sees only allow-listed jobs can start only
// those. A credential that sees more fails the check, even if it could not build them: the
// check is on the safe side.
func (j *Jenkins) CheckCredential(ctx context.Context, allowed []string) error {
	var who struct {
		Name          string `json:"name"`
		Anonymous     bool   `json:"anonymous"`
		Authenticated bool   `json:"authenticated"`
	}
	if err := j.getJSON(ctx, "/whoAmI/api/json", &who); err != nil {
		return fmt.Errorf("the credential check could not be run: %w", err)
	}
	if who.Anonymous || !who.Authenticated {
		return errors.New("the credential check failed: jenkins does not know this user and token")
	}
	tree := "jobs[name]"
	for i := 1; i < folderDepth; i++ {
		tree = "jobs[name," + tree + "]"
	}
	var root struct {
		Jobs []jenkinsJob `json:"jobs"`
	}
	if err := j.getJSON(ctx, "/api/json?tree="+url.QueryEscape(tree), &root); err != nil {
		return fmt.Errorf("the credential check could not be run: %w", err)
	}
	names, truncated := visibleJobs("", root.Jobs, folderDepth)
	if truncated {
		return fmt.Errorf("the credential check could not be run: folders are nested deeper than %d levels", folderDepth)
	}
	want := map[string]bool{}
	for _, a := range allowed {
		want[a] = true
	}
	seen := map[string]bool{}
	var outside []string
	for _, n := range names {
		seen[n] = true
		if !want[n] {
			outside = append(outside, n)
		}
	}
	for _, a := range allowed {
		if !seen[a] {
			return fmt.Errorf("the credential check failed: the allow-listed job %q is not visible to this credential", a)
		}
	}
	if len(outside) > 0 {
		sort.Strings(outside)
		return fmt.Errorf("%w: %d job(s), the first is %q", ErrBroadCredential, len(outside), outside[0])
	}
	return nil
}

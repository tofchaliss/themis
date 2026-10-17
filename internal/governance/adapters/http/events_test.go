package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// fakeEvents is the feed's store port with a fixed table of seqs, so paging can be asserted
// against what the store was asked for.
type fakeEvents struct {
	seqs      []int64
	lastAfter int64
	lastLimit int
	err       error
	badBody   bool
}

func (f *fakeEvents) ListReleaseEvaluatedEvents(_ context.Context, after int64, limit int) ([]app.ReleaseEvaluatedEvent, error) {
	f.lastAfter, f.lastLimit = after, limit
	if f.err != nil {
		return nil, f.err
	}
	var out []app.ReleaseEvaluatedEvent
	for _, s := range f.seqs {
		if s > after && len(out) < limit {
			body := json.RawMessage(`{"release_id":"rel-1","cause":"new_sbom","severity_counts":{"critical":1}}`)
			if f.badBody {
				body = json.RawMessage(`[1,2]`)
			}
			out = append(out, app.ReleaseEvaluatedEvent{Seq: s, EventID: "ev-" + string(rune('a'+s)), Name: app.EventReleaseEvaluated,
				OccurredAt: time.Unix(1_700_000_000, 0).UTC(), Body: body})
		}
	}
	return out, nil
}

// fakeKeys is an auth key store with one read key and one admin key, compared by plain
// equality so no bcrypt is needed.
type fakeKeys struct{}

func (fakeKeys) ActiveKeys(context.Context) ([]auth.APIKey, error) {
	return []auth.APIKey{
		{ID: "k-read", Name: "poller", KeyHash: "read-token", Scopes: []string{auth.ScopeRead}},
		{ID: "k-admin", Name: "ci", KeyHash: "admin-token", Scopes: []string{auth.ScopeAdmin}},
		{ID: "k-cb", Name: "jenkins", KeyHash: "cb-token", Scopes: []string{auth.ScopeDeliveryCallback}},
	}, nil
}

func eventsServer(t *testing.T, feed app.ReleaseEvaluatedEventReader) *httptest.Server {
	t.Helper()
	repo := newRepo()
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	if feed != nil {
		read = read.WithReleaseEvaluatedEvents(feed)
	}
	authn := auth.Authenticator{Keys: fakeKeys{}, Compare: func(hash, raw []byte) error {
		if string(hash) != string(raw) {
			return errors.New("mismatch")
		}
		return nil
	}}
	// The production chain: RequireAPIKey, then the method-based write floor (reads pass for
	// any authenticated principal — the `read` floor).
	srv := httptest.NewServer(authn.RequireAPIKey(auth.RequireWriteScope(govhttp.NewHandler(write, read).Router())))
	t.Cleanup(srv.Close)
	return srv
}

func getWithKey(t *testing.T, url, key string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if key != "" {
		req.Header.Set(auth.APIKeyHeader, key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [8192]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}

// N-M2d: the cursor read — auth matrix (no key 401, a read key is enough, admin too, the
// callback class may read as well since the floor is method-based), paging bounds (after is
// strict, next is the last seq or the caller's cursor), the clamped limit, and the empty page.
func TestReleaseEvaluatedEventsCursorRead_AfterLimit_AuthMatrix(t *testing.T) {
	feed := &fakeEvents{seqs: []int64{1, 2, 3, 4, 5}}
	srv := eventsServer(t, feed)
	path := srv.URL + "/events/release-evaluated"

	for _, tc := range []struct {
		key  string
		want int
	}{{"", http.StatusUnauthorized}, {"bogus", http.StatusUnauthorized}, {"read-token", http.StatusOK},
		{"admin-token", http.StatusOK}, {"cb-token", http.StatusOK}} {
		if s, body := getWithKey(t, path, tc.key); s != tc.want {
			t.Errorf("key %q: %d %s, want %d", tc.key, s, body, tc.want)
		}
	}

	type page struct {
		Items []struct {
			Seq        int64          `json:"seq"`
			EventID    string         `json:"event_id"`
			Name       string         `json:"name"`
			OccurredAt time.Time      `json:"occurred_at"`
			Body       map[string]any `json:"body"`
		} `json:"items"`
		Next int64 `json:"next"`
	}
	read := func(q string) page {
		t.Helper()
		s, body := getWithKey(t, path+q, "read-token")
		if s != http.StatusOK {
			t.Fatalf("%s: %d %s", q, s, body)
		}
		var p page
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("%s: %v in %s", q, err, body)
		}
		return p
	}

	// Defaults: from the start, default limit.
	p := read("")
	if len(p.Items) != 5 || p.Next != 5 || feed.lastAfter != 0 || feed.lastLimit != app.ReleaseEvaluatedEventsDefaultLimit {
		t.Errorf("default page = %+v (store asked after=%d limit=%d)", p, feed.lastAfter, feed.lastLimit)
	}
	if it := p.Items[0]; it.Seq != 1 || it.EventID != "ev-b" || it.Name != app.EventReleaseEvaluated ||
		it.Body["cause"] != "new_sbom" || it.OccurredAt.Unix() != 1_700_000_000 {
		t.Errorf("item = %+v", it)
	}
	// Strict cursor + page size: after=2 limit=2 → 3,4 and next=4.
	p = read("?after=2&limit=2")
	if len(p.Items) != 2 || p.Items[0].Seq != 3 || p.Items[1].Seq != 4 || p.Next != 4 {
		t.Errorf("after=2 limit=2 → %+v", p)
	}
	// Clamped, not refused.
	if p = read("?limit=9999"); feed.lastLimit != app.ReleaseEvaluatedEventsMaxLimit || len(p.Items) != 5 {
		t.Errorf("limit=9999 → store limit %d, page %+v", feed.lastLimit, p)
	}
	// Empty page keeps the caller's cursor.
	if p = read("?after=5"); len(p.Items) != 0 || p.Next != 5 {
		t.Errorf("after=5 → %+v, want no items and next=5", p)
	}
	// A malformed query param is the generated binder's 400.
	if s, _ := getWithKey(t, path+"?after=x", "read-token"); s != http.StatusBadRequest {
		t.Errorf("after=x → %d, want 400", s)
	}
}

// Failure shapes: a store error is a 500, an unwired feed is a 503 (never an empty page),
// and a stored body that is not an object is reported, not silently emptied.
func TestReleaseEvaluatedEventsCursorRead_Failures(t *testing.T) {
	feed := &fakeEvents{seqs: []int64{1}, err: errors.New("db down")}
	if s, body := getWithKey(t, eventsServer(t, feed).URL+"/events/release-evaluated", "read-token"); s != http.StatusInternalServerError || !strings.Contains(string(body), "db down") {
		t.Errorf("store error → %d %s", s, body)
	}
	if s, body := getWithKey(t, eventsServer(t, nil).URL+"/events/release-evaluated", "read-token"); s != http.StatusServiceUnavailable || !strings.Contains(string(body), "not available") {
		t.Errorf("unwired → %d %s", s, body)
	}
	bad := &fakeEvents{seqs: []int64{1}, badBody: true}
	if s, body := getWithKey(t, eventsServer(t, bad).URL+"/events/release-evaluated", "read-token"); s != http.StatusInternalServerError || !strings.Contains(string(body), "not a JSON object") {
		t.Errorf("bad body → %d %s", s, body)
	}
}

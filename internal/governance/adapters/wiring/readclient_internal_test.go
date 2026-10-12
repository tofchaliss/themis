package wiring

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The three Governance read seams must carry THEMIS_API_KEY, or an auth-on estate answers 401
// and the release-evaluation worker never publishes (N-M2b).
func TestReadClient_SendsAPIKeyOnlyWhenSet(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("X-API-Key"))
	}))
	defer srv.Close()

	for _, key := range []string{" read-key\n", ""} {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := readClient(key).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if req.Header.Get("X-API-Key") != "" {
			t.Error("the caller's request was modified")
		}
	}
	if len(got) != 2 || got[0] != "read-key" || got[1] != "" {
		t.Fatalf("X-API-Key sent = %q, want [read-key, \"\"] (trimmed key, then none)", got)
	}
}

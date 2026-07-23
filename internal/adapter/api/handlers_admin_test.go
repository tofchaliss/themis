package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/domain"
)

type fakeFeedSyncer struct {
	feeds map[string]error
}

func (f fakeFeedSyncer) SyncFeed(_ context.Context, feed string) error {
	err, ok := f.feeds[feed]
	if !ok {
		return domain.ErrUnknownFeed
	}
	return err
}

func (f fakeFeedSyncer) Feeds() []string {
	names := make([]string, 0, len(f.feeds))
	for k := range f.feeds {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func postFeedSync(t *testing.T, handler *api.Handler, keys domain.APIKeyRepository, feed string) int {
	t.Helper()
	r := mountTestAPI(handler, keys)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/feeds/"+feed+"/sync", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func TestTriggerFeedSync(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{FeedSyncer: fakeFeedSyncer{feeds: map[string]error{"epsskev": nil}}})
	if code := postFeedSync(t, handler, adminKeyRepo(t), "epsskev"); code != http.StatusOK {
		t.Fatalf("success status=%d", code)
	}
	if code := postFeedSync(t, handler, adminKeyRepo(t), "nope"); code != http.StatusNotFound {
		t.Fatalf("unknown feed status=%d, want 404", code)
	}
}

func TestTriggerFeedSyncError(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{FeedSyncer: fakeFeedSyncer{feeds: map[string]error{"epsskev": errors.New("feed down")}}})
	if code := postFeedSync(t, handler, adminKeyRepo(t), "epsskev"); code != http.StatusInternalServerError {
		t.Fatalf("sync error status=%d, want 500", code)
	}
}

func TestTriggerFeedSyncForbidden(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{FeedSyncer: fakeFeedSyncer{}})
	// A product-scoped (non-admin) key must be rejected.
	if code := postFeedSync(t, handler, productKeyRepo(t, "11111111-1111-4111-8111-111111111111"), "epsskev"); code != http.StatusForbidden {
		t.Fatalf("non-admin status=%d, want 403", code)
	}
}

func TestTriggerFeedSyncNilDep(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{})
	if code := postFeedSync(t, handler, adminKeyRepo(t), "epsskev"); code != http.StatusInternalServerError {
		t.Fatalf("nil syncer status=%d, want 500", code)
	}
}

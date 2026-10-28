package delivery_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/app"
)

// The format is per audience, read beside the URL, and refused at configure time when it is
// not in the closed set or names an audience with no target — a typo fails the start, not a send.
func TestWebhookFormats_ConfigAndRefusals(t *testing.T) {
	t.Setenv("THEMIS_COMMUNICATION_WEBHOOK_TARGETS", "slack-sec=https://hooks.example/a;teams-sec=https://prod.example/workflows/x")
	t.Setenv("THEMIS_COMMUNICATION_WEBHOOK_FORMATS", "teams-sec=teams")
	cfg := delivery.ConfigFromEnv().Webhook
	if cfg.Formats["teams-sec"] != delivery.WebhookFormatTeams {
		t.Fatalf("formats = %v", cfg.Formats)
	}
	line := cfg.String()
	if !strings.Contains(line, "teams-sec->prod.example(format=teams,") || !strings.Contains(line, "slack-sec->hooks.example(format=json,") {
		t.Fatalf("startup line omits the format: %s", line)
	}
	if _, err := delivery.NewRealWebhookDeliverer(cfg, nil, nil); err != nil {
		t.Fatalf("valid formats refused: %v", err)
	}
	for name, formats := range map[string]map[string]string{
		"unknown format":   {"teams-sec": "msteams"},
		"audience missing": {"nobody": "teams"},
	} {
		bad := cfg
		bad.Formats = formats
		if _, err := delivery.NewRealWebhookDeliverer(bad, nil, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A teams audience gets the Adaptive Card message, built from the stored Themis document and
// nothing else; the signature covers the bytes actually sent; a json audience is untouched.
func TestRealWebhookDeliverer_TeamsShapesTheBody(t *testing.T) {
	var gotBody, gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotSig = string(b), r.Header.Get(delivery.SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := delivery.WebhookConfig{
		Targets: map[string]string{"teams-sec": srv.URL + "/hook", "slack-sec": srv.URL + "/hook"},
		Formats: map[string]string{"teams-sec": delivery.WebhookFormatTeams},
		Secrets: map[string]string{"teams-sec": "k"},
	}
	d, err := delivery.NewRealWebhookDeliverer(cfg, &memHealth{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"event":"release_evaluated","product":"MRF","project":"MRFC","release":"1.2.3","release_id":"rel-1","summary":"Themis evaluated MRF / MRFC v1.2.3: Critical 1, High 2, Medium 0, Low 0.","link":"https://themis.example/#/release/rel-1","text":"x"}`
	in := app.Intent{ID: "int-t", Type: app.IntentWebhook, Destination: "teams-sec",
		Snapshot:     map[string]string{app.SnapshotWebhookEvent: app.WebhookReleaseEvaluated},
		PayloadBytes: app.BuildPayload("summary", []byte(doc))}
	if _, err := d.DeliverIntent(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	if gotSig != delivery.Sign("k", []byte(gotBody)) {
		t.Error("the signature does not cover the bytes sent")
	}
	var msg struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type    string           `json:"type"`
				Version string           `json:"version"`
				Body    []map[string]any `json:"body"`
				Actions []map[string]any `json:"actions"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(gotBody), &msg); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, gotBody)
	}
	if msg.Type != "message" || len(msg.Attachments) != 1 || msg.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("not a Teams card message: %s", gotBody)
	}
	card := msg.Attachments[0].Content
	if card.Type != "AdaptiveCard" || card.Version != "1.4" || len(card.Body) != 3 {
		t.Fatalf("card = %+v", card)
	}
	if card.Body[0]["text"] != "Themis: Release evaluated" || !strings.HasPrefix(card.Body[1]["text"].(string), "Themis evaluated MRF") {
		t.Errorf("title/summary = %v / %v", card.Body[0]["text"], card.Body[1]["text"])
	}
	facts := card.Body[2]["facts"].([]any)
	if len(facts) != 4 || facts[0].(map[string]any)["value"] != "MRF" {
		t.Errorf("facts = %v", facts)
	}
	if len(card.Actions) != 1 || card.Actions[0]["url"] != "https://themis.example/#/release/rel-1" {
		t.Errorf("actions = %v", card.Actions)
	}

	// The json audience still gets the document as stored.
	in.Destination = "slack-sec"
	if _, err := d.DeliverIntent(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	if gotBody != doc {
		t.Errorf("json audience body changed:\n%s", gotBody)
	}

	// No link, unknown event: no button, the kind itself as the title; a body that is not a
	// Themis document is refused, not guessed at.
	in.Destination = "teams-sec"
	in.PayloadBytes = app.BuildPayload("s", []byte(`{"event":"custom_thing","summary":"s","text":"s"}`))
	if _, err := d.DeliverIntent(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, `"Themis: custom_thing"`) || strings.Contains(gotBody, "Action.OpenUrl") || strings.Contains(gotBody, "FactSet") {
		t.Errorf("minimal card wrong: %s", gotBody)
	}
	gotBody = ""
	in.PayloadBytes = []byte("not a document")
	if _, err := d.DeliverIntent(t.Context(), in); err == nil || gotBody != "" {
		t.Errorf("a non-document was sent to teams: err=%v body=%q", err, gotBody)
	}
}

package notify

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// secretToken draws a non-whitespace token that is not the redaction marker, so
// "leak" checks are unambiguous.
func secretToken(t *rapid.T) string {
	s := rapid.StringMatching(`[A-Za-z0-9!#$%^&()_+=-]{6,24}`).Draw(t, "secret")
	if strings.Contains(s, "*") || s == "" {
		s = "S" + s
	}
	return s
}

func TestRedactLogMessageNoLeakProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		keyword := rapid.SampledFrom([]string{"password", "passwd"}).Draw(t, "keyword")
		secret := secretToken(t)
		gap := strings.Repeat(" ", rapid.IntRange(1, 3).Draw(t, "gap"))
		msg := keyword + gap + secret

		out := redactLogMessage(msg)
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked: in=%q out=%q secret=%q", msg, out, secret)
		}
	})
}

func TestRedactLogMessageIdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		keyword := rapid.SampledFrom([]string{"password", "passwd", "authToken="}).Draw(t, "keyword")
		secret := secretToken(t)
		prefix := rapid.StringMatching(`[a-z ]{0,12}`).Draw(t, "prefix")
		msg := prefix + keyword + " " + secret + " https://h.example/webhook/" + secret

		once := redactLogMessage(msg)
		twice := redactLogMessage(once)
		if once != twice {
			t.Fatalf("not idempotent:\nonce=%q\ntwice=%q", once, twice)
		}
	})
}

func TestRedactURLNoLeakProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := secretToken(t)
		url := "https://host.example/webhook/" + secret
		out := redactURL(url)
		if strings.Contains(out, secret) {
			t.Fatalf("webhook secret leaked: url=%q out=%q secret=%q", url, out, secret)
		}

		// Non-webhook, non-empty URLs collapse to a fixed marker.
		other := "https://host.example/" + secret
		if got := redactURL(other); strings.Contains(got, secret) {
			t.Fatalf("non-webhook secret leaked: url=%q out=%q", other, got)
		}

		if redactURL("") != "" {
			t.Fatalf("empty url should stay empty")
		}
	})
}

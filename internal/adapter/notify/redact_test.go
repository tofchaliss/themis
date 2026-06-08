package notify

import (
	"strings"
	"testing"
)

func TestRedactLogMessage(t *testing.T) {
	msg := redactLogMessage("password=secret123 https://outlook.office.com/webhook/abc/def")
	if strings.Contains(msg, "secret123") || strings.Contains(msg, "abc/def") {
		t.Fatalf("msg=%q", msg)
	}
}

func TestRedactURL(t *testing.T) {
	if got := redactURL("https://outlook.office.com/webhook/abc/def"); got == "" || strings.Contains(got, "abc") {
		t.Fatalf("got=%q", got)
	}
	if redactURL("") != "" {
		t.Fatal("empty url")
	}
	if !strings.Contains(redactURL("https://example.com/hooks"), "****") {
		t.Fatal("fallback redaction")
	}
}

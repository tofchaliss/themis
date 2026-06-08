package notify

import (
	"regexp"
	"strings"
)

var (
	smtpPasswordPattern = regexp.MustCompile(`(?i)(password|passwd|auth[^=\s]*=)\s*[^\s]+`)
	webhookURLPattern   = regexp.MustCompile(`https?://[^\s]+webhook[^\s]*`)
)

func redactLogMessage(msg string) string {
	msg = smtpPasswordPattern.ReplaceAllString(msg, "$1=****")
	msg = webhookURLPattern.ReplaceAllString(msg, "https://****/webhook/****")
	return msg
}

func redactURL(url string) string {
	if url == "" {
		return ""
	}
	if idx := strings.Index(url, "/webhook/"); idx >= 0 {
		return url[:idx+9] + "****"
	}
	return "https://****"
}

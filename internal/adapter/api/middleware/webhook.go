package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// webhookToleranceSeconds bounds the accepted clock skew between the signer's
// timestamp and the server, limiting how long a captured request can be replayed.
const webhookToleranceSeconds = 300

// verifyWebhook validates a replay-protected webhook request: it requires an
// X-Themis-Timestamp within tolerance of now and an X-Themis-Signature over
// "<unix_seconds>.<body>".
func verifyWebhook(secret string, r *http.Request, now time.Time) bool {
	tsHeader := strings.TrimSpace(r.Header.Get("X-Themis-Timestamp"))
	if tsHeader == "" {
		return false
	}
	tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	skew := now.Unix() - tsUnix
	if skew < 0 {
		skew = -skew
	}
	if skew > webhookToleranceSeconds {
		return false
	}

	signature := strings.TrimSpace(r.Header.Get("X-Themis-Signature"))
	if signature == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	expected := signWebhook(secret, tsUnix, body)
	return hmac.Equal([]byte(strings.ToLower(signature)), []byte(strings.ToLower(expected)))
}

// SignWebhook computes the replay-protected webhook signature over
// "<unix_seconds>.<body>". Callers must send the same unixSeconds value in the
// X-Themis-Timestamp header alongside the signature in X-Themis-Signature.
func SignWebhook(secret string, unixSeconds int64, body []byte) string {
	return signWebhook(secret, unixSeconds, body)
}

func signWebhook(secret string, unixSeconds int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(unixSeconds, 10)))
	_, _ = mac.Write([]byte{'.'})
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

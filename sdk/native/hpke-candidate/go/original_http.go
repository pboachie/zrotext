package hpke

// This transport returns UNTRUSTED wire JSON. It does not authenticate grant
// proofs, persist accepted history, or authorize plaintext release.
import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const originalMaxResponse = 524288

type OriginalHTTPError struct{ Unknown bool }

func (e OriginalHTTPError) Error() string {
	if e.Unknown {
		return "original reply outcome unknown"
	}
	return "original reply unavailable"
}

// OriginalWire is untrusted, including any purported proof or consumption ID.
type OriginalWire struct{ JSON json.RawMessage }
type OriginalHTTPRequest struct {
	Method                  string
	AcceptedManifestVersion uint64
	EventID                 string
	ConsumptionID           string
	Limit                   uint8
	CursorAcceptedAt        uint64
	CursorEventID           string
	RequestID               string
	ActiveRequestID         string
}

func originalUUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func originalCredential(s string) bool {
	if !strings.HasPrefix(s, "ztr_") || len(s) != 47 {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(s[4:])
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s[4:]
}
func (r OriginalHTTPRequest) body() ([]byte, error) {
	bad := OriginalHTTPError{}
	if r.AcceptedManifestVersion == 0 || r.AcceptedManifestVersion > 9007199254740991 {
		return nil, bad
	}
	b := map[string]any{"v": 1, "method": r.Method, "accepted_manifest_version": r.AcceptedManifestVersion}
	switch r.Method {
	case "current":
	case "read":
		if !originalUUID(r.EventID) {
			return nil, bad
		}
		b["event_id"] = r.EventID
	case "status":
		if !originalUUID(r.ConsumptionID) {
			return nil, bad
		}
		b["consumption_id"] = r.ConsumptionID
	case "page":
		if r.Limit < 1 || r.Limit > 32 {
			return nil, bad
		}
		b["limit"] = r.Limit
		b["cursor"] = nil
		if r.CursorEventID != "" || r.CursorAcceptedAt != 0 {
			if !originalUUID(r.CursorEventID) || r.CursorAcceptedAt == 0 || r.CursorAcceptedAt > 9007199254740991 {
				return nil, bad
			}
			b["cursor"] = map[string]any{"event_id": r.CursorEventID, "accepted_at_ms": r.CursorAcceptedAt}
		}
	case "consume":
		if !originalUUID(r.EventID) || !originalUUID(r.RequestID) || (r.ActiveRequestID != "" && !originalUUID(r.ActiveRequestID)) {
			return nil, bad
		}
		b["event_id"] = r.EventID
		b["request_id"] = r.RequestID
		b["descriptor"] = nil
		b["active_request_id"] = nil
		if r.ActiveRequestID != "" {
			b["active_request_id"] = r.ActiveRequestID
		}
	default:
		return nil, bad
	}
	if r.Method != "read" && r.Method != "consume" && r.EventID != "" || r.Method != "status" && r.ConsumptionID != "" || r.Method != "page" && (r.Limit != 0 || r.CursorAcceptedAt != 0 || r.CursorEventID != "") || r.Method != "consume" && (r.RequestID != "" || r.ActiveRequestID != "") {
		return nil, bad
	}
	encoded, e := json.Marshal(b)
	if e != nil || len(encoded) > 4096 {
		return nil, bad
	}
	return encoded, nil
}

// OriginalHTTP owns no credentials. The caller supplies a fresh original grant
// for each request. Additional roots must be independently trusted CA PEM, never
// server-provided certificates. Nil roots use the platform trust store.
type OriginalHTTP struct {
	endpoint string
	client   *http.Client
	timeout  time.Duration
}

func NewOriginalHTTP(origin string, timeout time.Duration, additionalRootsPEM []byte) (*OriginalHTTP, error) {
	bad := OriginalHTTPError{}
	if timeout < time.Millisecond || timeout > 10*time.Second || strings.ContainsRune(origin, '\\') {
		return nil, bad
	}
	for _, c := range origin {
		if c <= 32 || c >= 127 {
			return nil, bad
		}
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(origin, "#") {
		return nil, bad
	}
	var roots *x509.CertPool
	if len(additionalRootsPEM) > 0 {
		roots, e = x509.SystemCertPool()
		if e != nil {
			return nil, bad
		}
		if !roots.AppendCertsFromPEM(additionalRootsPEM) {
			return nil, bad
		}
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &OriginalHTTP{endpoint: strings.TrimSuffix(origin, "/") + "/v1/reply-events", client: client, timeout: timeout}, nil
}
func (c *OriginalHTTP) Exchange(ctx context.Context, credential string, request OriginalHTTPRequest) (OriginalWire, error) {
	fail := func(unknown bool) (OriginalWire, error) { return OriginalWire{}, OriginalHTTPError{Unknown: unknown} }
	if c == nil || ctx == nil || !originalCredential(credential) {
		return fail(false)
	}
	body, e := request.body()
	if e != nil {
		return fail(false)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return fail(false)
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if e != nil {
		return fail(false)
	}
	req.GetBody = nil // no replayable body, including transport-level replay.
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	unknown := request.Method == "consume"
	response, e := c.client.Do(req)
	if e != nil {
		return fail(unknown)
	}
	defer response.Body.Close()
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > originalMaxResponse {
		return fail(unknown)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, originalMaxResponse+1))
	if e != nil || len(raw) > originalMaxResponse || !utf8.Valid(raw) || ctx.Err() != nil {
		return fail(unknown)
	}
	top := map[string]json.RawMessage{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, e := decoder.Token()
	if e != nil || token != json.Delim('{') {
		return fail(unknown)
	}
	for decoder.More() {
		token, e = decoder.Token()
		key, ok := token.(string)
		if e != nil || !ok || top[key] != nil {
			return fail(unknown)
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return fail(unknown)
		}
		top[key] = value
	}
	if token, e = decoder.Token(); e != nil || token != json.Delim('}') || len(top) != 2 {
		return fail(unknown)
	}
	if _, e = decoder.Token(); e != io.EOF {
		return fail(unknown)
	}
	var kind string
	if json.Unmarshal(top["kind"], &kind) != nil || kind != request.Method {
		return fail(unknown)
	}
	result, ok := top["result"]
	if !ok {
		return fail(unknown)
	}
	return OriginalWire{JSON: append(json.RawMessage(nil), result...)}, nil
}

var _ error = OriginalHTTPError{}

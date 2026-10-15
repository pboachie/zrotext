package hpke

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// WorkflowAction owns exact canonical binding bytes. A digest is not permission.
type WorkflowAction struct {
	canonical []byte
	fields    map[string]json.RawMessage
}

var actionNames = []string{"account_id", "action_id", "authority_generation", "commitment", "content_digest", "content_ref", "content_version", "expires_at", "line_id", "not_before", "purpose_id", "recipient_id", "revision", "routine_id", "timezone", "window_id"}

func ParseWorkflowAction(raw []byte) (*WorkflowAction, error) {
	bad := OriginalHTTPError{}
	if len(raw) > 4096 {
		return nil, bad
	}
	fields, e := replyObject(raw, actionNames...)
	if e != nil {
		return nil, bad
	}
	values := map[string]any{}
	for _, name := range actionNames {
		switch name {
		case "authority_generation", "content_version", "expires_at", "not_before", "revision":
			number, e := strconv.ParseFloat(string(fields[name]), 64)
			n := uint64(0)
			if e == nil && !math.IsNaN(number) && !math.IsInf(number, 0) && number >= 0 && number <= 9007199254740991 && math.Trunc(number) == number {
				n = uint64(number)
			} else {
				return nil, bad
			}
			if e != nil || n > 9007199254740991 || (n == 0 && name != "not_before") {
				return nil, bad
			}
			values[name] = n
		default:
			s, e := replyString(fields[name])
			if e != nil || len(s) < 1 || len(s) > 128 {
				return nil, bad
			}
			for _, b := range []byte(s) {
				if b > 127 {
					return nil, bad
				}
			}
			values[name] = s
		}
	}
	digest := values["content_digest"].(string)
	if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" || values["not_before"].(uint64) >= values["expires_at"].(uint64) {
		return nil, bad
	}
	if values["commitment"] != "informational" && values["commitment"] != "sensitive" {
		return nil, bad
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(values) != nil {
		return nil, bad
	}
	canonical := bytes.ReplaceAll(bytes.TrimSuffix(out.Bytes(), []byte("\n")), []byte{127}, []byte(`\u007f`))
	// Own all fields by reparsing the owned canonical snapshot.
	owned, e := replyObject(canonical, actionNames...)
	if e != nil {
		return nil, bad
	}
	return &WorkflowAction{append([]byte(nil), canonical...), owned}, nil
}
func (a *WorkflowAction) Canonical() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.canonical...)
}
func (a *WorkflowAction) Digest() string {
	if a == nil {
		return ""
	}
	d := sha256.Sum256(a.canonical)
	return hex.EncodeToString(d[:])
}
func (a *WorkflowAction) production() bool {
	if a == nil {
		return false
	}
	for _, n := range []string{"account_id", "action_id", "line_id", "recipient_id", "purpose_id", "content_ref", "routine_id"} {
		s, e := replyString(a.fields[n])
		if e != nil || !originalUUID(s) {
			return false
		}
	}
	revision, e := replyInteger(a.fields["revision"])
	return e == nil && revision <= 128
}

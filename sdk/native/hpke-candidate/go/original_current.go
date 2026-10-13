package hpke

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
)

// VerifiedOriginalCurrent binds the TLS grant proof to independently selected
// scope and signed history after durable clock/history CAS. It is a snapshot,
// not permission to omit a fresh proof before/after plaintext or effects.
type VerifiedOriginalCurrent struct{ authority OriginalAuthority }

func (v *VerifiedOriginalCurrent) Authority() OriginalAuthority { return v.authority }

// OriginalCurrentClient serializes current-proof advancement. Reopen after a
// failed/uncertain checkpoint update or another writer's revision change.
type OriginalCurrentClient struct {
	mu             sync.Mutex
	transport      *OriginalHTTP
	checkpoint     *OriginalReplyCheckpoint
	scope          OriginalScope
	root           *RootTrust
	revision, last uint64
	failed         bool
}

func NewOriginalCurrentClient(transport *OriginalHTTP, checkpoint *OriginalReplyCheckpoint, pin, fingerprint []byte, scope OriginalScope, now uint64) (*OriginalCurrentClient, error) {
	bad := OriginalHTTPError{}
	if transport == nil || checkpoint == nil || !scope.valid() || !replyPositive(now) {
		return nil, bad
	}
	root, e := EnrollRoot(pin, fingerprint)
	if e != nil {
		return nil, bad
	}
	snap, e := checkpoint.Snapshot(scope, now)
	if e != nil || len(snap.History) == 0 {
		return nil, bad
	}
	if _, e = VerifyManifest(snap.History[0].raw, root, nil, 2, snap.History[0].comparison); e != nil {
		return nil, bad
	}
	return &OriginalCurrentClient{transport: transport, checkpoint: checkpoint, scope: scope, root: root, revision: snap.Revision, last: now}, nil
}
func replyPositive(v uint64) bool { return v > 0 && v <= 9007199254740991 }
func replyObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	bad := OriginalHTTPError{}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, bad
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, e = d.Token()
		key, ok := token.(string)
		if e != nil || !ok || !allowed[key] || out[key] != nil {
			return nil, bad
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, bad
		}
		out[key] = value
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') || len(out) != len(fields) {
		return nil, bad
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, bad
	}
	return out, nil
}
func replyInteger(raw json.RawMessage) (uint64, error) {
	n, e := strconv.ParseUint(string(raw), 10, 64)
	if e != nil || !replyPositive(n) {
		return 0, OriginalHTTPError{}
	}
	return n, nil
}
func replyString(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || len(raw) == 0 || raw[0] != '"' {
		return "", OriginalHTTPError{}
	}
	return s, nil
}
func replyUUID(raw json.RawMessage, expected [16]byte) bool {
	s, e := replyString(raw)
	if e != nil || !originalUUID(s) {
		return false
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil && bytes.Equal(b, expected[:])
}
func replyHex(raw json.RawMessage, expected [32]byte) bool {
	s, e := replyString(raw)
	return e == nil && s == hex.EncodeToString(expected[:])
}

// Current performs one request and installs only fully verified, durably fenced
// current authority. clock is independently trusted and may be sampled repeatedly.
func (c *OriginalCurrentClient) Current(ctx context.Context, grant string, clock func() uint64) (*VerifiedOriginalCurrent, error) {
	bad := OriginalHTTPError{}
	if c == nil || clock == nil || !c.mu.TryLock() {
		return nil, bad
	}
	defer c.mu.Unlock()
	if c.failed {
		return nil, bad
	}
	sample := func() (uint64, error) {
		n := clock()
		if !replyPositive(n) || n < c.last {
			return 0, bad
		}
		c.last = n
		return n, nil
	}
	now, e := sample()
	if e != nil {
		return nil, bad
	}
	saved, e := c.checkpoint.Snapshot(c.scope, now)
	if e != nil || saved.Revision != c.revision {
		c.failed = true
		return nil, bad
	}
	latest := saved.History[len(saved.History)-1]
	wire, e := c.transport.Exchange(ctx, grant, OriginalHTTPRequest{Method: "current", AcceptedManifestVersion: latest.version})
	if e != nil {
		return nil, bad
	}
	p, e := replyObject(wire.JSON, "account_id", "interval_id", "device_id", "line_id", "connector_id", "read_grant_id", "reader_id", "root_generation", "authority_revision", "expires_at_ms", "observed_at_ms", "current_manifest_version", "current_manifest_digest", "manifest_chain")
	if e != nil {
		return nil, bad
	}
	now, e = sample()
	if e != nil {
		return nil, bad
	}
	observed, e := replyInteger(p["observed_at_ms"])
	if e != nil {
		return nil, bad
	}
	expires, e := replyInteger(p["expires_at_ms"])
	if e != nil {
		return nil, bad
	}
	fresh := func(n uint64) bool { return n < expires && n <= observed+30000 && observed <= n+30000 }
	if !fresh(now) {
		return nil, bad
	}
	for field, expected := range map[string][16]byte{"account_id": c.scope.Account, "device_id": c.scope.Device, "line_id": c.scope.Line, "interval_id": c.scope.Interval, "connector_id": c.scope.Connector, "read_grant_id": c.scope.ReadGrant} {
		if !replyUUID(p[field], expected) {
			return nil, bad
		}
	}
	revision, e := replyInteger(p["authority_revision"])
	if e != nil || revision != 1 || !replyHex(p["reader_id"], c.scope.Reader) {
		return nil, bad
	}
	var chain []json.RawMessage
	if json.Unmarshal(p["manifest_chain"], &chain) != nil || len(chain) < 1 || len(chain) > 32 {
		return nil, bad
	}
	history := append([]*Manifest(nil), saved.History...)
	previous := latest
	for i, raw := range chain {
		entry, e := replyObject(raw, "version", "accepted_at_ms", "manifest_b64")
		if e != nil {
			return nil, bad
		}
		version, e := replyInteger(entry["version"])
		if e != nil {
			return nil, bad
		}
		at, e := replyInteger(entry["accepted_at_ms"])
		if e != nil || at > now+30000 {
			return nil, bad
		}
		want := previous.version + 1
		if i == 0 {
			want = latest.version
		}
		if version != want {
			return nil, bad
		}
		encoded, e := replyString(entry["manifest_b64"])
		if e != nil || len(encoded) > 13004 {
			return nil, bad
		}
		signed, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(signed) > 9751 || base64.StdEncoding.EncodeToString(signed) != encoded {
			return nil, bad
		}
		m, e := replyManifestAt(signed, c.root, previous, at)
		if e != nil || m.version != version || m.generation != latest.generation || m.root != latest.root {
			return nil, bad
		}
		if i == 0 {
			if m.digest != latest.digest {
				return nil, bad
			}
		} else {
			history = append(history, m)
		}
		previous = m
	}
	version, e := replyInteger(p["current_manifest_version"])
	if e != nil || version != previous.version {
		return nil, bad
	}
	generation, e := replyInteger(p["root_generation"])
	if e != nil || generation != latest.generation || !replyHex(p["current_manifest_digest"], previous.digest) || len(history) > 64 {
		return nil, bad
	}
	now, e = sample()
	if e != nil || !fresh(now) {
		return nil, bad
	}
	if _, e = replyManifestAt(previous.raw, c.root, previous, now); e != nil {
		return nil, bad
	}
	fence := func(m *Manifest, floor uint64) (uint64, error) {
		n, e := sample()
		if e != nil || n < floor || !fresh(n) {
			return 0, bad
		}
		if _, e = replyManifestAt(m.raw, c.root, m, n); e != nil {
			return 0, bad
		}
		return n, nil
	}
	// Any failure after entering persistence makes this instance stale. Reopening
	// recovers the committed revision without silently retrying or resetting trust.
	c.failed = true
	committed, e := c.checkpoint.Accept(c.scope, history, c.revision, now, fence)
	if e != nil {
		return nil, bad
	}
	after, e := sample()
	if e != nil || after < committed.Comparison || !fresh(after) {
		return nil, bad
	}
	current := committed.History[len(committed.History)-1]
	if _, e = replyManifestAt(current.raw, c.root, current, after); e != nil {
		return nil, bad
	}
	if after > committed.Comparison {
		committed, e = c.checkpoint.Accept(c.scope, committed.History, committed.Revision, after, fence)
		if e != nil {
			return nil, bad
		}
		current = committed.History[len(committed.History)-1]
	}
	c.revision = committed.Revision
	c.last = committed.Comparison
	c.failed = false
	return &VerifiedOriginalCurrent{authority: OriginalAuthority{Scope: c.scope, Revision: "1", Now: committed.Comparison, Expires: expires, Manifest: current}}, nil
}

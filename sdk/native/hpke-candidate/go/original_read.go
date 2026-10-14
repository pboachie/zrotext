package hpke

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// VerifiedOriginalRead is transient plaintext plus the exact ciphertext identity.
// It is not permission to consume an event or submit a workflow proposal.
type VerifiedOriginalRead struct {
	Plaintext               string
	Event                   [16]byte
	EnvelopeDigest          [32]byte
	AcceptedManifestVersion uint64
	Authority               OriginalAuthority
}

func replyBase64(raw json.RawMessage, maximum int) ([]byte, error) {
	s, e := replyString(raw)
	if e != nil || len(s) > ((maximum+2)/3)*4 {
		return nil, OriginalHTTPError{}
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > maximum || base64.StdEncoding.EncodeToString(b) != s {
		return nil, OriginalHTTPError{}
	}
	return b, nil
}
func replyUUIDText(v [16]byte) string {
	h := hex.EncodeToString(v[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ReadSoftware explicitly uses an exportable recipient scalar. baseline zero
// selects the oldest retained version within the service's 32-manifest window.
func (c *OriginalCurrentClient) ReadSoftware(ctx context.Context, grant string, event [16]byte, baseline uint64, scalar []byte, clock func() uint64) (*VerifiedOriginalRead, error) {
	owned := append([]byte(nil), scalar...)
	defer clear(owned)
	return c.read(ctx, grant, event, baseline, clock, func(p, e, i, a, t []byte) ([]byte, error) { return OpenSoftwareCEK(owned, p, e, i, a, t) })
}
func (c *OriginalCurrentClient) read(ctx context.Context, grant string, event [16]byte, baseline uint64, clock func() uint64, unwrap func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) (*VerifiedOriginalRead, error) {
	bad := OriginalHTTPError{}
	if c == nil || clock == nil || event == [16]byte{} || !c.mu.TryLock() {
		return nil, bad
	}
	defer c.mu.Unlock()
	if c.failed {
		return nil, bad
	}
	now := clock()
	if !replyPositive(now) || now < c.last {
		return nil, bad
	}
	c.last = now
	saved, e := c.checkpoint.Snapshot(c.scope, now)
	if e != nil || saved.Revision != c.revision {
		c.failed = true
		return nil, bad
	}
	latest := saved.History[len(saved.History)-1]
	var first *Manifest
	for _, m := range saved.History {
		if m.version <= latest.version && latest.version-m.version < 32 && (baseline == 0 || baseline == m.version) {
			first = m
			break
		}
	}
	if first == nil {
		return nil, bad
	}
	wire, e := c.transport.Exchange(ctx, grant, OriginalHTTPRequest{Method: "read", EventID: replyUUIDText(event), AcceptedManifestVersion: first.version})
	if e != nil {
		return nil, bad
	}
	r, e := replyObject(wire.JSON, "event_id", "accepted_at_ms", "envelope_b64", "historical_manifest_version", "statement_b64", "approval_signature_b64", "installation_signature_b64", "activation_manifest_version", "proof")
	if e != nil || !replyUUID(r["event_id"], event) {
		return nil, bad
	}
	initial, e := c.acceptProof(r["proof"], saved, first, clock)
	if e != nil {
		return nil, bad
	}
	snap, e := c.checkpoint.Snapshot(c.scope, c.last)
	if e != nil || snap.Revision != c.revision {
		c.failed = true
		return nil, bad
	}
	hv, e := replyInteger(r["historical_manifest_version"])
	if e != nil || hv < first.version {
		return nil, bad
	}
	av, e := replyInteger(r["activation_manifest_version"])
	if e != nil {
		return nil, bad
	}
	at, e := replyInteger(r["accepted_at_ms"])
	if e != nil || at > c.last+30000 {
		return nil, bad
	}
	var historical, activation *Manifest
	for _, m := range snap.History {
		if m.version == hv {
			historical = m
		}
		if m.version == av {
			activation = m
		}
	}
	if historical == nil || activation == nil {
		return nil, bad
	}
	activation, e = replyManifestAt(activation.raw, c.root, activation, at)
	if e != nil {
		return nil, bad
	}
	statement, e := replyBase64(r["statement_b64"], 1536)
	if e != nil {
		return nil, bad
	}
	approval, e := replyBase64(r["approval_signature_b64"], 64)
	if e != nil {
		return nil, bad
	}
	installation, e := replyBase64(r["installation_signature_b64"], 64)
	if e != nil {
		return nil, bad
	}
	selection, e := VerifyOriginalReplySelection02(statement, approval, installation, activation, at, c.scope)
	if e != nil {
		return nil, bad
	}
	envelope, e := replyBase64(r["envelope_b64"], 34082)
	if e != nil {
		return nil, bad
	}
	authority := initial.Authority()
	once := true
	current := func() (OriginalAuthority, error) {
		if once {
			once = false
			return authority, nil
		}
		v, e := c.currentLocked(ctx, grant, clock)
		if e != nil {
			return OriginalAuthority{}, e
		}
		authority = v.Authority()
		return authority, nil
	}
	plain, e := openOriginalReply02(envelope, event, historical, selection, c.scope, current, unwrap)
	if e != nil {
		return nil, bad
	}
	return &VerifiedOriginalRead{Plaintext: plain, Event: event, EnvelopeDigest: sha256.Sum256(envelope), AcceptedManifestVersion: first.version, Authority: authority}, nil
}

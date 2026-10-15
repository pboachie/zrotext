package hpke

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type OriginalReplyCursor struct {
	AcceptedAt uint64
	Event      [16]byte
}
type OriginalReplyEventMetadata struct {
	Event                                                                        [16]byte
	AcceptedAt, ObservedAt, HistoricalManifestVersion, ActivationManifestVersion uint64
	Disposition                                                                  string
	ActiveRequestIDs                                                             [][16]byte
}

// OriginalReplyPage is discovery metadata, never consumption or STOP authority.
type OriginalReplyPage struct {
	Events    []OriginalReplyEventMetadata
	Next      *OriginalReplyCursor
	Authority *VerifiedOriginalCurrent
}

func replyID(raw json.RawMessage) ([16]byte, error) {
	var id [16]byte
	s, e := replyString(raw)
	if e != nil || !originalUUID(s) {
		return id, OriginalHTTPError{}
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if e != nil {
		return id, OriginalHTTPError{}
	}
	copy(id[:], b)
	return id, nil
}
func replyCursorWire(raw json.RawMessage) (OriginalReplyCursor, error) {
	c := OriginalReplyCursor{}
	o, e := replyObject(raw, "accepted_at_ms", "event_id")
	if e != nil {
		return c, e
	}
	c.AcceptedAt, e = replyInteger(o["accepted_at_ms"])
	if e != nil {
		return c, e
	}
	c.Event, e = replyID(o["event_id"])
	return c, e
}
func cursorAfter(a, b OriginalReplyCursor) bool {
	return a.AcceptedAt > b.AcceptedAt || a.AcceptedAt == b.AcceptedAt && bytes.Compare(a.Event[:], b.Event[:]) > 0
}

// Page performs one request, verifies current signed history and durably advances
// its comparison before returning metadata. Cursor/limit failure sends nothing.
func (c *OriginalCurrentClient) Page(ctx context.Context, grant string, cursor *OriginalReplyCursor, limit uint8, clock func() uint64) (*OriginalReplyPage, error) {
	bad := OriginalHTTPError{}
	if c == nil || clock == nil || limit < 1 || limit > 32 {
		return nil, bad
	}
	after := OriginalReplyCursor{}
	if cursor != nil {
		after = *cursor
		if !replyPositive(after.AcceptedAt) || after.Event == [16]byte{} {
			return nil, bad
		}
	}
	if !c.mu.TryLock() {
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
	request := OriginalHTTPRequest{Method: "page", AcceptedManifestVersion: latest.version, Limit: limit}
	if cursor != nil {
		request.CursorAcceptedAt = after.AcceptedAt
		request.CursorEventID = replyUUIDText(after.Event)
	}
	wire, e := c.transport.Exchange(ctx, grant, request)
	if e != nil {
		return nil, bad
	}
	result, e := replyObject(wire.JSON, "events", "next", "proof")
	if e != nil {
		return nil, bad
	}
	var rows []json.RawMessage
	if len(result["events"]) == 0 || result["events"][0] != '[' || json.Unmarshal(result["events"], &rows) != nil || len(rows) > int(limit) {
		return nil, bad
	}
	out := &OriginalReplyPage{Events: make([]OriginalReplyEventMetadata, 0, len(rows))}
	ids := map[[16]byte]bool{}
	for _, raw := range rows {
		o, e := replyObject(raw, "event_id", "accepted_at_ms", "observed_at_ms", "historical_manifest_version", "activation_manifest_version", "disposition", "active_request_ids")
		if e != nil {
			return nil, bad
		}
		id, e := replyID(o["event_id"])
		if e != nil || ids[id] {
			return nil, bad
		}
		ids[id] = true
		v := OriginalReplyEventMetadata{Event: id}
		fields := []*uint64{&v.AcceptedAt, &v.ObservedAt, &v.HistoricalManifestVersion, &v.ActivationManifestVersion}
		for i, key := range []string{"accepted_at_ms", "observed_at_ms", "historical_manifest_version", "activation_manifest_version"} {
			*fields[i], e = replyInteger(o[key])
			if e != nil {
				return nil, bad
			}
		}
		current := OriginalReplyCursor{AcceptedAt: v.AcceptedAt, Event: id}
		if !cursorAfter(current, after) {
			return nil, bad
		}
		after = current
		v.Disposition, e = replyString(o["disposition"])
		if e != nil || (v.Disposition != "unassociated" && v.Disposition != "owner_review" && v.Disposition != "request_available") {
			return nil, bad
		}
		var requests []json.RawMessage
		if len(o["active_request_ids"]) == 0 || o["active_request_ids"][0] != '[' || json.Unmarshal(o["active_request_ids"], &requests) != nil || len(requests) > 8 {
			return nil, bad
		}
		unique := map[[16]byte]bool{}
		v.ActiveRequestIDs = make([][16]byte, 0, len(requests))
		for _, r := range requests {
			id, e := replyID(r)
			if e != nil || unique[id] {
				return nil, bad
			}
			unique[id] = true
			v.ActiveRequestIDs = append(v.ActiveRequestIDs, id)
		}
		out.Events = append(out.Events, v)
	}
	if !bytes.Equal(bytes.TrimSpace(result["next"]), []byte("null")) {
		next, e := replyCursorWire(result["next"])
		if e != nil || len(rows) != int(limit) || next != after {
			return nil, bad
		}
		out.Next = &next
	} else if len(rows) == int(limit) {
		return nil, bad
	}
	out.Authority, e = c.acceptProof(result["proof"], saved, latest, clock)
	if e != nil {
		return nil, bad
	}
	return out, nil
}

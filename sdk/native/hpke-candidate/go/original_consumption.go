package hpke

import (
	"bytes"
	"context"
	"encoding/json"
)

// OriginalOwnerReviewIntent is an immutable descriptor-null request. Persist its
// bytes before calling ConsumeOwnerReview and retain them across unknown outcomes.
type OriginalOwnerReviewIntent struct{ record [151]byte }

func (i *OriginalOwnerReviewIntent) Bytes() []byte {
	if i == nil {
		return nil
	}
	return append([]byte(nil), i.record[:]...)
}
func (c *OriginalCurrentClient) RestoreOwnerReviewIntent(raw []byte) (*OriginalOwnerReviewIntent, error) {
	bad := OriginalHTTPError{}
	if c == nil || c.root == nil || len(raw) != 151 || !bytes.Equal(raw[:5], []byte("ZTOR\x01")) {
		return nil, bad
	}
	scope, e := replyScopeHash(c.scope)
	if e != nil || !bytes.Equal(raw[5:70], c.root.enrolled[:]) || !bytes.Equal(raw[70:102], scope[:]) {
		return nil, bad
	}
	if bytes.Equal(raw[102:118], make([]byte, 16)) || bytes.Equal(raw[118:134], make([]byte, 16)) || raw[134] > 1 {
		return nil, bad
	}
	zero := bytes.Equal(raw[135:], make([]byte, 16))
	if (raw[134] == 0) != zero {
		return nil, bad
	}
	out := &OriginalOwnerReviewIntent{}
	copy(out.record[:], raw)
	return out, nil
}

// PrepareOwnerReview performs no network or persistence. The caller must durably
// save the returned bytes before attempting the effect; IDs are never generated.
func (c *OriginalCurrentClient) PrepareOwnerReview(event, request [16]byte, active *[16]byte) (*OriginalOwnerReviewIntent, error) {
	if c == nil || c.root == nil {
		return nil, OriginalHTTPError{}
	}
	var raw [151]byte
	copy(raw[:5], []byte("ZTOR\x01"))
	copy(raw[5:70], c.root.enrolled[:])
	scope, e := replyScopeHash(c.scope)
	if e != nil {
		return nil, OriginalHTTPError{}
	}
	copy(raw[70:102], scope[:])
	copy(raw[102:118], event[:])
	copy(raw[118:134], request[:])
	if active != nil {
		raw[134] = 1
		copy(raw[135:], active[:])
	}
	return c.RestoreOwnerReviewIntent(raw[:])
}

type OriginalOwnerReviewConsumption struct {
	Event, Consumption [16]byte
	ActiveRequest      *[16]byte
	Authority          *VerifiedOriginalCurrent
}

func ownerReviewResult(raw []byte, i *OriginalOwnerReviewIntent) (*OriginalOwnerReviewConsumption, error) {
	bad := OriginalHTTPError{}
	r, e := replyObject(raw, "event_id", "consumption_id", "disposition", "active_request_id", "action")
	if e != nil {
		return nil, bad
	}
	out := &OriginalOwnerReviewConsumption{}
	copy(out.Event[:], i.record[102:118])
	copy(out.Consumption[:], i.record[118:134])
	if !replyUUID(r["event_id"], out.Event) || !replyUUID(r["consumption_id"], out.Consumption) {
		return nil, bad
	}
	disposition, e := replyString(r["disposition"])
	if e != nil || disposition != "owner_review" || !bytes.Equal(bytes.TrimSpace(r["action"]), []byte("null")) {
		return nil, bad
	}
	if i.record[134] == 0 {
		if !bytes.Equal(bytes.TrimSpace(r["active_request_id"]), []byte("null")) {
			return nil, bad
		}
	} else {
		var active [16]byte
		copy(active[:], i.record[135:])
		if !replyUUID(r["active_request_id"], active) {
			return nil, bad
		}
		out.ActiveRequest = &active
	}
	return out, nil
}

// ConsumeOwnerReview attempts descriptor-null consumption once. Unavailable
// means this call did not dispatch consume, never that prior history is absent.
func (c *OriginalCurrentClient) ConsumeOwnerReview(ctx context.Context, grant string, intent *OriginalOwnerReviewIntent, clock func() uint64) (*OriginalOwnerReviewConsumption, error) {
	return c.ownerReview(ctx, grant, intent, clock, true)
}

// StatusOwnerReview reconciles exactly the saved intent without issuing consume.
// An unavailable status never establishes that the intent was not consumed.
func (c *OriginalCurrentClient) StatusOwnerReview(ctx context.Context, grant string, intent *OriginalOwnerReviewIntent, clock func() uint64) (*OriginalOwnerReviewConsumption, error) {
	return c.ownerReview(ctx, grant, intent, clock, false)
}
func (c *OriginalCurrentClient) ownerReview(ctx context.Context, grant string, intent *OriginalOwnerReviewIntent, clock func() uint64, effect bool) (*OriginalOwnerReviewConsumption, error) {
	bad := OriginalHTTPError{}
	if c == nil || intent == nil || clock == nil {
		return nil, bad
	}
	owned, e := c.RestoreOwnerReviewIntent(intent.Bytes())
	if e != nil {
		return nil, bad
	}
	if !c.mu.TryLock() {
		return nil, bad
	}
	defer c.mu.Unlock()
	before, e := c.currentLocked(ctx, grant, clock)
	if e != nil {
		return nil, bad
	}
	var event, request [16]byte
	copy(event[:], owned.record[102:118])
	copy(request[:], owned.record[118:134])
	req := OriginalHTTPRequest{Method: "status", ConsumptionID: replyUUIDText(request), AcceptedManifestVersion: before.authority.Manifest.version}
	if effect {
		req.Method = "consume"
		req.ConsumptionID = ""
		req.EventID = replyUUIDText(event)
		req.RequestID = replyUUIDText(request)
		if owned.record[134] == 1 {
			var active [16]byte
			copy(active[:], owned.record[135:])
			req.ActiveRequestID = replyUUIDText(active)
		}
	}
	wire, e := c.transport.Exchange(ctx, grant, req)
	if e != nil {
		return nil, e
	}
	fail := OriginalHTTPError{Unknown: effect}
	out, e := ownerReviewResult(json.RawMessage(wire.JSON), owned)
	if e != nil {
		return nil, fail
	}
	out.Authority, e = c.currentLocked(ctx, grant, clock)
	if e != nil {
		return nil, fail
	}
	return out, nil
}

package hpke

import (
	"bytes"
	"context"
)

// OriginalProposalIntent is an exact caller-persisted proposal, never approval.
type OriginalProposalIntent struct {
	record []byte
	owner  *OriginalOwnerReviewIntent
	action *WorkflowAction
}

func (i *OriginalProposalIntent) Bytes() []byte {
	if i == nil {
		return nil
	}
	return append([]byte(nil), i.record...)
}
func (c *OriginalCurrentClient) PrepareProposal(event, request, active [16]byte, action *WorkflowAction) (*OriginalProposalIntent, error) {
	owner, e := c.PrepareOwnerReview(event, request, &active)
	if e != nil || action == nil {
		return nil, OriginalHTTPError{}
	}
	raw := owner.Bytes()
	copy(raw[:5], []byte("ZTOP\x01"))
	return c.RestoreProposalIntent(append(raw, action.Canonical()...))
}
func (c *OriginalCurrentClient) RestoreProposalIntent(raw []byte) (*OriginalProposalIntent, error) {
	bad := OriginalHTTPError{}
	if len(raw) <= 151 || len(raw) > 4096 || !bytes.Equal(raw[:5], []byte("ZTOP\x01")) || raw[134] != 1 {
		return nil, bad
	}
	owned := append([]byte(nil), raw...)
	ownerRaw := append([]byte(nil), owned[:151]...)
	copy(ownerRaw[:5], []byte("ZTOR\x01"))
	owner, e := c.RestoreOwnerReviewIntent(ownerRaw)
	if e != nil {
		return nil, bad
	}
	action, e := ParseWorkflowAction(owned[151:])
	if e != nil || !action.production() || !bytes.Equal(owned[151:], action.canonical) {
		return nil, bad
	}
	if !replyUUID(action.fields["account_id"], c.scope.Account) || !replyUUID(action.fields["line_id"], c.scope.Line) {
		return nil, bad
	}
	return &OriginalProposalIntent{owned, owner, action}, nil
}

type WorkflowActionKey struct {
	AccountID, ActionID string
	Revision            uint64
	BindingDigest       string
}
type OriginalProposalConsumption struct {
	Event, Consumption, ActiveRequest [16]byte
	Action                            *WorkflowActionKey
	Authority                         *VerifiedOriginalCurrent
}

// ConsumeProposal uses output authorization only for this single proposal effect.
// Persist intent first. Unknown outcomes must be reconciled using StatusProposal.
func (c *OriginalCurrentClient) ConsumeProposal(ctx context.Context, grant, output string, intent *OriginalProposalIntent, clock func() uint64) (*OriginalProposalConsumption, error) {
	return c.proposal(ctx, grant, output, intent, clock, true)
}
func (c *OriginalCurrentClient) StatusProposal(ctx context.Context, grant string, intent *OriginalProposalIntent, clock func() uint64) (*OriginalProposalConsumption, error) {
	return c.proposal(ctx, grant, "", intent, clock, false)
}
func (c *OriginalCurrentClient) proposal(ctx context.Context, grant, output string, intent *OriginalProposalIntent, clock func() uint64, effect bool) (*OriginalProposalConsumption, error) {
	bad := OriginalHTTPError{}
	if c == nil || intent == nil || clock == nil || (effect && !outputCredential(output)) {
		return nil, bad
	}
	saved, e := c.RestoreProposalIntent(intent.Bytes())
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
	out := &OriginalProposalConsumption{}
	copy(out.Event[:], saved.owner.record[102:118])
	copy(out.Consumption[:], saved.owner.record[118:134])
	copy(out.ActiveRequest[:], saved.owner.record[135:])
	req := OriginalHTTPRequest{Method: "status", ConsumptionID: replyUUIDText(out.Consumption), AcceptedManifestVersion: before.authority.Manifest.version}
	var action *WorkflowAction
	if effect {
		req.Method = "consume"
		req.ConsumptionID = ""
		req.EventID = replyUUIDText(out.Event)
		req.RequestID = replyUUIDText(out.Consumption)
		req.ActiveRequestID = replyUUIDText(out.ActiveRequest)
		action = saved.action
	}
	wire, e := c.transport.exchange(ctx, grant, req, action, output)
	if e != nil {
		return nil, e
	}
	fail := OriginalHTTPError{Unknown: effect}
	r, e := replyObject(wire.JSON, "event_id", "consumption_id", "disposition", "active_request_id", "action")
	if e != nil || !replyUUID(r["event_id"], out.Event) || !replyUUID(r["consumption_id"], out.Consumption) || !replyUUID(r["active_request_id"], out.ActiveRequest) {
		return nil, fail
	}
	disposition, e := replyString(r["disposition"])
	if e != nil {
		return nil, fail
	}
	if disposition == "owner_review" && bytes.Equal(bytes.TrimSpace(r["action"]), []byte("null")) {
		out.Authority, e = c.currentLocked(ctx, grant, clock)
		if e != nil {
			return nil, fail
		}
		return out, nil
	}
	if disposition != "proposal" {
		return nil, fail
	}
	key, e := replyObject(r["action"], "account_id", "action_id", "revision", "binding_digest")
	if e != nil {
		return nil, fail
	}
	for _, name := range []string{"account_id", "action_id"} {
		actual, e := replyString(key[name])
		expected, _ := replyString(saved.action.fields[name])
		if e != nil || actual != expected {
			return nil, fail
		}
	}
	actualRevision, e := replyInteger(key["revision"])
	expectedRevision, _ := replyInteger(saved.action.fields["revision"])
	if e != nil || actualRevision != expectedRevision {
		return nil, fail
	}

	digest, e := replyString(key["binding_digest"])
	if e != nil || digest != saved.action.Digest() {
		return nil, fail
	}
	out.Action = &WorkflowActionKey{}
	out.Action.AccountID, _ = replyString(key["account_id"])
	out.Action.ActionID, _ = replyString(key["action_id"])
	out.Action.Revision, _ = replyInteger(key["revision"])
	out.Action.BindingDigest = digest
	out.Authority, e = c.currentLocked(ctx, grant, clock)
	if e != nil {
		return nil, fail
	}
	return out, nil
}

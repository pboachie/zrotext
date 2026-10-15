package hpke

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"
)

const contextContentType = "application/vnd.zrotext.workflow-context.v1"

type OwnerContextError struct{ Code, State string }

func (e OwnerContextError) Error() string { return "owner context " + e.Code }

type ContextTicket struct{ identity byte }
type ContextPending struct {
	RequestID, ContextID, EnvelopeDigest string
	Revision                             uint8
}
type ContextReceipt struct {
	ContextPending
	RequestAcknowledged bool
}
type ContextWriteReview struct {
	ContextPending
	ExpectedRevision uint8
	Scope            WorkflowContextScope
}
type OwnerContextOptions struct {
	Origin             string
	Binding            OwnerBinding
	Context            [16]byte
	Kind               byte
	Enabled            bool
	Timeout            time.Duration
	AdditionalRootsPEM []byte
	Current            func(context.Context) (OwnerTemplateAuthority, error)
	Session            func(context.Context) (OwnerSession, error)
	Review             func(context.Context, ContextWriteReview) error
}
type contextSaved struct {
	ticket             *ContextTicket
	scope              WorkflowContextScope
	wire               []byte
	request            string
	expected           uint8
	digest             [32]byte
	session            OwnerSession
	deadline           time.Time
	attempts, verifies uint8
	unknown            bool
	timer              *time.Timer
}

// OwnerWorkflowContextClient persists only exact reviewed ciphertext. Its private
// engine shares owner lifetime/admission policy, never template receipt semantics.
type OwnerWorkflowContextClient struct {
	engine  *OwnerTemplateClient
	expired atomic.Bool
	saved   *contextSaved // protected by engine.state and operation admission
	kind    byte
	review  func(context.Context, ContextWriteReview) error
}

func NewOwnerWorkflowContextClient(o OwnerContextOptions) (*OwnerWorkflowContextClient, error) {
	if o.Kind < 1 || o.Kind > 3 || o.Review == nil || o.Current == nil {
		return nil, OwnerContextError{"invalid_request", "refused"}
	}
	source := o.Current
	// Capture genuine token data before another caller callback can replace it.
	current := func(ctx context.Context) (OwnerTemplateAuthority, error) {
		a, e := source(ctx)
		if e == nil && a.Manifest != nil {
			m := *a.Manifest
			m.raw = append([]byte(nil), m.raw...)
			m.lineage = append([][32]byte(nil), m.lineage...)
			a.Manifest = &m
		}
		return a, e
	}
	engine, e := NewOwnerTemplateClient(OwnerTemplateOptions{Origin: o.Origin, Binding: o.Binding, Template: o.Context, Enabled: o.Enabled, Timeout: o.Timeout, AdditionalRootsPEM: o.AdditionalRootsPEM, Current: current, Session: o.Session}, func(context.Context, TemplateCiphertextReview) error { return ErrAuthentication })
	if e != nil {
		return nil, OwnerContextError{"invalid_request", "refused"}
	}
	return &OwnerWorkflowContextClient{engine: engine, kind: o.Kind, review: o.Review}, nil
}
func (c *OwnerWorkflowContextClient) Close() {
	if c == nil {
		return
	}
	c.engine.Close()
	c.cleanupClosed()
}
func (c *OwnerWorkflowContextClient) cleanupClosed() {
	if c.engine.reader.closed.Load() && c.engine.state.TryLock() {
		if c.saved != nil {
			if c.saved.timer != nil {
				c.saved.timer.Stop()
			}
			clear(c.saved.wire)
			c.saved = nil
		}
		c.engine.state.Unlock()
	}
}
func (c *OwnerWorkflowContextClient) Pending() *ContextPending {
	if c == nil {
		return nil
	}
	p := c.engine.Pending()
	if p == nil {
		return nil
	}
	return &ContextPending{p.RequestID, p.TemplateID, p.EncryptedDigest, p.Revision}
}
func (c *OwnerWorkflowContextClient) classify(e error) error {
	if e == nil {
		return nil
	}
	if known, ok := e.(OwnerContextError); ok {
		return known
	}
	code := "invalid_request"
	unknown := c.Pending() != nil
	if known, ok := e.(OwnerTemplateError); ok {
		code = known.Code
		unknown = unknown || known.Unknown
	}
	if code == "deadline" {
		code = "expired"
		c.expired.Store(true)
	}
	if unknown && code != "busy" && code != "capacity" && code != "pending_write" && code != "invalid_ticket" {
		return OwnerContextError{"response_unknown", "unknown"}
	}
	return OwnerContextError{code, "refused"}
}
func (c *OwnerWorkflowContextClient) execute(ctx context.Context, op func(context.Context, *ownerTemplateWork) (ownerSaveResult, error)) (ownerSaveResult, error) {
	if c == nil {
		return ownerSaveResult{}, OwnerContextError{"invalid_request", "refused"}
	}
	return c.executeOwned(ctx, op, nil)
}
func (c *OwnerWorkflowContextClient) executeOwned(ctx context.Context, op func(context.Context, *ownerTemplateWork) (ownerSaveResult, error), cleanup func()) (ownerSaveResult, error) {
	if c == nil {
		if cleanup != nil {
			cleanup()
		}
		return ownerSaveResult{}, OwnerContextError{"invalid_request", "refused"}
	}
	result, e := c.engine.executeOwned(ctx, func(ctx context.Context, w *ownerTemplateWork) (ownerSaveResult, error) {
		v, e := op(ctx, w)
		if own, ok := e.(OwnerContextError); ok {
			v.value = own
			return v, nil
		}
		return v, e
	}, func() {
		if cleanup != nil {
			cleanup()
		}
		c.cleanupClosed()
	})
	if e == nil {
		if own, ok := result.value.(OwnerContextError); ok && own.State != "not_current" {
			return ownerSaveResult{}, own
		}
	}
	return result, c.classify(e)
}
func contextTemplateScope(s WorkflowContextScope) EncryptedTemplateScope {
	return EncryptedTemplateScope{s.Account, s.Device, s.Line, s.Interval, s.Context, s.BindingGeneration, s.Revision, s.Expires, s.TrustGeneration, s.ManifestVersion, s.PeerDigest, s.Reader, s.ManifestDigest}
}
func parseContextScope(wire []byte) (WorkflowContextScope, error) {
	var s WorkflowContextScope
	if len(wire) < 308 || len(wire) > 33075 || !bytes.Equal(wire[:5], []byte("ZTWC\x01")) || wire[222] != 4 || int(binary.BigEndian.Uint32(wire[287:291])) != len(wire)-291 {
		return s, ErrShape
	}
	s.Kind = wire[5]
	for i, p := range [][]byte{s.Account[:], s.Device[:], s.Line[:], s.Interval[:], s.Context[:]} {
		copy(p, wire[6+i*16:22+i*16])
	}
	for i, p := range []*uint64{&s.BindingGeneration, &s.Revision, &s.Expires, &s.TrustGeneration, &s.ManifestVersion} {
		*p = binary.BigEndian.Uint64(wire[86+i*8 : 94+i*8])
	}
	for i, p := range [][]byte{s.PeerDigest[:], s.Reader[:], s.ManifestDigest[:]} {
		copy(p, wire[126+i*32:158+i*32])
	}
	_, e := s.AAD()
	return s, e
}
func (c *OwnerWorkflowContextClient) authorize(ctx context.Context, w *ownerTemplateWork, s WorkflowContextScope, session OwnerSession) error {
	if s.Kind != c.kind {
		c.Close()
		return OwnerTemplateError{Code: "owner_changed"}
	}
	mapped := contextTemplateScope(s)
	return c.engine.reader.authorize(ctx, w, &mapped, session)
}
func (c *OwnerWorkflowContextClient) identity(r *contextSaved) ContextPending {
	id := hex.EncodeToString(r.scope.Context[:])
	return ContextPending{r.request, id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:], hex.EncodeToString(r.digest[:]), uint8(r.scope.Revision)}
}
func (c *OwnerWorkflowContextClient) forget(r *contextSaved) {
	if c.saved == r {
		if r.timer != nil {
			r.timer.Stop()
		}
		clear(r.wire)
		c.saved = nil
		c.engine.setPending(nil)
	}
}
func (c *OwnerWorkflowContextClient) deadline(r *contextSaved, w *ownerTemplateWork) {
	w.shorten(r.deadline)
	r.deadline = w.end()
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(time.Until(r.deadline), func() { c.expired.Store(true); c.Close() })
}
func (c *OwnerWorkflowContextClient) ticket(t *ContextTicket, w *ownerTemplateWork) (*contextSaved, error) {
	if c.engine.reader.closed.Load() && c.Pending() != nil {
		return nil, OwnerContextError{"closed", "unknown"}
	}
	r := c.saved
	if t == nil || r == nil || r.ticket != t {
		return nil, OwnerContextError{"invalid_ticket", "refused"}
	}
	w.shorten(r.deadline)
	return r, nil
}
func (c *OwnerWorkflowContextClient) Prepare(ctx context.Context, request string, expected uint8, scope WorkflowContextScope, envelope []byte) (*ContextTicket, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return nil, OwnerContextError{"invalid_request", "refused"}
	}
	wire := append([]byte(nil), envelope...)
	out, e := c.executeOwned(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		if c.saved != nil || c.Pending() != nil {
			return out, OwnerContextError{"pending_write", "refused"}
		}
		if e := c.engine.reader.live(ctx, w); e != nil {
			return out, e
		}
		parsed, e := parseContextScope(wire)
		if e != nil || parsed != scope || !originalUUID(request) || expected > 127 || scope.Revision != uint64(expected)+1 {
			return out, OwnerContextError{"invalid_request", "refused"}
		}
		session, e := c.engine.reader.credentials(ctx, w)
		if e != nil {
			return out, e
		}
		r := &contextSaved{ticket: &ContextTicket{}, scope: scope, wire: append([]byte(nil), wire...), request: request, expected: expected, digest: sha256.Sum256(wire), session: session, deadline: w.end()}
		c.saved = r
		defer func() {
			if err != nil {
				c.forget(r)
			}
		}()
		c.deadline(r, w)
		if err = c.authorize(ctx, w, scope, session); err != nil {
			return
		}
		c.deadline(r, w)
		if _, err = ecdh.P256().NewPublicKey(wire[222:287]); err != nil {
			return out, OwnerContextError{"invalid_request", "refused"}
		}
		if err = c.review(ctx, ContextWriteReview{c.identity(r), expected, scope}); err != nil {
			return out, OwnerContextError{"read_refused", "refused"}
		}
		if err = c.engine.reader.live(ctx, w); err != nil {
			return
		}
		if err = c.authorize(ctx, w, scope, session); err != nil {
			return
		}
		c.deadline(r, w)
		out.value = r.ticket
		return
	}, func() { clear(wire) })
	if e != nil {
		return nil, e
	}
	return out.value.(*ContextTicket), nil
}
func (c *OwnerWorkflowContextClient) fetch(ctx context.Context, w *ownerTemplateWork, r *contextSaved, post bool) (int, string, []byte, error) {
	if e := c.engine.reader.live(ctx, w); e != nil {
		return 0, "", nil, e
	}
	session, e := c.engine.reader.credentials(ctx, w)
	if e != nil || session != r.session {
		c.Close()
		return 0, "", nil, OwnerTemplateError{Code: "owner_changed"}
	}
	path := "/v1/owner/workflow/contexts"
	method := "GET"
	var body io.Reader
	if post {
		method = "POST"
		body = bytes.NewReader(r.wire)
	} else {
		path += "/" + c.identity(r).ContextID
	}
	call, cancel := context.WithDeadline(ctx, w.end())
	defer cancel()
	req, e := http.NewRequestWithContext(call, method, c.engine.reader.options.Origin+path, body)
	if e != nil {
		return 0, "", nil, e
	}
	req.GetBody = nil
	req.Header.Set("Cookie", session.Cookie)
	req.Header.Set("X-Zrotext-CSRF", session.CSRF)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Accept", contextContentType)
	if post {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", contextContentType)
		req.Header.Set("Idempotency-Key", r.request)
		req.Header.Set("X-Zrotext-Context-Revision", strconv.Itoa(int(r.expected)))
	}
	response, e := c.engine.reader.client.Do(req)
	if e != nil {
		return 0, "", nil, e
	}
	defer response.Body.Close()
	if e = c.engine.reader.live(ctx, w); e != nil {
		return 0, "", nil, e
	}
	typ := response.Header.Get("Content-Type")
	if len(response.Header.Values("Content-Type")) != 1 {
		typ = ""
	}
	if response.StatusCode != 200 {
		return response.StatusCode, typ, nil, nil
	}
	limit := 33075
	if post {
		limit = 64
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if e != nil || len(raw) > limit {
		return 0, "", nil, OwnerTemplateError{Code: "response_unknown"}
	}
	if e = c.engine.reader.live(ctx, w); e != nil {
		return 0, "", nil, e
	}
	return 200, typ, raw, nil
}
func (c *OwnerWorkflowContextClient) latest(ctx context.Context, w *ownerTemplateWork, r *contextSaved, ack bool) (ContextReceipt, bool, error) {
	none := ContextReceipt{}
	if e := c.authorize(ctx, w, r.scope, r.session); e != nil {
		return none, false, e
	}
	c.deadline(r, w)
	status, typ, raw, e := c.fetch(ctx, w, r, false)
	if e != nil || status != 200 || typ != contextContentType {
		return none, false, OwnerTemplateError{Code: "response_unknown"}
	}
	if bytes.Equal(raw, r.wire) {
		if e = c.authorize(ctx, w, r.scope, r.session); e != nil {
			return none, false, e
		}
		c.deadline(r, w)
		return ContextReceipt{c.identity(r), ack}, false, nil
	}
	newer, e := parseContextScope(raw)
	old := r.scope
	if e != nil || newer.Kind != old.Kind || newer.Account != old.Account || newer.Device != old.Device || newer.Line != old.Line || newer.Interval != old.Interval || newer.Context != old.Context || newer.PeerDigest != old.PeerDigest || newer.Reader != old.Reader || newer.BindingGeneration != old.BindingGeneration || newer.TrustGeneration != old.TrustGeneration || newer.Revision <= old.Revision {
		return none, false, OwnerTemplateError{Code: "response_unknown"}
	}
	if _, e = ecdh.P256().NewPublicKey(raw[222:287]); e != nil {
		return none, false, OwnerTemplateError{Code: "response_unknown"}
	}
	if e = c.authorize(ctx, w, newer, r.session); e != nil {
		return none, false, e
	}
	c.deadline(r, w)
	if ack {
		return none, true, nil
	}
	return none, false, OwnerTemplateError{Code: "response_unknown"}
}
func (c *OwnerWorkflowContextClient) Commit(ctx context.Context, t *ContextTicket) (ContextReceipt, error) {
	return c.post(ctx, t, false)
}
func (c *OwnerWorkflowContextClient) RetryUnknown(ctx context.Context, t *ContextTicket) (ContextReceipt, error) {
	return c.post(ctx, t, true)
}
func (c *OwnerWorkflowContextClient) post(ctx context.Context, t *ContextTicket, retry bool) (ContextReceipt, error) {
	if c != nil && c.engine.reader.closed.Load() {
		if c.Pending() != nil {
			code := "closed"
			if c.expired.Load() {
				code = "expired"
			}
			return ContextReceipt{}, OwnerContextError{code, "unknown"}
		}
		return ContextReceipt{}, OwnerContextError{"invalid_ticket", "refused"}
	}
	out, e := c.execute(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		r, e := c.ticket(t, w)
		if e != nil {
			return out, e
		}
		prior := r.unknown
		if (retry && !prior) || (!retry && r.attempts != 0) {
			return out, OwnerContextError{"invalid_ticket", "refused"}
		}
		if r.attempts >= 3 {
			return out, OwnerContextError{"attempts_exhausted", "unknown"}
		}
		if e = c.authorize(ctx, w, r.scope, r.session); e != nil {
			return out, e
		}
		c.deadline(r, w)
		r.attempts++
		r.unknown = true
		p := c.identity(r)
		c.engine.setPending(&TemplatePending{p.RequestID, p.ContextID, p.EnvelopeDigest, p.Revision})
		status, typ, raw, e := c.fetch(ctx, w, r, true)
		if e != nil {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		codes := map[int]string{400: "invalid_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict", 413: "too_large", 429: "rate_limited"}
		if code, ok := codes[status]; ok {
			if prior {
				return out, OwnerTemplateError{Code: "response_unknown"}
			}
			out.value = OwnerContextError{code, "refused"}
			out.finish = func() { c.forget(r) }
			return out, nil
		}
		canonical := []byte("{\"revision\":" + strconv.FormatUint(r.scope.Revision, 10) + "}")
		raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
		if status != 200 || !regexp.MustCompile(`(?i)^application/json(?:\s*;\s*charset=utf-8)?$`).MatchString(typ) || !bytes.Equal(raw, canonical) {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		receipt, changed, e := c.latest(ctx, w, r, true)
		if e != nil {
			return out, e
		}
		out.value = receipt
		if changed {
			out.value = OwnerContextError{"head_changed", "not_current"}
		}
		out.finish = func() { c.forget(r) }
		return out, nil
	})
	if e != nil {
		return ContextReceipt{}, e
	}
	if refused, ok := out.value.(OwnerContextError); ok {
		return ContextReceipt{}, refused
	}
	return out.value.(ContextReceipt), nil
}
func (c *OwnerWorkflowContextClient) VerifyUnknown(ctx context.Context, t *ContextTicket) (ContextReceipt, error) {
	if c != nil && c.engine.reader.closed.Load() {
		if c.Pending() != nil {
			code := "closed"
			if c.expired.Load() {
				code = "expired"
			}
			return ContextReceipt{}, OwnerContextError{code, "unknown"}
		}
		return ContextReceipt{}, OwnerContextError{"invalid_ticket", "refused"}
	}
	out, e := c.execute(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		r, e := c.ticket(t, w)
		if e != nil {
			return out, e
		}
		if !r.unknown {
			return out, OwnerContextError{"invalid_ticket", "refused"}
		}
		if r.verifies >= 3 {
			return out, OwnerContextError{"attempts_exhausted", "unknown"}
		}
		r.verifies++
		receipt, _, e := c.latest(ctx, w, r, false)
		if e != nil {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		out.value = receipt
		return out, nil
	})
	if e != nil {
		return ContextReceipt{}, e
	}
	return out.value.(ContextReceipt), nil
}

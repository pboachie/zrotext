package hpke

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// TemplateTicket is an instance-bound capability for the exact reviewed bytes.
// It cannot be serialized or restored as authority after a restart.
type TemplateTicket struct{ identity byte }
type TemplatePending struct {
	RequestID, TemplateID, EncryptedDigest string
	Revision                               uint8
}
type TemplateAcknowledgement struct{ TemplatePending }
type TemplateCiphertextReview struct {
	RequestID        string
	ExpectedRevision uint8
	Scope            EncryptedTemplateScope
	EncryptedDigest  string
}
type CiphertextReviewer func(context.Context, TemplateCiphertextReview) error
type ownerSaved struct {
	ticket             *TemplateTicket
	request            *TemplateSaveRequest
	scope              EncryptedTemplateScope
	session            OwnerSession
	deadline           time.Time
	attempts, verifies int
	unknown            bool
	timer              *time.Timer
}
type ownerSaveResult struct {
	ticket   *TemplateTicket
	snapshot *OwnerTemplateSnapshot
	ack      *TemplateAcknowledgement
	finish   func()
}

// OwnerTemplateClient owns in-memory save/recovery state. All operations are
// explicit, serialized, and bound to one independent owner host lifetime.
type OwnerTemplateClient struct {
	reader    *OwnerTemplateReader
	review    CiphertextReviewer
	state     sync.Mutex
	saved     *ownerSaved
	pendingMu sync.Mutex
	pending   *TemplatePending
}

func NewOwnerTemplateClient(options OwnerTemplateOptions, review CiphertextReviewer) (*OwnerTemplateClient, error) {
	if review == nil {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	reader, e := NewOwnerTemplateReader(options)
	if e != nil {
		return nil, e
	}
	return &OwnerTemplateClient{reader: reader, review: review}, nil
}
func (c *OwnerTemplateClient) Close() {
	if c != nil {
		c.reader.Close()
	}
}
func (c *OwnerTemplateClient) Pending() *TemplatePending {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if c.pending == nil {
		return nil
	}
	p := *c.pending
	return &p
}
func (c *OwnerTemplateClient) setPending(p *TemplatePending) {
	c.pendingMu.Lock()
	c.pending = p
	c.pendingMu.Unlock()
}
func (c *OwnerTemplateClient) classify(e error) error {
	if known, ok := e.(OwnerTemplateError); ok && (known.Code == "invalid_request" || known.Code == "pending_write" || known.Code == "busy" || known.Code == "capacity") {
		return e
	}
	if e != nil && c.Pending() != nil {
		return OwnerTemplateError{Code: "response_unknown", Unknown: true}
	}
	return e
}
func (c *OwnerTemplateClient) forget(r *ownerSaved) {
	if c.saved == r {
		if r.timer != nil {
			r.timer.Stop()
		}
		clear(r.request.body)
		c.saved = nil
		c.setPending(nil)
	}
}
func (c *OwnerTemplateClient) identity(r *ownerSaved) TemplatePending {
	id := hex.EncodeToString(r.scope.Template[:])
	return TemplatePending{r.request.request, id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:], r.request.EncryptedDigest(), r.request.Revision()}
}
func (c *OwnerTemplateClient) deadline(r *ownerSaved, w *ownerTemplateWork) {
	w.shorten(r.deadline)
	r.deadline = w.end()
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(time.Until(r.deadline), c.Close)
}
func (c *OwnerTemplateClient) ticket(t *TemplateTicket, w *ownerTemplateWork) (*ownerSaved, error) {
	r := c.saved
	if r == nil || t == nil || r.ticket != t {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	w.shorten(r.deadline)
	return r, nil
}

// Admission precedes every saved/pending decision. A losing prepare never owns
// another operation's record, and cannot clear its ticket or uncertainty.
func (c *OwnerTemplateClient) execute(ctx context.Context, op func(context.Context, *ownerTemplateWork) (ownerSaveResult, error)) (ownerSaveResult, error) {
	empty := ownerSaveResult{}
	if c == nil || ctx == nil {
		return empty, OwnerTemplateError{Code: "invalid_request"}
	}
	r := c.reader
	if !r.busy.CompareAndSwap(false, true) {
		return empty, c.classify(OwnerTemplateError{Code: "busy"})
	}
	select {
	case ownerTemplateAdmission <- struct{}{}:
	default:
		r.busy.Store(false)
		return empty, c.classify(OwnerTemplateError{Code: "capacity"})
	}
	ctx, cancel := context.WithTimeout(ctx, r.options.Timeout)
	defer cancel()
	r.mu.Lock()
	r.cancel = cancel
	r.mu.Unlock()
	w := &ownerTemplateWork{deadline: time.Now().Add(r.options.Timeout), changed: make(chan struct{}, 1)}
	type outcome struct {
		value ownerSaveResult
		err   error
	}
	done := make(chan outcome, 1)
	settled := make(chan struct{})
	released := make(chan struct{})
	finished := false
	go func() {
		defer func() {
			r.mu.Lock()
			r.cancel = nil
			r.mu.Unlock()
			<-ownerTemplateAdmission
			r.busy.Store(false)
			close(released)
		}()
		c.state.Lock()
		value, e := op(ctx, w)
		c.state.Unlock()
		done <- outcome{value, e}
		<-settled
		if r.closed.Load() {
			c.state.Lock()
			if c.saved != nil {
				if c.saved.timer != nil {
					c.saved.timer.Stop()
				}
				clear(c.saved.request.body)
				c.saved = nil
			}
			c.state.Unlock()
		}
	}()
	defer func() {
		close(settled)
		if finished {
			<-released
		}
	}()
	for {
		timer := time.NewTimer(time.Until(w.end()))
		select {
		case result := <-done:
			finished = true
			timer.Stop()
			if result.err != nil {
				return empty, c.classify(result.err)
			}
			if e := r.live(ctx, w); e != nil {
				return empty, c.classify(e)
			}
			// Only the foreground success fence can forget an acknowledged request.
			c.state.Lock()
			if result.value.finish != nil {
				result.value.finish()
			}
			c.state.Unlock()
			return result.value, nil
		case <-w.changed:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			c.Close()
			return empty, c.classify(OwnerTemplateError{Code: "deadline"})
		case <-timer.C:
			c.Close()
			return empty, c.classify(OwnerTemplateError{Code: "deadline"})
		}
	}
}
func (c *OwnerTemplateClient) PrepareSave(ctx context.Context, scope EncryptedTemplateScope, requestID string, expected uint8, envelope []byte) (*TemplateTicket, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	// Snapshot caller-owned bytes before asynchronous work; no state is captured.
	wire := append([]byte(nil), envelope...)
	result, e := c.execute(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		defer clear(wire)
		if c.saved != nil || c.Pending() != nil {
			return out, OwnerTemplateError{Code: "pending_write"}
		}
		if err = c.reader.live(ctx, w); err != nil {
			return
		}
		request, e := NewTemplateSaveRequest(scope, requestID, expected, wire)
		if e != nil {
			return out, OwnerTemplateError{Code: "invalid_request"}
		}
		if _, e = parseTemplateScope(wire); e != nil {
			return out, OwnerTemplateError{Code: "invalid_request"}
		}
		session, e := c.reader.credentials(ctx, w)
		if e != nil {
			return out, e
		}
		saved := &ownerSaved{ticket: &TemplateTicket{1}, request: request, scope: scope, session: session, deadline: w.end()}
		c.saved = saved
		defer func() {
			if err != nil {
				c.forget(saved)
			}
		}()
		if err = c.reader.authorize(ctx, w, &scope, session); err != nil {
			return
		}
		c.deadline(saved, w)
		if _, e = ecdh.P256().NewPublicKey(wire[222:287]); e != nil {
			return out, OwnerTemplateError{Code: "invalid_request"}
		}
		if err = c.review(ctx, TemplateCiphertextReview{requestID, expected, scope, request.EncryptedDigest()}); err != nil {
			return out, OwnerTemplateError{Code: "invalid_request"}
		}
		if err = c.reader.authorize(ctx, w, &scope, session); err != nil {
			return
		}
		c.deadline(saved, w)
		out.ticket = saved.ticket
		return
	})
	return result.ticket, e
}
func (c *OwnerTemplateClient) Commit(ctx context.Context, t *TemplateTicket) (*TemplateAcknowledgement, error) {
	return c.post(ctx, t, false)
}
func (c *OwnerTemplateClient) RetryUnknown(ctx context.Context, t *TemplateTicket) (*TemplateAcknowledgement, error) {
	return c.post(ctx, t, true)
}
func (c *OwnerTemplateClient) post(ctx context.Context, t *TemplateTicket, retry bool) (*TemplateAcknowledgement, error) {
	result, e := c.execute(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		r, e := c.ticket(t, w)
		if e != nil {
			return out, e
		}
		if retry && !r.unknown || !retry && r.attempts != 0 {
			return out, OwnerTemplateError{Code: "invalid_request"}
		}
		if r.attempts >= 3 {
			return out, OwnerTemplateError{Code: "attempts_exhausted"}
		}
		if e = c.reader.authorize(ctx, w, &r.scope, r.session); e != nil {
			return out, e
		}
		c.deadline(r, w)
		r.attempts++
		r.unknown = true
		p := c.identity(r)
		c.setPending(&p)
		session, e := c.reader.credentials(ctx, w)
		if e != nil || session != r.session {
			c.Close()
			return out, OwnerTemplateError{Code: "owner_changed"}
		}
		call, cancel := context.WithDeadline(ctx, w.end())
		defer cancel()
		req, e := http.NewRequestWithContext(call, "POST", c.reader.options.Origin+r.request.Path(), bytes.NewReader(r.request.body))
		if e != nil {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		// No GetBody replay seam, even though transport policy already disables it.
		req.GetBody = nil
		for name, value := range r.request.Headers() {
			req.Header.Set(name, value)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cookie", session.Cookie)
		req.Header.Set("X-Zrotext-CSRF", session.CSRF)
		req.Header.Set("Cache-Control", "no-store")
		response, e := c.reader.client.Do(req)
		if e != nil {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		defer response.Body.Close()
		if response.StatusCode == 401 || response.StatusCode == 403 {
			c.Close()
		}
		validType := regexp.MustCompile(`(?i)^application/json(?:\s*;\s*charset=utf-8)?$`).MatchString(response.Header.Get("Content-Type"))
		if response.StatusCode != 200 || len(response.Header.Values("Content-Type")) != 1 || !validType {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 257))
		if e != nil {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		if _, e = r.request.Receipt(body); e != nil {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		if e = c.reader.authorize(ctx, w, &r.scope, r.session); e != nil {
			return out, e
		}
		c.deadline(r, w)
		if r.scope.Revision == c.reader.head && r.request.digest != c.reader.headDigest {
			return out, OwnerTemplateError{Code: "response_unknown"}
		}
		out.ack = &TemplateAcknowledgement{c.identity(r)}
		out.finish = func() {
			if r.scope.Revision >= c.reader.head {
				c.reader.head = r.scope.Revision
				c.reader.headDigest = r.request.digest
			}
			c.forget(r)
		}
		return out, nil
	})
	return result.ack, e
}
func (c *OwnerTemplateClient) ReadLatest(ctx context.Context) (*OwnerTemplateSnapshot, error) {
	return c.latest(ctx, nil, false)
}
func (c *OwnerTemplateClient) VerifyUnknown(ctx context.Context, t *TemplateTicket) (*OwnerTemplateSnapshot, error) {
	return c.latest(ctx, t, true)
}
func (c *OwnerTemplateClient) latest(ctx context.Context, t *TemplateTicket, verify bool) (*OwnerTemplateSnapshot, error) {
	result, e := c.execute(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		r := c.saved
		if verify {
			r, err = c.ticket(t, w)
			if err != nil {
				return
			}
			if !r.unknown {
				return out, OwnerTemplateError{Code: "invalid_request"}
			}
		}
		if r != nil {
			w.shorten(r.deadline)
			if r.unknown {
				if r.verifies >= 3 {
					return out, OwnerTemplateError{Code: "attempts_exhausted"}
				}
				r.verifies++
			}
			session, e := c.reader.credentials(ctx, w)
			if e != nil || session != r.session {
				c.Close()
				return out, OwnerTemplateError{Code: "owner_changed"}
			}
		}
		var expected *OwnerSession
		if r != nil {
			expected = &r.session
		}
		out.snapshot, err = c.reader.readExpected(ctx, w, expected)
		if err != nil && r != nil && r.unknown {
			err = OwnerTemplateError{Code: "response_unknown", Unknown: true}
		}
		if err == nil && r != nil {
			c.deadline(r, w)
			out.snapshot.matchesPending = bytes.Equal(out.snapshot.wire, r.request.body)
		}
		return
	})
	return result.snapshot, e
}

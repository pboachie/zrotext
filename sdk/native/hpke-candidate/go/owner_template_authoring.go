package hpke

import (
	"context"
	"regexp"
	"time"
)

// TemplateDraftState is an independently maintained host lease. CustodyLive is
// not a key capability or evidence of protected provider qualification.
type TemplateDraftState struct {
	Epoch, Revision uint64
	CustodyLive     bool
}
type TemplateDraftSource func(context.Context) (TemplateDraftState, error)
type TemplateDraftReview struct {
	RequestID            string
	ExpectedRevision     uint8
	Scope                EncryptedTemplateScope
	Epoch, DraftRevision uint64
	Content              *TemplateContent
	Text                 string
	Segments             SegmentEstimate
}
type TemplateDraftReviewer func(context.Context, TemplateDraftReview) (bool, error)

// OwnerTemplateAuthoring prepares one reviewed immutable draft, never submits it.
// Host input, navigation or custody changes must invalidate this lifetime.
type OwnerTemplateAuthoring struct {
	client, guard *OwnerTemplateClient
	draft         TemplateDraftSource
	review        TemplateDraftReviewer
	used          bool // guarded by guard.state after admission
}

func NewOwnerTemplateAuthoring(options OwnerTemplateOptions, ciphertext CiphertextReviewer, draft TemplateDraftSource, review TemplateDraftReviewer) (*OwnerTemplateAuthoring, error) {
	if draft == nil || review == nil {
		return nil, OwnerTemplateError{Code: "invalid_draft"}
	}
	client, e := NewOwnerTemplateClient(options, ciphertext)
	if e != nil {
		return nil, e
	}
	guard, e := NewOwnerTemplateClient(options, func(context.Context, TemplateCiphertextReview) error { return ErrAuthentication })
	if e != nil {
		client.Close()
		return nil, e
	}
	return &OwnerTemplateAuthoring{client: client, guard: guard, draft: draft, review: review}, nil
}
func (a *OwnerTemplateAuthoring) Client() *OwnerTemplateClient { return a.client }
func (a *OwnerTemplateAuthoring) Close() {
	if a != nil {
		a.guard.Close()
		a.client.Close()
	}
}
func (a *OwnerTemplateAuthoring) Invalidate() { a.Close() }

// An operation abort must not close a different operation's saved ticket.
func (a *OwnerTemplateAuthoring) abort(owned *TemplateTicket) {
	a.guard.Close()
	if !a.client.state.TryLock() {
		return
	}
	defer a.client.state.Unlock()
	if owned != nil && a.client.saved != nil && a.client.saved.ticket == owned {
		a.client.Close()
		return
	}
	if a.client.saved == nil && a.client.reader.busy.CompareAndSwap(false, true) {
		a.client.Close()
		a.client.reader.busy.Store(false)
	}
}

func (a *OwnerTemplateAuthoring) Prepare(ctx context.Context, request string, expected uint8, scope EncryptedTemplateScope, content *TemplateContent, epoch, revision uint64) (*TemplateTicket, error) {
	if a == nil || content == nil {
		return nil, OwnerTemplateError{Code: "invalid_draft"}
	}
	// Own the validated content before the asynchronous worker sees it.
	canonical := content.Canonical()
	defer clear(canonical)
	captured, e := ParseTemplateContent(canonical)
	if e != nil || len(canonical) > 32768 {
		return nil, OwnerTemplateError{Code: "invalid_draft"}
	}
	result, e := a.guard.execute(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		// Admission and serialization precede inspecting the one-draft state.
		if a.used || a.client.Pending() != nil {
			return out, OwnerTemplateError{Code: "pending_draft"}
		}
		if !a.client.state.TryLock() {
			return out, OwnerTemplateError{Code: "pending_draft"}
		}
		hasSaved := a.client.saved != nil
		a.client.state.Unlock()
		if hasSaved {
			return out, OwnerTemplateError{Code: "pending_draft"}
		}
		var owned *TemplateTicket
		defer func() {
			v, known := err.(OwnerTemplateError)
			if err != nil && !(known && v.Code == "pending_draft") {
				a.abort(owned)
			}
		}()
		if epoch == 0 || revision == 0 || expected >= 128 || scope.Revision != uint64(expected)+1 || !regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).MatchString(request) {
			return out, OwnerTemplateError{Code: "invalid_draft"}
		}
		r := a.guard.reader
		draft := func() error {
			v, e := a.draft(ctx)
			if e != nil || v.Epoch != epoch || v.Revision != revision || !v.CustodyLive {
				return OwnerTemplateError{Code: "draft_changed"}
			}
			return r.live(ctx, w)
		}
		session, e := r.credentials(ctx, w)
		if e != nil {
			return out, e
		}
		current := func() error {
			if e := draft(); e != nil {
				return e
			}
			if e := r.authorize(ctx, w, &scope, session); e != nil {
				return e
			}
			if e := draft(); e != nil {
				return e
			}
			next, e := r.credentials(ctx, w)
			if e != nil || next != session {
				return OwnerTemplateError{Code: "owner_changed"}
			}
			return r.live(ctx, w)
		}
		text, segments, e := captured.Preview()
		if e != nil {
			return out, e
		}
		if err = current(); err != nil {
			return
		}
		accepted, e := a.review(ctx, TemplateDraftReview{request, expected, scope, epoch, revision, captured, text, segments})
		if e != nil || !accepted {
			return out, OwnerTemplateError{Code: "review_declined"}
		}
		if err = current(); err != nil {
			return
		}
		wire, e := SealEncryptedTemplate(r.prior, scope, r.now, captured)
		if e != nil {
			return out, e
		}
		defer clear(wire)
		if err = current(); err != nil {
			return
		}
		ticket, e := a.client.PrepareSave(ctx, scope, request, expected, wire)
		if e != nil {
			if v, ok := e.(OwnerTemplateError); ok && (v.Code == "pending_write" || v.Code == "busy" || v.Code == "capacity") {
				return out, OwnerTemplateError{Code: "pending_draft"}
			}
			return out, e
		}
		owned = ticket
		if err = current(); err != nil {
			return
		}
		if a.client.reader.closed.Load() {
			return out, OwnerTemplateError{Code: "closed"}
		}

		for _, reader := range []*OwnerTemplateReader{a.client.reader, a.guard.reader} {
			reader.mu.Lock()
			if reader.lifetime.IsZero() || w.end().Before(reader.lifetime) {
				reader.lifetime = w.end()
			}
			reader.mu.Unlock()
		}
		a.client.state.Lock()
		if a.client.saved != nil {
			if w.end().Before(a.client.saved.deadline) {
				a.client.saved.deadline = w.end()
			}
		}
		a.client.state.Unlock()
		out.ticket = ticket
		out.finish = func() { a.used = true; time.AfterFunc(time.Until(w.end()), a.Close) }
		return
	})
	if e != nil {
		if v, ok := e.(OwnerTemplateError); !ok || (v.Code != "busy" && v.Code != "capacity" && v.Code != "pending_draft") {
			a.abort(nil)
		}
		return nil, e
	}
	if a.client.reader.closed.Load() {
		a.Close()
		return nil, OwnerTemplateError{Code: "closed"}
	}
	return result.ticket, nil
}

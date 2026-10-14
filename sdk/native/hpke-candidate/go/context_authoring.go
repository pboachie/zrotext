package hpke

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
	"unicode/utf8"
)

// ContextAuthoringCurrent is independently authenticated host authority.
type ContextAuthoringCurrent struct {
	Binding                       OwnerBinding
	Manifest                      *Manifest
	Now                           uint64
	OwnerSessionLive, ConsentLive bool
}
type ContextAuthoringReview struct {
	Review                        ContextWriteReview
	Text, AccountID, LineID, Peer string
	Expires, Epoch, DraftRevision uint64
}
type ContextAuthoringOptions struct {
	Origin               string
	Binding              OwnerBinding
	Context              [16]byte
	Expires              uint64
	Enabled              bool
	Timeout, Observation time.Duration
	AdditionalRootsPEM   []byte
	Current              func(context.Context) (ContextAuthoringCurrent, error)
	Session              func(context.Context) (OwnerSession, error)
	Draft                TemplateDraftSource
	Review               func(context.Context, ContextAuthoringReview) (bool, error)
}
type ContextAuthoringState struct {
	Phase   string
	Pending *ContextPending
}
type AcknowledgedContextSource struct {
	AccountID string
	Receipt   ContextReceipt
}

var contextAuthors = make(chan struct{}, 4)

// OwnerContextAuthoring owns one initial facts draft and its exact saved intent.
// The host draft lease is not a protected private-key capability.
type OwnerContextAuthoring struct {
	options               ContextAuthoringOptions
	mu                    sync.Mutex
	settled               *sync.Cond
	callbacks             int
	busy, closed          bool
	phase                 string
	end                   time.Time
	timer                 *time.Timer
	ctx                   context.Context
	cancel                context.CancelFunc
	client                *OwnerWorkflowContextClient
	ticket                *ContextTicket
	pending               *ContextPending
	saved                 *AcknowledgedContextSource
	credentials           *OwnerSession
	epoch, revision, now  uint64
	posts, checks         uint8
	text, request, digest string
	scope                 WorkflowContextScope
}

func NewOwnerContextAuthoring(o ContextAuthoringOptions) (*OwnerContextAuthoring, error) {
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Observation == 0 {
		o.Observation = 10 * time.Second
	}
	if o.Context == [16]byte{} || o.Expires == 0 || o.Expires > 0x7fffffffffffffff || o.Timeout < time.Millisecond || o.Timeout > 10*time.Second || o.Observation < time.Millisecond || o.Observation > 10*time.Second || o.Current == nil || o.Session == nil || o.Draft == nil || o.Review == nil {
		return nil, ErrShape
	}
	// Reuse exact owner origin/binding validation without exposing a transport.
	validation, e := NewOwnerWorkflowContextClient(OwnerContextOptions{Origin: o.Origin, Binding: o.Binding, Context: o.Context, Kind: 1, Enabled: o.Enabled, Timeout: o.Timeout, AdditionalRootsPEM: o.AdditionalRootsPEM, Current: func(context.Context) (OwnerTemplateAuthority, error) {
		return OwnerTemplateAuthority{}, ErrAuthentication
	}, Session: o.Session, Review: func(context.Context, ContextWriteReview) error { return ErrAuthentication }})
	if e != nil {
		return nil, e
	}
	validation.Close()
	o.AdditionalRootsPEM = append([]byte(nil), o.AdditionalRootsPEM...)
	ctx, cancel := context.WithCancel(context.Background())
	a := &OwnerContextAuthoring{options: o, phase: "editing", ctx: ctx, cancel: cancel}
	a.settled = sync.NewCond(&a.mu)
	if !o.Enabled {
		a.Close()
	}
	return a, nil
}
func contextUUID(v [16]byte) string {
	h := hex.EncodeToString(v[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func (a *OwnerContextAuthoring) State() ContextAuthoringState {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := ContextAuthoringState{Phase: a.phase}
	if a.pending != nil {
		p := *a.pending
		v.Pending = &p
	}
	return v
}
func (a *OwnerContextAuthoring) SavedSource() *AcknowledgedContextSource {
	if a.live() != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != "saved" || a.saved == nil {
		return nil
	}
	v := *a.saved
	return &v
}
func (a *OwnerContextAuthoring) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	a.phase = "closed"
	a.saved = nil
	a.text = ""
	a.credentials = nil
	a.ticket = nil
	if a.timer != nil {
		a.timer.Stop()
	}
	c := a.client
	a.cancel()
	a.mu.Unlock()
	if c != nil {
		p := c.Pending()
		c.Close()
		if p != nil {
			a.mu.Lock()
			a.pending = p
			a.mu.Unlock()
		}
	}
}
func (a *OwnerContextAuthoring) Invalidate() { a.Close() }
func (a *OwnerContextAuthoring) live() error {
	a.mu.Lock()
	bad := a.closed || (!a.end.IsZero() && !time.Now().Before(a.end))
	a.mu.Unlock()
	if bad {
		a.Close()
		return ErrAuthentication
	}
	return nil
}
func (a *OwnerContextAuthoring) cap(end time.Time) error {
	a.mu.Lock()
	if a.closed || (!a.end.IsZero() && end.After(a.end)) {
		a.mu.Unlock()
		return ErrAuthentication
	}
	a.end = end
	if a.timer != nil {
		a.timer.Stop()
	}
	a.timer = time.AfterFunc(time.Until(end), a.Close)
	a.mu.Unlock()
	return a.live()
}
func (a *OwnerContextAuthoring) host(fn func() error) error {
	a.mu.Lock()
	if a.closed || (!a.end.IsZero() && !time.Now().Before(a.end)) {
		a.mu.Unlock()
		return ErrAuthentication
	}
	a.callbacks++
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.callbacks--; a.settled.Broadcast(); a.mu.Unlock() }()
	return fn()
}
func (a *OwnerContextAuthoring) draft() error {
	var v TemplateDraftState
	e := a.host(func() error { var e error; v, e = a.options.Draft(a.ctx); return e })
	if e != nil {
		return e
	}
	a.mu.Lock()
	valid := v.Epoch == a.epoch && v.Revision == a.revision && v.CustodyLive
	a.mu.Unlock()
	if !valid {
		a.Close()
		return ErrAuthentication
	}
	return a.live()
}
func (a *OwnerContextAuthoring) current(_ context.Context) (out OwnerTemplateAuthority, err error) {
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	if err = a.draft(); err != nil {
		return
	}
	start := time.Now()
	var c ContextAuthoringCurrent
	if err = a.host(func() error {
		var e error
		c, e = a.options.Current(a.ctx)
		if e == nil && c.Manifest != nil {
			m := *c.Manifest
			m.raw = append([]byte(nil), m.raw...)
			m.lineage = append([][32]byte(nil), m.lineage...)
			c.Manifest = &m
		}
		return e
	}); err != nil {
		return
	}
	if err = a.live(); err != nil {
		return
	}
	m := c.Manifest
	b := a.options.Binding
	a.mu.Lock()
	nowFloor := a.now
	end := a.end
	a.mu.Unlock()
	if c.Binding != b || !c.OwnerSessionLive || !c.ConsentLive || c.Now == 0 || c.Now < nowFloor || m == nil || m.profile != 2 || m.account != b.Account || !manifestWindow(m.issued, m.expires, c.Now) || c.Now < m.comparison || a.options.Expires <= c.Now || a.options.Expires-c.Now > 30*86400000 {
		return out, ErrAuthentication
	}
	phone := manifestKey(m, 1, b.PhoneReader[:])
	reader := manifestKey(m, 2, b.ArchiveReader[:])
	var signer []byte
	for i := 0; i < int(m.raw[150]); i++ {
		w := m.raw[151+i*149 : 151+(i+1)*149]
		if w[0] == 4 && activeKey(w, c.Now, 2) && binary.BigEndian.Uint16(w[130:132]) == 2 && bytes.Equal(w[98:114], b.Device[:]) && bytes.Equal(w[114:130], b.Line[:]) {
			signer = w
			break
		}
	}
	if !activeKey(phone, c.Now, 0) || !bytes.Equal(phone[98:114], b.Device[:]) || !bytes.Equal(phone[114:130], b.Line[:]) || !activeKey(reader, c.Now, 8) || signer == nil {
		return out, ErrAuthentication
	}
	expires := min(m.expires, a.options.Expires, binary.BigEndian.Uint64(phone[140:148]), binary.BigEndian.Uint64(reader[140:148]), binary.BigEndian.Uint64(signer[140:148]))
	next := start.Add(time.Duration(min(expires-c.Now, uint64(a.options.Observation/time.Millisecond))) * time.Millisecond)
	if end.Before(next) {
		next = end
	}
	if err = a.cap(next); err != nil {
		return
	}
	a.mu.Lock()
	a.now = c.Now
	a.mu.Unlock()
	if err = a.draft(); err != nil {
		return
	}
	valid := time.Until(next).Truncate(time.Millisecond)
	if valid < time.Millisecond {
		return out, ErrAuthentication
	}
	return OwnerTemplateAuthority{Binding: b, Manifest: m, Now: c.Now, OwnerSessionLive: true, ConsentLive: true, Active: true, ValidFor: valid}, nil
}
func (a *OwnerContextAuthoring) session(_ context.Context) (v OwnerSession, err error) {
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	err = a.host(func() error { var e error; v, e = a.options.Session(a.ctx); return e })
	if err != nil {
		return
	}
	if err = a.live(); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !v.valid(a.options.Origin) || (a.credentials != nil && v != *a.credentials) {
		return v, ErrAuthentication
	}
	copy := v
	a.credentials = &copy
	return
}
func (a *OwnerContextAuthoring) review(_ context.Context, v ContextWriteReview) error {
	if e := a.draft(); e != nil {
		return e
	}
	a.mu.Lock()
	scope := a.scope
	text := a.text
	valid := v.RequestID == a.request && v.ContextID == contextUUID(a.options.Context) && v.Revision == 1 && v.ExpectedRevision == 0 && v.EnvelopeDigest == a.digest && v.Scope == scope
	a.phase = "review"
	epoch, revision := a.epoch, a.revision
	a.mu.Unlock()
	if !valid {
		return ErrAuthentication
	}
	var accepted bool
	e := a.host(func() error {
		var e error
		accepted, e = a.options.Review(a.ctx, ContextAuthoringReview{v, text, contextUUID(a.options.Binding.Account), contextUUID(a.options.Binding.Line), a.options.Binding.Peer, a.options.Expires, epoch, revision})
		return e
	})
	if e != nil || !accepted {
		return ErrAuthentication
	}
	if e = a.draft(); e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrAuthentication
	}
	a.phase = "saving"
	return nil
}
func (a *OwnerContextAuthoring) retain(r ContextReceipt) error {
	if e := a.live(); e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || !r.RequestAcknowledged || r.RequestID != a.request || r.ContextID != contextUUID(a.options.Context) || r.Revision != 1 || r.EnvelopeDigest != a.digest {
		return ErrAuthentication
	}
	a.saved = &AcknowledgedContextSource{contextUUID(a.options.Binding.Account), r}
	a.pending = nil
	a.ticket = nil
	a.text = ""
	a.phase = "saved"
	if a.timer != nil {
		a.timer.Stop()
	}
	return nil
}
func (a *OwnerContextAuthoring) outcome() {
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	var p *ContextPending
	if c != nil {
		p = c.Pending()
	}
	a.mu.Lock()
	a.saved = nil
	a.text = ""
	if p != nil {
		a.pending = p
	}
	closed := a.closed
	pending := a.pending != nil
	if closed {
		a.phase = "closed"
	} else if pending {
		a.phase = "unknown"
	} else {
		a.phase = "refused"
	}
	a.mu.Unlock()
	if !closed && !pending {
		a.Close()
		a.mu.Lock()
		a.phase = "refused"
		a.mu.Unlock()
	}
}
func (a *OwnerContextAuthoring) operation(ctx context.Context, phase string, run func() error) ContextAuthoringState {
	if ctx == nil {
		return a.State()
	}
	a.mu.Lock()
	if a.closed || a.busy || a.phase != phase {
		a.mu.Unlock()
		return a.State()
	}
	select {
	case contextAuthors <- struct{}{}:
	default:
		a.mu.Unlock()
		return a.State()
	}
	a.busy = true
	if phase == "editing" {
		a.phase = "preparing"
		a.end = time.Now().Add(a.options.Timeout)
	} else {
		a.phase = "saving"
	}
	a.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if e := run(); e != nil {
			a.outcome()
		}
		a.mu.Lock()
		for a.callbacks > 0 {
			a.settled.Wait()
		}
		a.mu.Unlock()
		<-contextAuthors
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	defer func() { go func() { <-done; a.mu.Lock(); a.busy = false; a.mu.Unlock() }() }()
	for {
		select {
		case <-done:
			return a.State()
		case <-ctx.Done():
			a.Close()
			return a.State()
		case <-ticker.C:
			if a.live() != nil {
				return a.State()
			}
		}
	}
}
func (a *OwnerContextAuthoring) Author(ctx context.Context, text string, epoch, revision uint64) ContextAuthoringState {
	return a.operation(ctx, "editing", func() error {
		a.mu.Lock()
		end := a.end
		a.mu.Unlock()
		if e := a.cap(end); e != nil {
			return e
		}
		if epoch == 0 || revision == 0 || len(text) < 1 || len(text) > 32768 || !utf8.ValidString(text) {
			return ErrShape
		}
		content := []byte(text)
		defer clear(content)
		a.mu.Lock()
		a.text = text
		a.epoch = epoch
		a.revision = revision
		a.mu.Unlock()
		c, e := a.current(a.ctx)
		if e != nil {
			return e
		}
		b := a.options.Binding
		m := c.Manifest
		scope := WorkflowContextScope{Kind: 1, Account: b.Account, Device: b.Device, Line: b.Line, Interval: b.Interval, Context: a.options.Context, BindingGeneration: b.Generation, Revision: 1, Expires: a.options.Expires, TrustGeneration: m.generation, ManifestVersion: m.version, PeerDigest: sha256.Sum256([]byte(b.Peer)), Reader: b.ArchiveReader, ManifestDigest: m.digest}
		wire, e := SealWorkflowContext(m, scope, OwnerContextReader, c.Now, content)
		if e != nil {
			return e
		}
		defer clear(wire)
		clear(content)
		if e = a.draft(); e != nil {
			return e
		}
		var id [16]byte
		if _, e = rand.Read(id[:]); e != nil {
			return e
		}
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		digest := sha256.Sum256(wire)
		a.mu.Lock()
		a.scope = scope
		a.request = contextUUID(id)
		a.digest = hex.EncodeToString(digest[:])
		timeout := time.Until(a.end)
		a.mu.Unlock()
		if timeout < time.Millisecond {
			return ErrAuthentication
		}
		client, e := NewOwnerWorkflowContextClient(OwnerContextOptions{Origin: a.options.Origin, Binding: b, Context: a.options.Context, Kind: 1, Enabled: true, Timeout: timeout, AdditionalRootsPEM: a.options.AdditionalRootsPEM, Current: a.current, Session: a.session, Review: a.review})
		if e != nil {
			return e
		}
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			client.Close()
			return ErrAuthentication
		}
		a.client = client
		request := a.request
		a.mu.Unlock()
		t, e := client.Prepare(a.ctx, request, 0, scope, wire)
		if e != nil {
			return e
		}
		if e = a.draft(); e != nil {
			return e
		}
		a.mu.Lock()
		a.ticket = t
		a.posts++
		a.mu.Unlock()
		receipt, e := client.Commit(a.ctx, t)
		if e != nil {
			return e
		}
		if e = a.draft(); e != nil {
			return e
		}
		return a.retain(receipt)
	})
}
func (a *OwnerContextAuthoring) reconcile(ctx context.Context, retry bool) ContextAuthoringState {
	return a.operation(ctx, "unknown", func() error {
		if e := a.draft(); e != nil {
			return e
		}
		a.mu.Lock()
		client, t := a.client, a.ticket
		limit := a.checks
		if retry {
			limit = a.posts
		}
		if limit >= 3 {
			a.phase = "unknown"
			a.mu.Unlock()
			return nil
		}
		if retry {
			a.posts++
		} else {
			a.checks++
		}
		a.mu.Unlock()
		if client == nil || t == nil {
			return ErrAuthentication
		}
		var r ContextReceipt
		var e error
		if retry {
			r, e = client.RetryUnknown(a.ctx, t)
		} else {
			r, e = client.VerifyUnknown(a.ctx, t)
		}
		if e != nil {
			return e
		}
		if e = a.draft(); e != nil {
			return e
		}
		if !r.RequestAcknowledged {
			a.mu.Lock()
			if !a.closed {
				a.phase = "unknown"
			}
			a.mu.Unlock()
			return nil
		}
		return a.retain(r)
	})
}
func (a *OwnerContextAuthoring) RetryUnknown(ctx context.Context) ContextAuthoringState {
	return a.reconcile(ctx, true)
}
func (a *OwnerContextAuthoring) VerifyUnknown(ctx context.Context) ContextAuthoringState {
	return a.reconcile(ctx, false)
}

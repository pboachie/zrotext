package hpke

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type OwnerTemplateError struct {
	Code    string
	Unknown bool
}

func (e OwnerTemplateError) Error() string { return "owner template " + e.Code }

var ownerTemplateAdmission = make(chan struct{}, 8)

// OwnerBinding is independently authenticated conversation/session selection.
// PhoneReader participates in binding equality, not template decryption.
type OwnerBinding struct {
	Account, Device, Line, Interval, Session [16]byte
	Generation                               uint64
	Peer                                     string
	PhoneReader, ArchiveReader               [32]byte
}

func (b OwnerBinding) valid() bool {
	for _, id := range [][16]byte{b.Account, b.Device, b.Line, b.Interval, b.Session} {
		if id == [16]byte{} {
			return false
		}
	}
	if b.Generation == 0 || b.Generation > 0x7fffffffffffffff || b.PhoneReader == [32]byte{} || b.ArchiveReader == [32]byte{} || len(b.Peer) < 3 || len(b.Peer) > 16 || b.Peer[0] != '+' || b.Peer[1] < '1' || b.Peer[1] > '9' {
		return false
	}
	for _, c := range b.Peer[2:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type OwnerTemplateAuthority struct {
	Binding                               OwnerBinding
	Manifest                              *Manifest
	Now                                   uint64
	ValidFor                              time.Duration
	OwnerSessionLive, ConsentLive, Active bool
}

// OwnerSession must come from an independent trusted host. No browser cookie
// extraction or login is performed; response cookies are never retained.
type OwnerSession struct{ Origin, Cookie, CSRF string }

func (s OwnerSession) valid(origin string) bool {
	if s.Origin != origin || len(s.Cookie) < 1 || len(s.Cookie) > 4096 || !strings.Contains(s.Cookie, "=") || len(s.CSRF) < 1 || len(s.CSRF) > 256 {
		return false
	}
	for _, c := range s.Cookie {
		if c < 32 || c > 126 {
			return false
		}
	}
	for _, c := range s.CSRF {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

type OwnerTemplateOptions struct {
	Origin             string
	Binding            OwnerBinding
	Template           [16]byte
	Enabled            bool
	Timeout            time.Duration
	AdditionalRootsPEM []byte
	Current            func(context.Context) (OwnerTemplateAuthority, error)
	Session            func(context.Context) (OwnerSession, error)
}

// OwnerTemplateSnapshot is opaque current ciphertext. It never acknowledges a
// saved request, decrypts content, or grants approval/send authority.
type OwnerTemplateSnapshot struct {
	scope          EncryptedTemplateScope
	wire           []byte
	digest         [32]byte
	matchesPending bool
}

func (s *OwnerTemplateSnapshot) Scope() EncryptedTemplateScope { return s.scope }
func (s *OwnerTemplateSnapshot) Envelope() []byte              { return append([]byte(nil), s.wire...) }
func (s *OwnerTemplateSnapshot) EncryptedDigest() string       { return hex.EncodeToString(s.digest[:]) }
func (s *OwnerTemplateSnapshot) RequestAcknowledged() bool     { return false }
func (s *OwnerTemplateSnapshot) MatchesPending() bool          { return s.matchesPending }

// OwnerTemplateReader is a cold readLatest client. Callbacks must not reenter
// it. A stalled callback retains admission until it actually settles, even
// after the foreground deadline has refused and closed the instance.
type OwnerTemplateReader struct {
	options      OwnerTemplateOptions
	client       *http.Client
	closed, busy atomic.Bool
	mu           sync.Mutex
	cancel       context.CancelFunc
	lifetime     time.Time
	prior        *Manifest
	now, head    uint64
	headDigest   [32]byte
}

func NewOwnerTemplateReader(o OwnerTemplateOptions) (*OwnerTemplateReader, error) {
	bad := OwnerTemplateError{Code: "invalid_request"}
	if !o.Binding.valid() || o.Template == [16]byte{} || o.Current == nil || o.Session == nil {
		return nil, bad
	}
	u, e := url.Parse(o.Origin)
	if e != nil || u.Scheme+"://"+u.Host != o.Origin || u.Host != strings.ToLower(u.Host) || strings.Contains(u.Host, "@") {
		return nil, bad
	}
	transport, e := NewOriginalHTTP(o.Origin, o.Timeout, o.AdditionalRootsPEM)
	if e != nil {
		return nil, bad
	}
	o.AdditionalRootsPEM = nil
	c := &OwnerTemplateReader{options: o, client: transport.client}
	if !o.Enabled {
		c.closed.Store(true)
	}
	return c, nil
}
func (c *OwnerTemplateReader) Close() {
	if c == nil {
		return
	}
	c.closed.Store(true)
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
}

type ownerTemplateWork struct {
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func (w *ownerTemplateWork) end() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return w.deadline }
func (w *ownerTemplateWork) shorten(at time.Time) {
	w.mu.Lock()
	if at.Before(w.deadline) {
		w.deadline = at
		select {
		case w.changed <- struct{}{}:
		default:
		}
	}
	w.mu.Unlock()
}
func (c *OwnerTemplateReader) live(ctx context.Context, w *ownerTemplateWork) error {
	c.mu.Lock()
	lifetime := c.lifetime
	c.mu.Unlock()
	if !lifetime.IsZero() {
		w.shorten(lifetime)
	}
	if c.closed.Load() || ctx.Err() != nil {
		return OwnerTemplateError{Code: "closed"}
	}
	if !time.Now().Before(w.end()) {
		c.Close()
		return OwnerTemplateError{Code: "deadline"}
	}
	return nil
}
func (c *OwnerTemplateReader) credentials(ctx context.Context, w *ownerTemplateWork) (OwnerSession, error) {
	if e := c.live(ctx, w); e != nil {
		return OwnerSession{}, e
	}
	s, e := c.options.Session(ctx)
	if e != nil || !s.valid(c.options.Origin) {
		return OwnerSession{}, OwnerTemplateError{Code: "owner_changed"}
	}
	return s, c.live(ctx, w)
}
func (c *OwnerTemplateReader) authorize(ctx context.Context, w *ownerTemplateWork, scope *EncryptedTemplateScope, session OwnerSession) (err error) {
	defer func() {
		if err != nil {
			c.Close()
			err = OwnerTemplateError{Code: "owner_changed"}
		}
	}()
	if e := c.live(ctx, w); e != nil {
		return e
	}
	started := time.Now()
	a, e := c.options.Current(ctx)
	if e != nil {
		return e
	}
	if e = c.live(ctx, w); e != nil {
		return e
	}
	m := a.Manifest
	b := c.options.Binding
	if a.Binding != b || !a.OwnerSessionLive || !a.ConsentLive || !a.Active || a.Now == 0 || a.Now < c.now || a.ValidFor <= 0 || a.ValidFor > 60*time.Second || m == nil || m.profile != 2 || m.account != b.Account || !manifestWindow(m.issued, m.expires, a.Now) || a.Now < m.comparison {
		return ErrAuthentication
	}
	if p := c.prior; p != nil && (m.root != p.root || m.enrolled != p.enrolled || m.generation != p.generation || m.version < p.version || (m.version == p.version && m.digest != p.digest)) {
		return ErrAuthentication
	}
	reader := manifestKey(m, 2, b.ArchiveReader[:])
	if !activeKey(reader, a.Now, 8) {
		return ErrAuthentication
	}
	var phone []byte
	for i := 0; i < int(m.raw[150]); i++ {
		k := m.raw[151+i*149 : 151+(i+1)*149]
		if k[0] == 4 && activeKey(k, a.Now, 2) && string(k[98:114]) == string(b.Device[:]) && string(k[114:130]) == string(b.Line[:]) {
			phone = k
			break
		}
	}
	if phone == nil || binary.BigEndian.Uint16(phone[130:132]) != 2 {
		return ErrAuthentication
	}
	expiry := min(m.expires, binary.BigEndian.Uint64(reader[140:148]), binary.BigEndian.Uint64(phone[140:148]))
	if scope != nil {
		s := *scope
		if s.Account != b.Account || s.Device != b.Device || s.Line != b.Line || s.Interval != b.Interval || s.Template != c.options.Template || s.BindingGeneration != b.Generation || s.Reader != b.ArchiveReader || s.TrustGeneration != m.generation || s.ManifestVersion != m.version || s.ManifestDigest != m.digest || s.Expires <= a.Now || s.Expires-a.Now > 30*86400000 || s.PeerDigest != sha256.Sum256([]byte(b.Peer)) {
			return ErrAuthentication
		}
		expiry = min(expiry, s.Expires)
	}
	// Durations are bounded by current freshness before conversion to avoid overflow.
	remaining := min(expiry-a.Now, uint64(a.ValidFor/time.Millisecond))
	if remaining == 0 {
		return ErrAuthentication
	}
	w.shorten(started.Add(time.Duration(remaining) * time.Millisecond))
	fresh, e := c.credentials(ctx, w)
	if e != nil || fresh != session {
		return ErrAuthentication
	}
	if e = c.live(ctx, w); e != nil {
		return e
	}
	c.prior = m
	c.now = a.Now
	return nil
}
func (c *OwnerTemplateReader) read(ctx context.Context, w *ownerTemplateWork) (*OwnerTemplateSnapshot, error) {
	return c.readExpected(ctx, w, nil)
}
func (c *OwnerTemplateReader) readExpected(ctx context.Context, w *ownerTemplateWork, expected *OwnerSession) (*OwnerTemplateSnapshot, error) {
	session, e := c.credentials(ctx, w)
	if e != nil {
		return nil, e
	}
	if expected != nil && session != *expected {
		c.Close()
		return nil, OwnerTemplateError{Code: "owner_changed"}
	}
	if e = c.authorize(ctx, w, nil, session); e != nil {
		return nil, e
	}
	fresh, e := c.credentials(ctx, w)
	if e != nil || fresh != session {
		c.Close()
		return nil, OwnerTemplateError{Code: "owner_changed"}
	}
	id := hex.EncodeToString(c.options.Template[:])
	id = id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
	ctx, cancel := context.WithDeadline(ctx, w.end())
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", c.options.Origin+"/v1/owner/workflow/templates/"+id, nil)
	if e != nil {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	req.Header.Set("Accept", templateContentType)
	req.Header.Set("X-Zrotext-CSRF", session.CSRF)
	req.Header.Set("Cookie", session.Cookie)
	req.Header.Set("Cache-Control", "no-store")
	response, e := c.client.Do(req)
	if e != nil {
		return nil, OwnerTemplateError{Code: "read_refused"}
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, OwnerTemplateError{Code: "response_unknown", Unknown: true}
	}
	if response.StatusCode != 200 || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != templateContentType {
		if response.StatusCode == 401 || response.StatusCode == 403 {
			c.Close()
		}
		return nil, OwnerTemplateError{Code: "read_refused"}
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 33076))
	if e != nil || len(raw) > 33075 {
		return nil, OwnerTemplateError{Code: "response_unknown", Unknown: true}
	}
	if e = c.live(ctx, w); e != nil {
		return nil, e
	}
	scope, e := parseTemplateScope(raw)
	if e != nil {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	if scope.Revision < c.head {
		return nil, OwnerTemplateError{Code: "head_regressed"}
	}
	if e = c.authorize(ctx, w, &scope, session); e != nil {
		return nil, e
	}
	if _, e = ecdh.P256().NewPublicKey(raw[222:287]); e != nil {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	digest := sha256.Sum256(raw)
	if e = c.authorize(ctx, w, &scope, session); e != nil {
		return nil, e
	}
	if scope.Revision == c.head && digest != c.headDigest {
		return nil, OwnerTemplateError{Code: "head_changed"}
	}
	if e = c.live(ctx, w); e != nil {
		return nil, e
	}
	c.head = scope.Revision
	c.headDigest = digest
	return &OwnerTemplateSnapshot{scope: scope, wire: raw, digest: digest}, nil
}
func (c *OwnerTemplateReader) ReadLatest(ctx context.Context) (*OwnerTemplateSnapshot, error) {
	bad := OwnerTemplateError{Code: "read_refused"}
	if c == nil || ctx == nil {
		return nil, bad
	}
	if !c.busy.CompareAndSwap(false, true) {
		return nil, OwnerTemplateError{Code: "busy"}
	}
	select {
	case ownerTemplateAdmission <- struct{}{}:
	default:
		c.busy.Store(false)
		return nil, OwnerTemplateError{Code: "capacity"}
	}
	ctx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
	w := &ownerTemplateWork{deadline: time.Now().Add(c.options.Timeout), changed: make(chan struct{}, 1)}
	type result struct {
		snapshot *OwnerTemplateSnapshot
		err      error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { c.mu.Lock(); c.cancel = nil; c.mu.Unlock(); <-ownerTemplateAdmission; c.busy.Store(false) }()
		snapshot, e := c.read(ctx, w)
		done <- result{snapshot, e}
	}()
	for {
		timer := time.NewTimer(time.Until(w.end()))
		select {
		case r := <-done:
			timer.Stop()
			if r.err != nil {
				return nil, r.err
			}
			if c.closed.Load() {
				return nil, OwnerTemplateError{Code: "closed"}
			}
			if !time.Now().Before(w.end()) {
				c.Close()
				return nil, OwnerTemplateError{Code: "deadline"}
			}
			return r.snapshot, r.err
		case <-w.changed:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			c.Close()
			return nil, OwnerTemplateError{Code: "closed"}
		case <-timer.C:
			c.Close()
			return nil, OwnerTemplateError{Code: "deadline"}
		}
	}
}

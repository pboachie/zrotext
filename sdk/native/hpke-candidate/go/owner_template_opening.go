package hpke

import (
	"bytes"
	"context"
	"crypto/ecdh"
)

// TemplateOpenedPreview is local plaintext, never persistence/send authority.
// Returned strings have no secure-erasure guarantee.
type TemplateOpenedPreview struct {
	text, digest string
	segments     SegmentEstimate
	revision     uint64
	matches      bool
}

func (p *TemplateOpenedPreview) Text() string              { return p.text }
func (p *TemplateOpenedPreview) Segments() SegmentEstimate { return p.segments }
func (p *TemplateOpenedPreview) Revision() uint64          { return p.revision }
func (p *TemplateOpenedPreview) EncryptedDigest() string   { return p.digest }
func (p *TemplateOpenedPreview) MatchesPending() bool      { return p.matches }
func (p *TemplateOpenedPreview) RequestAcknowledged() bool { return false }

// OwnerTemplateOpening owns the dedicated client's close lifecycle, never the
// caller's protected key deletion. The host must invalidate on custody/UI change.
type OwnerTemplateOpening struct{ client, guard *OwnerTemplateClient }

func NewOwnerTemplateOpening(options OwnerTemplateOptions, client *OwnerTemplateClient) (*OwnerTemplateOpening, error) {
	if client == nil || client.reader == nil || client.reader.options.Origin != options.Origin || client.reader.options.Binding != options.Binding || client.reader.options.Template != options.Template {
		if client != nil && client.reader != nil {
			client.Close()
		}
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	guard, e := NewOwnerTemplateClient(options, func(context.Context, TemplateCiphertextReview) error { return ErrAuthentication })
	if e != nil {
		client.Close()
		return nil, e
	}
	o := &OwnerTemplateOpening{client, guard}
	if !options.Enabled {
		o.Close()
	}
	return o, nil
}
func (o *OwnerTemplateOpening) Close() {
	if o != nil {
		o.guard.Close()
		o.client.Close()
	}
}
func (o *OwnerTemplateOpening) Invalidate() { o.Close() }
func (o *OwnerTemplateOpening) open(ctx context.Context, point func() ([]byte, error), decrypt func(*Manifest, EncryptedTemplateScope, uint64, []byte) (*TemplateContent, error), cleanup func()) (*TemplateOpenedPreview, error) {
	if o == nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	result, e := o.guard.executeOwned(ctx, func(ctx context.Context, w *ownerTemplateWork) (out ownerSaveResult, err error) {
		defer func() {
			if err != nil {
				o.Close()
			}
		}()
		r := o.guard.reader
		if err = r.live(ctx, w); err != nil {
			return
		}
		public, e := point()
		if e != nil {
			return out, OwnerTemplateError{Code: "refused"}
		}
		public = append([]byte(nil), public...)
		if _, e = ecdh.P256().NewPublicKey(public); e != nil {
			return out, OwnerTemplateError{Code: "refused"}
		}
		session, e := r.credentials(ctx, w)
		if e != nil {
			return out, e
		}
		if err = r.authorize(ctx, w, nil, session); err != nil {
			return
		}
		selected := manifestKey(r.prior, 2, r.options.Binding.ArchiveReader[:])
		if selected == nil || !bytes.Equal(public, selected[33:98]) {
			return out, OwnerTemplateError{Code: "refused"}
		}
		// Concrete private-branded client, not a replaceable transport interface.
		snapshot, e := o.client.ReadLatest(ctx)
		if e != nil {
			return out, OwnerTemplateError{Code: "refused"}
		}
		if err = r.live(ctx, w); err != nil {
			return
		}
		scope := snapshot.Scope()
		wire := snapshot.Envelope()
		defer clear(wire)
		if err = r.authorize(ctx, w, &scope, session); err != nil {
			return
		}
		content, e := decrypt(r.prior, scope, r.now, wire)
		if e != nil {
			return out, OwnerTemplateError{Code: "refused"}
		}
		livePoint := func() error {
			if o.client.reader.closed.Load() {
				return OwnerTemplateError{Code: "closed"}
			}
			if e := r.live(ctx, w); e != nil {
				return e
			}
			p, e := point()
			if e != nil || !bytes.Equal(p, public) {
				return OwnerTemplateError{Code: "refused"}
			}
			return r.live(ctx, w)
		}
		if err = livePoint(); err != nil {
			return
		}
		if err = r.authorize(ctx, w, &scope, session); err != nil {
			return
		}
		text, segments, e := content.Preview()
		if e != nil {
			return out, OwnerTemplateError{Code: "refused"}
		}
		if err = r.authorize(ctx, w, &scope, session); err != nil {
			return
		}
		if err = livePoint(); err != nil {
			return
		}
		out.value = &TemplateOpenedPreview{text, snapshot.EncryptedDigest(), segments, scope.Revision, snapshot.MatchesPending()}
		return
	}, cleanup)
	if e == nil && o.client.reader.closed.Load() {
		e = OwnerTemplateError{Code: "closed"}
	}
	if e != nil {
		o.Close()
		return nil, e
	}
	return result.value.(*TemplateOpenedPreview), nil
}

// OpenLatestSoftware is explicitly candidate software custody, never protected.
func (o *OwnerTemplateOpening) OpenLatestSoftware(ctx context.Context, scalar []byte) (*TemplateOpenedPreview, error) {
	if len(scalar) != 32 {
		return nil, OwnerTemplateError{Code: "invalid_request"}
	}
	owned := append([]byte(nil), scalar...)
	return o.open(ctx, func() ([]byte, error) {
		key, e := ecdh.P256().NewPrivateKey(owned)
		if e != nil {
			return nil, e
		}
		return key.PublicKey().Bytes(), nil
	}, func(m *Manifest, s EncryptedTemplateScope, now uint64, wire []byte) (*TemplateContent, error) {
		return OpenSoftwareEncryptedTemplate(m, s, now, owned, wire)
	}, func() { clear(owned) })
}

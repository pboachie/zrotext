//go:build windows

package hpke

import (
	"bytes"
	"context"
	"crypto/sha256"
)

const contactRootPrefix = "zrotext-candidate-contact-root-"

// ContactRootSigner is a dedicated qualified PCP contact-field capability.
// It cannot sign envelopes, manifests, reader statements or arbitrary domains.
// Do not copy after first use. The caller owns close and exact created-key deletion.
type ContactRootSigner struct{ signer *HardwareSigner }

func CreateContactRootSigner(receipt func(string) error) (*ContactRootSigner, error) {
	s, e := createHardwareSignerPrefix(receipt, contactRootPrefix)
	if e != nil {
		return nil, e
	}
	return &ContactRootSigner{signer: s}, nil
}
func OpenContactRootSigner(alias string, expected []byte) (*ContactRootSigner, error) {
	s, e := openHardwareSignerPrefix(alias, expected, contactRootPrefix)
	if e != nil {
		return nil, e
	}
	return &ContactRootSigner{signer: s}, nil
}
func (s *ContactRootSigner) PublicPoint() ([]byte, error) {
	if s == nil || s.signer == nil {
		return nil, ErrProtectedUnavailable
	}
	return s.signer.PublicPoint()
}
func (s *ContactRootSigner) Alias() string {
	if s == nil || s.signer == nil {
		return ""
	}
	return s.signer.Alias()
}
func (s *ContactRootSigner) Close() {
	if s != nil && s.signer != nil {
		s.signer.Close()
	}
}
func (s *ContactRootSigner) DeleteCreated() error {
	if s == nil || s.signer == nil {
		return ErrProtectedUnavailable
	}
	return s.signer.DeleteCreated()
}

func ProduceProtectedContactField01(ctx context.Context, signer *ContactRootSigner, st *ContactStatement, e ContactExpected, f ContactFieldInput) (*ContactProduction, error) {
	unsigned, err := contactUnsigned(st, e, f)
	if err != nil {
		return nil, err
	}
	if signer == nil || signer.signer == nil || signer.signer.native == nil {
		return nil, ErrProtectedUnavailable
	}
	return contactProduce(ctx, st, e, unsigned, func(limited context.Context) ([]byte, error) {
		s := signer.signer
		r := s.native
		r.mu.Lock()
		defer r.mu.Unlock()
		if limited.Err() != nil || !r.qualified || r.closed {
			return nil, ErrProtectedUnavailable
		}
		point, err := r.publicMagic(0x31534345)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(point, st.rootPoint[:]) {
			return nil, ErrAuthentication
		}
		if limited.Err() != nil {
			return nil, ErrShape
		}
		digest := sha256.Sum256(contactTranscript(contactFieldDomain, unsigned))
		sig, err := s.signDigest(digest[:])
		if err != nil {
			return nil, err
		}
		if err = verifySignature(point, digest[:], sig); err != nil {
			return nil, err
		}
		return sig, nil
	}, func() {})
}

package hpke

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"
)

var contactAdmission = make(chan struct{}, 4)

// ContactProduction is historical ciphertext integrity only. The caller owns
// explicit review, persistence, submission, and any subsequent authority checks.
type ContactProduction struct{ field *ContactField }

func (p *ContactProduction) Bytes() []byte {
	if p == nil {
		return nil
	}
	return p.field.Bytes()
}
func (p *ContactProduction) Verified() *ContactField {
	if p == nil {
		return nil
	}
	return p.field
}

// ProduceSoftwareContactField01 is the explicit exportable software-key lane.
// The protected lane uses a separate concrete qualified provider capability.
func ProduceSoftwareContactField01(ctx context.Context, scalar []byte, st *ContactStatement, e ContactExpected, f ContactFieldInput) (*ContactProduction, error) {
	unsigned, err := contactUnsigned(st, e, f)
	if err != nil {
		return nil, err
	}
	if len(scalar) != 32 {
		return nil, ErrShape
	}
	owned := append([]byte(nil), scalar...)
	d := new(big.Int).SetBytes(owned)
	if d.Sign() <= 0 || d.Cmp(elliptic.P256().Params().N) >= 0 {
		clear(owned)
		return nil, ErrShape
	}
	x, y := elliptic.P256().ScalarBaseMult(owned)
	if !bytes.Equal(elliptic.Marshal(elliptic.P256(), x, y), st.rootPoint[:]) {
		clear(owned)
		return nil, ErrAuthentication
	}
	return contactProduce(ctx, st, e, unsigned, func(limited context.Context) ([]byte, error) {
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), owned)
		if err != nil {
			return nil, ErrShape
		}
		digest := sha256.Sum256(contactTranscript(contactFieldDomain, unsigned))
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			return nil, err
		}
		n := elliptic.P256().Params().N
		if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
			s.Sub(n, s)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}, func() { clear(owned) })
}

// cleanup belongs to the admitted worker until actual settlement, including
// after caller cancellation. Non-admitted callers release it immediately.
func contactProduce(ctx context.Context, st *ContactStatement, e ContactExpected, unsigned []byte, sign func(limited context.Context) ([]byte, error), cleanup func()) (*ContactProduction, error) {
	if ctx == nil || ctx.Err() != nil {
		cleanup()
		return nil, ErrShape
	}
	select {
	case contactAdmission <- struct{}{}:
	default:
		cleanup()
		return nil, ErrShape
	}
	// Independent byte snapshots are captured before starting concurrent work.
	expected := ContactExpected{Account: append([]byte(nil), e.Account...), Origin: e.Origin, RootFingerprint: append([]byte(nil), e.RootFingerprint...), Contact: append([]byte(nil), e.Contact...), RoutingDigest: append([]byte(nil), e.RoutingDigest...)}
	limited, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type result struct {
		p *ContactProduction
		e error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { cleanup(); <-contactAdmission }()
		if limited.Err() != nil {
			done <- result{e: ErrShape}
			return
		}
		sig, err := sign(limited)
		if err != nil {
			done <- result{e: err}
			return
		}
		if limited.Err() != nil {
			done <- result{e: ErrShape}
			return
		}
		field, err := VerifyContactField01(append(append([]byte(nil), unsigned...), sig...), st, expected)
		if err != nil {
			done <- result{e: err}
			return
		}
		done <- result{p: &ContactProduction{field: field}}
	}()
	select {
	case <-limited.Done():
		return nil, ErrShape
	case out := <-done:
		if limited.Err() != nil {
			return nil, ErrShape
		}
		return out.p, out.e
	}
}

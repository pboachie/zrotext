package hpke

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// ContactMutationProduction is an unsubmitted historical transition. The caller
// must independently review, persist and reconcile any subsequent effects.
type ContactMutationProduction struct{ transition *ContactTransition }

func (p *ContactMutationProduction) Bytes() []byte {
	if p == nil {
		return nil
	}
	return p.transition.mutation.Bytes()
}
func (p *ContactMutationProduction) Verified() *ContactTransition {
	if p == nil {
		return nil
	}
	return p.transition
}

func contactMutationPlan(st *ContactStatement, e ContactExpected, m ContactMutationInput, legacy uint64, previous *ContactTransition, previousStatement *ContactStatement, replacements []*ContactField) ([]byte, error) {
	unsigned, err := contactMutationUnsigned(st, e, m, legacy)
	if err != nil {
		return nil, err
	}
	if previous == nil {
		if previousStatement != nil {
			return nil, ErrShape
		}
	} else {
		if previous.mutation == nil || !contactExpected(previousStatement, e) || !bytes.Equal(previous.mutation.statement.raw, previousStatement.raw) {
			return nil, ErrAuthentication
		}
	}
	// Private unsigned preview is never returned as a verified token. Validate
	// every transition relation before invoking either signing provider.
	preview := &ContactMutation{raw: append(append([]byte(nil), unsigned...), make([]byte, 64)...), statement: st, input: m}
	if _, err = contactTransitionFields(previous, preview, replacements); err != nil {
		return nil, err
	}
	return unsigned, nil
}
func contactProduceMutation(ctx context.Context, st *ContactStatement, e ContactExpected, legacy uint64, previous *ContactTransition, replacements []*ContactField, unsigned []byte, sign func(context.Context) ([]byte, error), cleanup func()) (*ContactMutationProduction, error) {
	expected := ContactExpected{Account: append([]byte(nil), e.Account...), Origin: e.Origin, RootFingerprint: append([]byte(nil), e.RootFingerprint...), Contact: append([]byte(nil), e.Contact...), RoutingDigest: append([]byte(nil), e.RoutingDigest...)}
	fields := append([]*ContactField(nil), replacements...)
	return contactExecute(ctx, sign, cleanup, func(sig []byte) (*ContactMutationProduction, error) {
		next, err := VerifyContactMutation01(append(append([]byte(nil), unsigned...), sig...), st, expected, legacy)
		if err != nil {
			return nil, err
		}
		transition, err := VerifyContactTransition01(previous, next, fields)
		if err != nil {
			return nil, err
		}
		return &ContactMutationProduction{transition: transition}, nil
	})
}
func ProduceSoftwareContactMutation01(ctx context.Context, scalar []byte, st *ContactStatement, e ContactExpected, m ContactMutationInput, legacy uint64, previous *ContactTransition, previousStatement *ContactStatement, replacements []*ContactField) (*ContactMutationProduction, error) {
	unsigned, err := contactMutationPlan(st, e, m, legacy, previous, previousStatement, replacements)
	if err != nil {
		return nil, err
	}
	if len(scalar) != 32 {
		return nil, ErrShape
	}
	owned := append([]byte(nil), scalar...)
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), owned)
	if err != nil {
		clear(owned)
		return nil, ErrShape
	}
	if !bytes.Equal(elliptic.Marshal(elliptic.P256(), k.X, k.Y), st.rootPoint[:]) {
		clear(owned)
		return nil, ErrAuthentication
	}
	return contactProduceMutation(ctx, st, e, legacy, previous, replacements, unsigned, func(context.Context) ([]byte, error) {
		h := sha256.Sum256(contactTranscript(contactMutationDomain, unsigned))
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
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

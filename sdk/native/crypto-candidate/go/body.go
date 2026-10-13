// Package candidatebody provides an experimental symmetric body primitive.
// It never verifies envelopes, manifests, routing, expiry or replay authority.
package candidatebody

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"unicode/utf8"
)

var (
	ErrShape          = errors.New("shape")
	ErrAuthentication = errors.New("authentication")
	ErrLength         = errors.New("length")
	ErrNul            = errors.New("nul")
	ErrBom            = errors.New("bom")
	ErrUtf8           = errors.New("utf8")
)

// Decode checks plaintext only and grants no authority or authentication.
func Decode(raw []byte) (string, error) {
	if len(raw) < 1 || len(raw) > 32768 {
		return "", ErrLength
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return "", ErrNul
	}
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return "", ErrBom
	}
	if !utf8.Valid(raw) {
		return "", ErrUtf8
	}
	return string(raw), nil
}

// Open authenticates before decoding/returning plaintext. Caller must verify
// independent envelope authority and recover the authorized key first. AAD must
// be the exact verified transcript. Caller key and returned string are not wiped;
// clearing our working buffer is not a secure-memory guarantee.
func Open(key, nonce, verifiedAAD, ciphertext []byte) (string, error) {
	if len(key) != 32 || len(nonce) != 12 || len(verifiedAAD) < 1 || len(verifiedAAD) > 36864 || len(ciphertext) < 17 || len(ciphertext) > 32784 {
		return "", ErrShape
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrShape
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrShape
	}
	raw, err := aead.Open(nil, nonce, ciphertext, verifiedAAD)
	if err != nil {
		return "", ErrAuthentication
	}
	defer clear(raw)
	return Decode(raw)
}

// Package hpke provides candidate RFC9180 base-mode recipient opening only.
// Software keys are explicitly exportable; this is not protected custody.
package hpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

var ErrShape = errors.New("hpke shape")
var ErrAuthentication = errors.New("hpke authentication")
var ErrProtectedUnavailable = errors.New("protected HPKE provider unavailable")
var kemSuite = []byte{'K', 'E', 'M', 0, 16}
var suite = []byte{'H', 'P', 'K', 'E', 0, 16, 0, 1, 0, 1}

func join(parts ...[]byte) []byte {
	var result []byte
	for _, p := range parts {
		result = append(result, p...)
	}
	return result
}
func extract(salt, suite []byte, label string, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(join([]byte("HPKE-v1"), suite, []byte(label), ikm))
	return m.Sum(nil)
}

// All selected suite outputs fit one SHA256 HKDF block.
func expand(prk, suite []byte, label string, info []byte, n int) []byte {
	m := hmac.New(sha256.New, prk)
	m.Write(join([]byte{byte(n >> 8), byte(n)}, []byte("HPKE-v1"), suite, []byte(label), info, []byte{1}))
	return m.Sum(nil)[:n]
}

// OpenSoftwareCEK opens exactly one 32-byte content key, sequence zero. It does
// not authorize the transcript, establish trust or enforce a replay journal.
func OpenSoftwareCEK(private, public, enc, info, aad, ciphertext []byte) ([]byte, error) {
	if len(private) != 32 || len(public) != 65 || public[0] != 4 || len(enc) != 65 || enc[0] != 4 || len(info) > 36864 || len(aad) > 36864 || len(ciphertext) != 48 {
		return nil, ErrShape
	}
	sk, e := ecdh.P256().NewPrivateKey(private)
	if e != nil {
		return nil, ErrShape
	}
	if !bytes.Equal(sk.PublicKey().Bytes(), public) {
		return nil, ErrShape
	}
	pk, e := ecdh.P256().NewPublicKey(enc)
	if e != nil {
		return nil, ErrShape
	}
	dh, e := sk.ECDH(pk)
	if e != nil {
		return nil, ErrAuthentication
	}
	defer clear(dh)
	eae := extract(nil, kemSuite, "eae_prk", dh)
	defer clear(eae)
	shared := expand(eae, kemSuite, "shared_secret", join(enc, public), 32)
	defer clear(shared)
	pskHash := extract(nil, suite, "psk_id_hash", nil)
	infoHash := extract(nil, suite, "info_hash", info)
	context := join([]byte{0}, pskHash, infoHash)
	schedule := extract(shared, suite, "secret", nil)
	defer clear(schedule)
	key := expand(schedule, suite, "key", context, 16)
	defer clear(key)
	nonce := expand(schedule, suite, "base_nonce", context, 12)
	defer clear(nonce)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrShape
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrShape
	}
	plain, e := gcm.Open(nil, nonce, ciphertext, aad)
	if e != nil {
		return nil, ErrAuthentication
	}
	return plain, nil
}

// OpenProtectedCEK deliberately refuses until a maintained protected provider
// exists. It never imports a scalar or falls back to OpenSoftwareCEK.
func OpenProtectedCEK() ([]byte, error) { return nil, ErrProtectedUnavailable }

package hpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"unicode/utf8"
)

// ElectedContext contains independent expected identity/routing and comparison time.
type ElectedContext struct {
	Message []byte
	Peer    string
	Now     uint64
}

// OpenSoftwareElected03 explicitly chooses exportable software custody; never a protected fallback.
func OpenSoftwareElected03(input []byte, m *Manifest, p *ElectionProof, current ElectionRecord, scalar []byte, context ElectedContext) (string, error) {
	return openElected03(input, m, p, current, context, func(public, enc, info, aad, ct []byte) ([]byte, error) {
		return OpenSoftwareCEK(scalar, public, enc, info, aad, ct)
	})
}
func openElected03(input []byte, m *Manifest, p *ElectionProof, current ElectionRecord, context ElectedContext, unwrap func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) (string, error) {
	c, err := RequireCurrentElection03(p, m, current, context.Now)
	if err != nil {
		return "", err
	}
	if len(input) < 426 || len(input) > 36864 || len(context.Message) != 16 || bytes.Equal(context.Message, make([]byte, 16)) {
		return "", ErrShape
	}
	b := append([]byte(nil), input...)
	now := context.Now
	if b[4] != 3 || b[5] != 1 || !bytes.Equal(b[10:26], c.Bytes["accountId"]) || !bytes.Equal(b[26:42], context.Message) || !bytes.Equal(b[42:58], c.Bytes["deviceId"]) || !bytes.Equal(b[58:74], c.Bytes["lineId"]) || binary.BigEndian.Uint64(b[74:82]) != m.version || !bytes.Equal(b[82:114], m.digest[:]) {
		return "", ErrAuthentication
	}
	observed := binary.BigEndian.Uint64(b[146:154])
	expires := binary.BigEndian.Uint64(b[154:162])
	if observed == 0 || observed > now || observed < m.issued || observed >= m.expires || expires <= now || expires > m.expires || expires > c.Numbers["permissionExpiresAtMs"] {
		return "", ErrAuthentication
	}
	signer := manifestKey(m, 5, b[114:146])
	if !activeKey(signer, now, 1) || !activeKey(signer, observed, 1) || expires > binary.BigEndian.Uint64(signer[140:148]) || !bytes.Equal(signer[114:130], c.Bytes["lineId"]) {
		return "", ErrAuthentication
	}
	e, err := VerifyEnvelope(b, signer[33:98], 3)
	if err != nil {
		return "", err
	}
	if string(b[164:e.prefix]) != context.Peer {
		return "", ErrAuthentication
	}
	selected := -1
	var reader, wrap []byte
	for i := 0; i < int(b[e.bodyEnd]); i++ {
		w := b[e.bodyEnd+1+i*146 : e.bodyEnd+1+(i+1)*146]
		k := manifestKey(m, w[0], w[1:33])
		if !activeKey(k, now, 4) || !activeKey(k, observed, 4) || expires > binary.BigEndian.Uint64(k[140:148]) {
			return "", ErrAuthentication
		}
		if w[0] == 1 {
			if !bytes.Equal(k[98:114], c.Bytes["deviceId"]) || !bytes.Equal(k[114:130], c.Bytes["lineId"]) {
				return "", ErrAuthentication
			}
			if bytes.Equal(w[1:33], c.Bytes["selectedReaderKeyId"]) {
				selected = i
				reader = k
				wrap = w
			}
		}
	}
	if selected < 0 {
		return "", ErrAuthentication
	}
	info, aad, err := e.WrapTranscript(selected)
	if err != nil {
		return "", err
	}
	cek, err := unwrap(reader[33:98], wrap[33:98], info, aad, wrap[98:])
	if err != nil {
		return "", err
	}
	defer clear(cek)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", ErrAuthentication
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrAuthentication
	}
	plain, err := gcm.Open(nil, b[e.prefix:e.prefix+12], b[e.prefix+16:e.bodyEnd], e.BodyAAD())
	if err != nil {
		return "", ErrAuthentication
	}
	defer clear(plain)
	if len(plain) < 1 || len(plain) > 32768 || !utf8.Valid(plain) || bytes.IndexByte(plain, 0) >= 0 || bytes.HasPrefix(plain, []byte{239, 187, 191}) {
		return "", ErrShape
	}
	return string(plain), nil
}

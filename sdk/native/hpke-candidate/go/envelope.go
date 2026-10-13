package hpke

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// IntegrityEnvelope proves syntax and a signature, not manifest authority.
// Its owned bytes cannot be changed through caller aliases.
type IntegrityEnvelope struct {
	data                         []byte
	prefix, bodyEnd, unsignedEnd int
}

// VerifyEnvelope validates candidate profile 02 (both kinds) or 03 (outbound).
// signer must be independently authorized before this token is used for effects.
func VerifyEnvelope(input, signer []byte, expectedProfile byte) (*IntegrityEnvelope, error) {
	if (expectedProfile != 2 && expectedProfile != 3) || len(input) < 426 || len(input) > 36864 || len(signer) != 65 || signer[0] != 4 {
		return nil, ErrShape
	}
	b := append([]byte(nil), input...)
	if b[4] != expectedProfile {
		return nil, ErrShape
	}
	if !bytes.Equal(b[:4], []byte("ZTSE")) || (b[4] != 2 && b[4] != 3) || (b[5] != 1 && b[5] != 2) || (b[4] == 3 && b[5] != 1) || b[6] != 0 || b[7] != 0 {
		return nil, ErrShape
	}
	kind := b[5]
	pl := int(binary.BigEndian.Uint16(b[8:10]))
	base := 154
	if kind == 2 {
		base = 169
		if len(b) > 34082 {
			return nil, ErrShape
		}
	}
	if pl < base+3 || pl > base+16 {
		return nil, ErrShape
	}
	end := 10 + pl
	p := b[10:end]
	if int(p[base-1])+base != pl {
		return nil, ErrShape
	}
	peer := p[base:]
	if peer[0] != '+' || peer[1] < '1' || peer[1] > '9' {
		return nil, ErrShape
	}
	for _, c := range peer[2:] {
		if c < '0' || c > '9' {
			return nil, ErrShape
		}
	}
	u64 := func(at int) (uint64, bool) {
		v := binary.BigEndian.Uint64(p[at : at+8])
		return v, v <= 0x7fffffffffffffff
	}
	_, ok := u64(64)
	if !ok {
		return nil, ErrShape
	}
	observed, ok := u64(136)
	if !ok {
		return nil, ErrShape
	}
	if kind == 1 {
		expiry, valid := u64(144)
		if !valid || expiry <= observed || expiry-observed > 900000 || p[152] != 1 {
			return nil, ErrShape
		}
	} else {
		seq, valid := u64(160)
		if !valid || seq == 0 || !bytes.Equal(p[16:32], p[144:160]) {
			return nil, ErrShape
		}
	}
	size := int(binary.BigEndian.Uint32(b[end+12 : end+16]))
	if size < 17 || size > 32784 {
		return nil, ErrShape
	}
	bodyEnd := end + 16 + size
	if bodyEnd >= len(b) {
		return nil, ErrShape
	}
	count := int(b[bodyEnd])
	low, high := 2, 8
	if kind == 2 {
		low, high = 1, 7
	}
	if count < low || count > high {
		return nil, ErrShape
	}
	unsigned := bodyEnd + 1 + count*146
	if unsigned+64 != len(b) {
		return nil, ErrShape
	}
	devices, archives := 0, 0
	var last []byte
	for i := 0; i < count; i++ {
		w := b[bodyEnd+1+i*146 : bodyEnd+1+(i+1)*146]
		if w[0] < 1 || w[0] > 3 || (last != nil && bytes.Compare(last, w[:33]) >= 0) {
			return nil, ErrShape
		}
		last = w[:33]
		if w[33] != 4 {
			return nil, ErrShape
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), w[33:98])
		if x == nil || y == nil {
			return nil, ErrShape
		}
		if w[0] == 1 {
			devices++
		}
		if w[0] == 2 {
			archives++
		}
	}
	expected := 1
	if kind == 2 {
		expected = 0
	}
	if devices != expected || archives != 1 {
		return nil, ErrShape
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), signer)
	if x == nil || y == nil {
		return nil, ErrShape
	}
	id := sha256.Sum256(append([]byte("ZTSE/key/v1\x00\x01\x01"), signer...))
	if !bytes.Equal(id[:], p[104:136]) {
		return nil, ErrAuthentication
	}
	r, s := new(big.Int).SetBytes(b[unsigned:unsigned+32]), new(big.Int).SetBytes(b[unsigned+32:])
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(half) > 0 {
		return nil, ErrAuthentication
	}
	domain := []byte("ZTSE/sign/v2\x00")
	if b[4] == 3 {
		domain = []byte("ZTSE/sign/v3\x00")
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(unsigned))
	transcript := append(append(domain, length...), b[:unsigned]...)
	digest := sha256.Sum256(transcript)
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s) {
		return nil, ErrAuthentication
	}
	return &IntegrityEnvelope{b, end, bodyEnd, unsigned}, nil
}
func (e *IntegrityEnvelope) UnsignedDigest() [32]byte { return sha256.Sum256(e.data[:e.unsignedEnd]) }
func (e *IntegrityEnvelope) BodyAAD() []byte {
	label := []byte("ZTSE/body/v2\x00")
	if e.data[4] == 3 {
		label = []byte("ZTSE/body/v3\x00")
	}
	return append(label, e.data[:e.prefix]...)
}

// WrapTranscript returns independent copies of info and AAD for a canonical wrap.
func (e *IntegrityEnvelope) WrapTranscript(index int) ([]byte, []byte, error) {
	count := int(e.data[e.bodyEnd])
	if index < 0 || index >= count {
		return nil, nil, ErrShape
	}
	w := e.data[e.bodyEnd+1+index*146 : e.bodyEnd+1+index*146+33]
	label := []byte("ZTSE/wrap/v2\x00")
	var aad []byte
	if e.data[4] == 3 {
		label = []byte("ZTSE/wrap/v3\x00")
		aad = append(append([]byte("ZTSE/wrap-aad/v3\x00"), e.data[:e.prefix]...), w...)
	}
	return append(append(label, e.data[:e.prefix]...), w...), aad, nil
}

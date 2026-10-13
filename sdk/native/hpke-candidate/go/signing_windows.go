//go:build windows

package hpke

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"unsafe"
)

const signerPrefix = "zrotext-candidate-sign-"

// HardwareSigner is a qualified PCP ECDSA handle. Do not copy after first use.
// No software import/fallback, arbitrary digest signing or remote attestation API.
type HardwareSigner struct {
	native  *HardwareRecipient
	created bool
}

func ProbeHardwareSigner() error {
	r, e := startHardwareAlgorithm("ECDSA_P256")
	if e == nil {
		r.Close()
	}
	return e
}
func CreateHardwareSigner(receipt func(string) error) (*HardwareSigner, error) {
	if receipt == nil {
		return nil, ErrShape
	}
	r, e := startHardwareAlgorithm("ECDSA_P256")
	if e != nil {
		return nil, e
	}
	s := &HardwareSigner{native: r}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		r.Close()
		return nil, e
	}
	r.name = signerPrefix + hex.EncodeToString(random[:])
	if e = receipt(r.name); e != nil {
		r.Close()
		return nil, e
	}
	e = r.api.call("NCryptCreatePersistedKey", r.provider, uintptr(unsafe.Pointer(&r.key)), uintptr(unsafe.Pointer(wide("ECDSA_P256"))), uintptr(unsafe.Pointer(wide(r.name))), 0, silent)
	s.created = e == nil
	if e == nil {
		var policy uint32
		e = r.api.call("NCryptSetProperty", r.key, uintptr(unsafe.Pointer(wide("Export Policy"))), uintptr(unsafe.Pointer(&policy)), 4, 0)
	}
	if e == nil {
		e = r.api.call("NCryptFinalizeKey", r.key, silent)
	}
	if e == nil {
		e = s.qualify()
	}
	if e != nil {
		if s.created && r.key != 0 {
			if cleanup := r.api.call("NCryptDeleteKey", r.key, 0); cleanup != nil {
				r.Close()
				return nil, cleanup
			}
			r.key = 0
		}
		r.Close()
		return nil, e
	}
	r.qualified = true
	return s, nil
}
func OpenHardwareSigner(name string, expected []byte) (*HardwareSigner, error) {
	suffix := strings.TrimPrefix(name, signerPrefix)
	v, e := hex.DecodeString(suffix)
	if e != nil || len(v) != 16 || name != signerPrefix+hex.EncodeToString(v) || len(expected) != 65 {
		return nil, ErrShape
	}
	if x, _ := elliptic.Unmarshal(elliptic.P256(), expected); x == nil {
		return nil, ErrShape
	}
	expected = append([]byte(nil), expected...)
	r, e := startHardwareAlgorithm("ECDSA_P256")
	if e != nil {
		return nil, e
	}
	s := &HardwareSigner{native: r}
	r.name = name
	e = r.api.call("NCryptOpenKey", r.provider, uintptr(unsafe.Pointer(&r.key)), uintptr(unsafe.Pointer(wide(name))), 0, silent)
	if e == nil {
		e = s.qualify()
	}
	if e == nil {
		var point []byte
		point, e = r.publicMagic(0x31534345)
		if e == nil && !bytes.Equal(point, expected) {
			e = ErrAuthentication
		}
	}
	if e != nil {
		r.Close()
		return nil, e
	}
	r.qualified = true
	return s, nil
}
func (s *HardwareSigner) qualify() error {
	r := s.native
	policy, e := r.api.property(r.key, "Export Policy")
	if e != nil {
		return e
	}
	if policy != 0 {
		return ErrProtectedUnavailable
	}
	var size uint32
	e = r.api.call("NCryptExportKey", r.key, 0, uintptr(unsafe.Pointer(wide("ECCPRIVATEBLOB"))), 0, 0, 0, uintptr(unsafe.Pointer(&size)), silent)
	status, ok := e.(*CustodyError)
	if !ok || (status.Status != 0x80090010 && status.Status != 0x8009000a) {
		return ErrProtectedUnavailable
	}
	point, e := r.publicMagic(0x31534345)
	if e != nil {
		return e
	}
	challenge := make([]byte, 32)
	if _, e = rand.Read(challenge); e != nil {
		return e
	}
	sig, e := s.signDigest(challenge)
	if e != nil {
		return e
	}
	return verifySignature(point, challenge, sig)
}
func verifySignature(point, digest, sig []byte) error {
	if len(point) != 65 || len(sig) != 64 {
		return ErrShape
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil || !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return ErrAuthentication
	}
	return nil
}
func (s *HardwareSigner) signDigest(digest []byte) ([]byte, error) {
	r := s.native
	if r.closed || r.key == 0 || len(digest) != 32 {
		return nil, ErrProtectedUnavailable
	}
	raw := make([]byte, 64)
	var size uint32
	if e := r.api.call("NCryptSignHash", r.key, 0, uintptr(unsafe.Pointer(&digest[0])), 32, uintptr(unsafe.Pointer(&raw[0])), 64, uintptr(unsafe.Pointer(&size)), silent); e != nil {
		return nil, e
	}
	if size != 64 {
		return nil, ErrShape
	}
	order := elliptic.P256().Params().N
	rr := new(big.Int).SetBytes(raw[:32])
	ss := new(big.Int).SetBytes(raw[32:])
	if rr.Sign() <= 0 || ss.Sign() <= 0 || rr.Cmp(order) >= 0 || ss.Cmp(order) >= 0 {
		return nil, ErrShape
	}
	if ss.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		ss.Sub(order, ss)
		ss.FillBytes(raw[32:])
	}
	return raw, nil
}
func (s *HardwareSigner) PublicPoint() ([]byte, error) {
	if s == nil || s.native == nil {
		return nil, ErrProtectedUnavailable
	}
	r := s.native
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.qualified {
		return nil, ErrProtectedUnavailable
	}
	return r.publicMagic(0x31534345)
}
func (s *HardwareSigner) Alias() string {
	if s == nil || s.native == nil {
		return ""
	}
	return s.native.Alias()
}
func (s *HardwareSigner) Close() {
	if s != nil && s.native != nil {
		s.native.Close()
	}
}

// DeleteCreated removes only the exact key successfully created by this instance.
func (s *HardwareSigner) DeleteCreated() error {
	if s == nil || s.native == nil {
		return ErrProtectedUnavailable
	}
	r := s.native
	r.mu.Lock()
	defer r.mu.Unlock()
	if !s.created || r.closed || r.key == 0 {
		return ErrProtectedUnavailable
	}
	if e := r.api.call("NCryptDeleteKey", r.key, 0); e != nil {
		return e
	}
	r.key = 0
	s.created = false
	r.close()
	return nil
}
func (s *HardwareSigner) SignEnvelope03(unsigned []byte) ([]byte, error) {
	return s.signProfile(unsigned, 3)
}
func (s *HardwareSigner) SignEnvelope02(unsigned []byte) ([]byte, error) {
	return s.signProfile(unsigned, 2)
}
func (s *HardwareSigner) signProfile(unsigned []byte, profile byte) ([]byte, error) {
	if s == nil || s.native == nil {
		return nil, ErrProtectedUnavailable
	}
	r := s.native
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.qualified || r.closed || len(unsigned) < 493 || len(unsigned) > 34149 || !bytes.Equal(unsigned[:8], []byte{'Z', 'T', 'S', 'E', profile, 1, 0, 0}) {
		return nil, ErrShape
	}
	captured := append([]byte(nil), unsigned...)
	label := []byte("ZTSE/sign/v3\x00")
	label[11] = '0' + profile
	transcript := append(label, binary.BigEndian.AppendUint32(nil, uint32(len(captured)))...)
	transcript = append(transcript, captured...)
	digest := sha256.Sum256(transcript)
	sig, e := s.signDigest(digest[:])
	if e != nil {
		return nil, e
	}
	point, e := r.publicMagic(0x31534345)
	if e != nil {
		return nil, e
	}
	if e = verifySignature(point, digest[:], sig); e != nil {
		return nil, e
	}
	return sig, nil
}

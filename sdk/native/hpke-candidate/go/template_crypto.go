package hpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// EncryptedTemplateScope is caller-supplied independent context, never wire authority.
type EncryptedTemplateScope struct {
	Account, Device, Line, Interval, Template                              [16]byte
	BindingGeneration, Revision, Expires, TrustGeneration, ManifestVersion uint64
	PeerDigest, Reader, ManifestDigest                                     [32]byte
}

func (s EncryptedTemplateScope) AAD() ([]byte, error) {
	if s.Revision > 128 {
		return nil, ErrShape
	}
	out := []byte{'Z', 'T', 'W', 'T', 1, 1}
	for _, v := range [][16]byte{s.Account, s.Device, s.Line, s.Interval, s.Template} {
		if v == [16]byte{} {
			return nil, ErrShape
		}
		out = append(out, v[:]...)
	}
	for _, n := range []uint64{s.BindingGeneration, s.Revision, s.Expires, s.TrustGeneration, s.ManifestVersion} {
		if n == 0 || n > 0x7fffffffffffffff {
			return nil, ErrShape
		}
		out = binary.BigEndian.AppendUint64(out, n)
	}
	for _, v := range [][32]byte{s.PeerDigest, s.Reader, s.ManifestDigest} {
		if v == [32]byte{} {
			return nil, ErrShape
		}
		out = append(out, v[:]...)
	}
	return out, nil
}
func templateAuthority(m *Manifest, s EncryptedTemplateScope, now uint64) ([]byte, error) {
	if m == nil || m.profile != 2 || !manifestWindow(m.issued, m.expires, now) || now < m.comparison || s.Expires <= now || s.Expires-now > 30*86400000 || s.Account != m.account || s.TrustGeneration != m.generation || s.ManifestVersion != m.version || s.ManifestDigest != m.digest {
		return nil, ErrAuthentication
	}
	reader := manifestKey(m, 2, s.Reader[:])
	if !activeKey(reader, now, 8) {
		return nil, ErrAuthentication
	}
	signer := false
	for i := 0; i < int(m.raw[150]); i++ {
		w := m.raw[151+i*149 : 151+(i+1)*149]
		if w[0] == 4 && bytes.Equal(w[98:114], s.Device[:]) && bytes.Equal(w[114:130], s.Line[:]) && activeKey(w, now, 2) && binary.BigEndian.Uint16(w[130:132]) == 2 {
			signer = true
		}
	}
	if !signer {
		return nil, ErrAuthentication
	}
	return append([]byte(nil), reader[33:98]...), nil
}
func sealTemplateHPKE(point, plain, info, aad []byte) ([]byte, error) {
	peer, e := ecdh.P256().NewPublicKey(point)
	if e != nil {
		return nil, ErrShape
	}
	ephemeral, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return nil, ErrShape
	}
	enc := ephemeral.PublicKey().Bytes()
	dh, e := ephemeral.ECDH(peer)
	if e != nil {
		return nil, ErrAuthentication
	}
	defer clear(dh)
	prk := extract(nil, kemSuite, "eae_prk", dh)
	defer clear(prk)
	shared := expand(prk, kemSuite, "shared_secret", join(enc, point), 32)
	defer clear(shared)
	context := join([]byte{0}, extract(nil, suite, "psk_id_hash", nil), extract(nil, suite, "info_hash", info))
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
	return append(enc, gcm.Seal(nil, nonce, plain, aad)...), nil
}

// SealEncryptedTemplate uses fresh ephemeral HPKE; this performs no persistence.
func SealEncryptedTemplate(m *Manifest, s EncryptedTemplateScope, now uint64, content *TemplateContent) ([]byte, error) {
	aad, e := s.AAD()
	if e != nil {
		return nil, e
	}
	point, e := templateAuthority(m, s, now)
	if e != nil {
		return nil, e
	}
	if content == nil {
		return nil, ErrShape
	}
	plain := content.Canonical()
	defer clear(plain)
	if len(plain) < 1 || len(plain) > 32768 {
		return nil, ErrShape
	}
	wrapped, e := sealTemplateHPKE(point, plain, join([]byte("ZT/workflow-template/hpke/v1\x00"), aad), aad)
	if e != nil {
		return nil, e
	}
	out := append(aad, wrapped[:65]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(wrapped)-65))
	return append(out, wrapped[65:]...), nil
}
func openTemplate(m *Manifest, s EncryptedTemplateScope, now uint64, envelope []byte, open func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) (*TemplateContent, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return nil, ErrShape
	}
	wire := append([]byte(nil), envelope...)
	aad, e := s.AAD()
	if e != nil || !bytes.Equal(wire[:222], aad) || int(binary.BigEndian.Uint32(wire[287:291])) != len(wire)-291 {
		return nil, ErrShape
	}
	point, e := templateAuthority(m, s, now)
	if e != nil {
		return nil, e
	}
	plain, e := open(point, wire[222:287], join([]byte("ZT/workflow-template/hpke/v1\x00"), aad), aad, wire[291:])
	if e != nil {
		return nil, e
	}
	defer clear(plain)
	return ParseTemplateContent(plain)
}
func OpenSoftwareEncryptedTemplate(m *Manifest, s EncryptedTemplateScope, now uint64, scalar, envelope []byte) (*TemplateContent, error) {
	return openTemplate(m, s, now, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		return openSoftwareContent(scalar, point, enc, info, aad, ct)
	})
}

// EncryptedTemplateDigest binds transport bytes only, never plaintext or authority.
func EncryptedTemplateDigest(envelope []byte) ([32]byte, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return [32]byte{}, ErrShape
	}
	return sha256.Sum256(envelope), nil
}

// TemplateAuthoritySource must independently supply current verified authority.
// The callback is invoked before crypto and again before exposing its result.
// It does not persist a comparison floor or authenticate an HTTP response.
type TemplateAuthoritySource func() (*Manifest, uint64, error)

func templateCurrent(source TemplateAuthoritySource, s EncryptedTemplateScope, floor uint64) (*Manifest, uint64, error) {
	if source == nil {
		return nil, 0, ErrAuthentication
	}
	m, now, e := source()
	if e != nil {
		return nil, 0, e
	}
	if now < floor {
		return nil, 0, ErrAuthentication
	}
	_, e = templateAuthority(m, s, now)
	return m, now, e
}

func SealCurrentEncryptedTemplate(source TemplateAuthoritySource, s EncryptedTemplateScope, content *TemplateContent) ([]byte, error) {
	m, now, e := templateCurrent(source, s, 0)
	if e != nil {
		return nil, e
	}
	out, e := SealEncryptedTemplate(m, s, now, content)
	if e != nil {
		return nil, e
	}
	if e = templateFinal(source, s, now, m); e != nil {
		clear(out)
		return nil, e
	}
	return out, nil
}

func openCurrentTemplate(source TemplateAuthoritySource, s EncryptedTemplateScope, envelope []byte, unwrap func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) (*TemplateContent, error) {
	m, now, e := templateCurrent(source, s, 0)
	if e != nil {
		return nil, e
	}
	return openTemplate(m, s, now, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		plain, e := unwrap(point, enc, info, aad, ct)
		if e != nil {
			return nil, e
		}
		if e = templateFinal(source, s, now, m); e != nil {
			clear(plain)
			return nil, e
		}
		return plain, nil
	})
}

func templateFinal(source TemplateAuthoritySource, s EncryptedTemplateScope, now uint64, prior *Manifest) error {
	m, _, e := templateCurrent(source, s, now)
	if e != nil {
		return e
	}
	if m.root != prior.root || m.enrolled != prior.enrolled {
		return ErrAuthentication
	}
	return nil
}

func OpenCurrentSoftwareEncryptedTemplate(source TemplateAuthoritySource, s EncryptedTemplateScope, scalar, envelope []byte) (*TemplateContent, error) {
	return openCurrentTemplate(source, s, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		return openSoftwareContent(scalar, point, enc, info, aad, ct)
	})
}

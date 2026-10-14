package hpke

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// WorkflowContextScope is caller-supplied independent context, never wire authority.
// WorkflowContextRole is explicit caller intent, never negotiated from ciphertext.
type WorkflowContextRole byte

const (
	OwnerContextReader       WorkflowContextRole = 2
	IntegrationContextReader WorkflowContextRole = 3
)

type WorkflowContextScope struct {
	Kind                                                                   byte
	Account, Device, Line, Interval, Context                               [16]byte
	BindingGeneration, Revision, Expires, TrustGeneration, ManifestVersion uint64
	PeerDigest, Reader, ManifestDigest                                     [32]byte
}

func (s WorkflowContextScope) AAD() ([]byte, error) {
	if s.Revision > 128 || s.Kind < 1 || s.Kind > 3 {
		return nil, ErrShape
	}
	out := []byte{'Z', 'T', 'W', 'C', 1, s.Kind}
	for _, v := range [][16]byte{s.Account, s.Device, s.Line, s.Interval, s.Context} {
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
func contextAuthority(m *Manifest, s WorkflowContextScope, role WorkflowContextRole, now uint64) ([]byte, error) {
	if (role != OwnerContextReader && role != IntegrationContextReader) || m == nil || m.profile != 2 || !manifestWindow(m.issued, m.expires, now) || now < m.comparison || s.Expires <= now || s.Expires-now > 30*86400000 || s.Account != m.account || s.TrustGeneration != m.generation || s.ManifestVersion != m.version || s.ManifestDigest != m.digest {
		return nil, ErrAuthentication
	}
	reader := manifestKey(m, byte(role), s.Reader[:])
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

// SealWorkflowContext uses fresh ephemeral HPKE; this performs no persistence.
func SealWorkflowContext(m *Manifest, s WorkflowContextScope, role WorkflowContextRole, now uint64, content []byte) ([]byte, error) {
	aad, e := s.AAD()
	if e != nil {
		return nil, e
	}
	point, e := contextAuthority(m, s, role, now)
	if e != nil {
		return nil, e
	}
	if len(content) < 1 || len(content) > 32768 {
		return nil, ErrShape
	}
	plain := append([]byte(nil), content...)
	defer clear(plain)
	if len(plain) < 1 || len(plain) > 32768 {
		return nil, ErrShape
	}
	wrapped, e := sealTemplateHPKE(point, plain, join([]byte("ZT/workflow-context/hpke/v1\x00"), aad), aad)
	if e != nil {
		return nil, e
	}
	out := append(aad, wrapped[:65]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(wrapped)-65))
	return append(out, wrapped[65:]...), nil
}
func openContext(m *Manifest, s WorkflowContextScope, role WorkflowContextRole, now uint64, envelope []byte, open func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) ([]byte, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return nil, ErrShape
	}
	wire := append([]byte(nil), envelope...)
	aad, e := s.AAD()
	if e != nil || !bytes.Equal(wire[:222], aad) || int(binary.BigEndian.Uint32(wire[287:291])) != len(wire)-291 {
		return nil, ErrShape
	}
	point, e := contextAuthority(m, s, role, now)
	if e != nil {
		return nil, e
	}
	plain, e := open(point, wire[222:287], join([]byte("ZT/workflow-context/hpke/v1\x00"), aad), aad, wire[291:])
	if e != nil {
		return nil, e
	}
	return plain, nil
}
func OpenSoftwareWorkflowContext(m *Manifest, s WorkflowContextScope, role WorkflowContextRole, now uint64, scalar, envelope []byte) ([]byte, error) {
	return openContext(m, s, role, now, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		return openSoftwareContent(scalar, point, enc, info, aad, ct)
	})
}

// WorkflowContextDigest binds transport bytes only, never plaintext or authority.
func WorkflowContextDigest(envelope []byte) ([32]byte, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return [32]byte{}, ErrShape
	}
	return sha256.Sum256(envelope), nil
}

// ContextAuthoritySource must independently supply current verified authority.
// The callback is invoked before crypto and again before exposing its result.
// It does not persist a comparison floor or authenticate an HTTP response.
type ContextAuthoritySource func() (*Manifest, uint64, error)

func contextCurrent(source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, floor uint64) (*Manifest, uint64, error) {
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
	_, e = contextAuthority(m, s, role, now)
	if e != nil {
		return nil, 0, e
	}
	owned := *m
	owned.raw = append([]byte(nil), m.raw...)
	owned.lineage = append([][32]byte(nil), m.lineage...)
	return &owned, now, nil
}

func SealCurrentWorkflowContext(source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, content []byte) ([]byte, error) {
	if len(content) < 1 || len(content) > 32768 {
		return nil, ErrShape
	}
	content = append([]byte(nil), content...)
	defer clear(content)
	m, now, e := contextCurrent(source, s, role, 0)
	if e != nil {
		return nil, e
	}
	out, e := SealWorkflowContext(m, s, role, now, content)
	if e != nil {
		return nil, e
	}
	if e = contextFinal(source, s, role, now, m); e != nil {
		clear(out)
		return nil, e
	}
	return out, nil
}

func openCurrentContext(source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, envelope []byte, unwrap func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) ([]byte, error) {
	if len(envelope) < 308 || len(envelope) > 33075 {
		return nil, ErrShape
	}
	envelope = append([]byte(nil), envelope...)
	m, now, e := contextCurrent(source, s, role, 0)
	if e != nil {
		return nil, e
	}
	return openContext(m, s, role, now, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		plain, e := unwrap(point, enc, info, aad, ct)
		if e != nil {
			return nil, e
		}
		if e = contextFinal(source, s, role, now, m); e != nil {
			clear(plain)
			return nil, e
		}
		return plain, nil
	})
}

func contextFinal(source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, now uint64, prior *Manifest) error {
	m, _, e := contextCurrent(source, s, role, now)
	if e != nil {
		return e
	}
	if m.root != prior.root || m.enrolled != prior.enrolled {
		return ErrAuthentication
	}
	return nil
}

func OpenCurrentSoftwareWorkflowContext(source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, scalar, envelope []byte) ([]byte, error) {
	if len(scalar) != 32 {
		return nil, ErrShape
	}
	scalar = append([]byte(nil), scalar...)
	defer clear(scalar)
	return openCurrentContext(source, s, role, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		return openSoftwareContent(scalar, point, enc, info, aad, ct)
	})
}

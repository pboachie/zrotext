package hpke

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const contactMutationDomain = "ZT/contact-field/mutation/v1"

// ContactSlot is an exact absent sentinel or a reference to a verified field.
type ContactSlot struct {
	Tag          byte
	SealRevision uint64
	Digest       [32]byte
}

// ContactMutationInput never derives the previous identity from storage.
type ContactMutationInput struct {
	Operation                                    byte
	ExpectedRevision, Revision, LegacyGeneration uint64
	RequestID                                    [16]byte
	PreviousDigest                               [32]byte
	Name, Notes                                  ContactSlot
}

// ContactMutation owns authenticated historical bytes, not current permission.
// Its zero value is invalid.
type ContactMutation struct {
	raw       []byte
	digest    [32]byte
	statement *ContactStatement
	input     ContactMutationInput
}

// ContactTransition retains genuine unchanged field tokens across statements.
// It is not a durable accepted-history checkpoint. Its zero value is invalid.
type ContactTransition struct {
	mutation *ContactMutation
	fields   [2]*ContactField
}

func (m *ContactMutation) Bytes() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.raw...)
}
func (m *ContactMutation) Digest() []byte {
	if m == nil || len(m.raw) == 0 {
		return nil
	}
	return append([]byte(nil), m.digest[:]...)
}
func (t *ContactTransition) Mutation() *ContactMutation {
	if t == nil {
		return nil
	}
	return t.mutation
}
func (t *ContactTransition) Field(kind byte) *ContactField {
	if t == nil || kind < 1 || kind > 2 {
		return nil
	}
	return t.fields[kind-1]
}

func contactSlotValid(s ContactSlot, revision uint64) bool {
	if s.SealRevision > revision {
		return false
	}
	if s.Tag == 0 {
		return s.SealRevision == 0 && s.Digest == [32]byte{}
	}
	return s.Tag == 1 && contactPositive(s.SealRevision) && s.Digest != [32]byte{}
}
func contactMutationUnsigned(st *ContactStatement, e ContactExpected, m ContactMutationInput, legacy uint64) ([]byte, error) {
	if !contactExpected(st, e) || !contactPositive(m.Revision) || m.ExpectedRevision > 0x7fffffffffffffff || m.LegacyGeneration > 0x7fffffffffffffff || m.LegacyGeneration != legacy || !contactNonzero(m.RequestID[:], 16) || !contactSlotValid(m.Name, m.Revision) || !contactSlotValid(m.Notes, m.Revision) {
		return nil, ErrShape
	}
	switch m.Operation {
	case 1, 3:
		if m.ExpectedRevision != 0 || m.Revision != 1 || m.PreviousDigest != [32]byte{} || (m.Operation == 1 && m.LegacyGeneration != 0) || (m.Operation == 3 && m.LegacyGeneration == 0) {
			return nil, ErrShape
		}
	case 2:
		if !contactPositive(m.ExpectedRevision) || m.ExpectedRevision == 0x7fffffffffffffff || m.Revision != m.ExpectedRevision+1 || m.PreviousDigest == [32]byte{} || m.LegacyGeneration != 0 {
			return nil, ErrShape
		}
	default:
		return nil, ErrShape
	}
	b := append([]byte("ZTCM\x01"), m.Operation)
	b = append(b, e.Account...)
	b = append(b, e.Contact...)
	b = binary.BigEndian.AppendUint64(b, m.ExpectedRevision)
	b = binary.BigEndian.AppendUint64(b, m.Revision)
	b = append(b, m.RequestID[:]...)
	b = append(b, m.PreviousDigest[:]...)
	b = binary.BigEndian.AppendUint64(b, 1)
	b = binary.BigEndian.AppendUint64(b, st.version)
	for _, p := range [][]byte{st.manifestDigest[:], st.digest[:], e.RoutingDigest} {
		b = append(b, p...)
	}
	b = binary.BigEndian.AppendUint64(b, m.LegacyGeneration)
	for _, s := range []ContactSlot{m.Name, m.Notes} {
		b = append(b, s.Tag)
		b = binary.BigEndian.AppendUint64(b, s.SealRevision)
		b = append(b, s.Digest[:]...)
	}
	return b, nil
}
func contactMutationInput(b []byte) ContactMutationInput {
	m := ContactMutationInput{Operation: b[5], ExpectedRevision: binary.BigEndian.Uint64(b[38:46]), Revision: binary.BigEndian.Uint64(b[46:54]), LegacyGeneration: binary.BigEndian.Uint64(b[214:222])}
	copy(m.RequestID[:], b[54:70])
	copy(m.PreviousDigest[:], b[70:102])
	for i, s := range []*ContactSlot{&m.Name, &m.Notes} {
		at := 222 + i*41
		s.Tag = b[at]
		s.SealRevision = binary.BigEndian.Uint64(b[at+1 : at+9])
		copy(s.Digest[:], b[at+9:at+41])
	}
	return m
}
func VerifyContactMutation01(input []byte, st *ContactStatement, e ContactExpected, expectedLegacy uint64) (*ContactMutation, error) {
	if len(input) != 368 {
		return nil, ErrShape
	}
	b := append([]byte(nil), input...)
	m := contactMutationInput(b)
	unsigned, err := contactMutationUnsigned(st, e, m, expectedLegacy)
	if err != nil || !bytes.Equal(unsigned, b[:304]) {
		return nil, ErrAuthentication
	}
	if err = contactVerify(st.rootPoint[:], b, contactMutationDomain); err != nil {
		return nil, err
	}
	return &ContactMutation{raw: b, digest: sha256.Sum256(b), statement: st, input: m}, nil
}

func contactTransitionFields(previous *ContactTransition, n *ContactMutation, replacements []*ContactField) ([2]*ContactField, error) {
	var out [2]*ContactField
	if n == nil || len(n.raw) != 368 || n.statement == nil || len(replacements) > 2 {
		return out, ErrShape
	}
	var supplied [2]*ContactField
	for _, f := range replacements {
		if f == nil || len(f.raw) < 396 || f.raw[5] < 1 || f.raw[5] > 2 || supplied[f.raw[5]-1] != nil {
			return out, ErrShape
		}
		supplied[f.raw[5]-1] = f
	}
	m, s := n.input, n.statement
	if previous != nil {
		p := previous.mutation
		if p == nil || len(p.raw) != 368 {
			return out, ErrShape
		}
		ps := p.statement
		if m.Operation != 2 || m.ExpectedRevision != p.input.Revision || m.PreviousDigest != p.digest || !bytes.Equal(n.raw[6:38], p.raw[6:38]) || !bytes.Equal(n.raw[182:214], p.raw[182:214]) || s.origin != ps.origin || s.fingerprint != ps.fingerprint || s.version < ps.version || (s.version == ps.version && s.manifestDigest != ps.manifestDigest) || s.readerGeneration < ps.readerGeneration || (s.readerGeneration == ps.readerGeneration && (s.readerID != ps.readerID || s.readerPoint != ps.readerPoint)) {
			return out, ErrAuthentication
		}
	} else if m.Operation == 2 {
		return out, ErrAuthentication
	}
	used := 0
	for i, slot := range []ContactSlot{m.Name, m.Notes} {
		if slot.Tag == 0 {
			continue
		}
		if slot.SealRevision == m.Revision {
			f := supplied[i]
			if f == nil {
				return out, ErrAuthentication
			}
			b := f.raw
			if f.digest != slot.Digest || binary.BigEndian.Uint64(b[38:46]) != m.Revision || !bytes.Equal(b[198:214], m.RequestID[:]) || !bytes.Equal(b[6:38], n.raw[6:38]) || binary.BigEndian.Uint64(b[46:54]) != 1 || binary.BigEndian.Uint64(b[54:62]) != s.version || binary.BigEndian.Uint64(b[62:70]) != s.readerGeneration || !bytes.Equal(b[70:102], s.readerID[:]) || !bytes.Equal(b[102:134], s.manifestDigest[:]) || !bytes.Equal(b[134:166], s.digest[:]) || !bytes.Equal(b[166:198], n.raw[182:214]) || !bytes.Equal(b[214:246], s.rootWriterID[:]) {
				return out, ErrAuthentication
			}
			out[i] = f
			used++
		} else {
			if previous == nil {
				return out, ErrAuthentication
			}
			old := previous.mutation.input.Name
			if i == 1 {
				old = previous.mutation.input.Notes
			}
			if slot != old || previous.fields[i] == nil {
				return out, ErrAuthentication
			}
			out[i] = previous.fields[i]
		}
	}
	if used != len(replacements) {
		return out, ErrAuthentication
	}
	return out, nil
}
func VerifyContactTransition01(previous *ContactTransition, next *ContactMutation, replacements []*ContactField) (*ContactTransition, error) {
	fields, err := contactTransitionFields(previous, next, replacements)
	if err != nil {
		return nil, err
	}
	return &ContactTransition{mutation: next, fields: fields}, nil
}

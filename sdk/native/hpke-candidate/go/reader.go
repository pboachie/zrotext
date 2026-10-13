package hpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"unicode/utf8"
)

// ArchiveContext must come from independently authenticated routing/current policy.
type ArchiveContext struct {
	Account, Device, Line, Reader []byte
	Peer                          string
	Now                           uint64
}

func manifestKey(m *Manifest, role byte, id []byte) []byte {
	offset := 0
	if m.profile == 3 {
		offset = 2
	}
	for i := 0; i < int(m.raw[150+offset]); i++ {
		w := m.raw[151+offset+i*149 : 151+offset+(i+1)*149]
		if w[0] == role && bytes.Equal(w[1:33], id) {
			return w
		}
	}
	return nil
}
func activeKey(w []byte, now uint64, scope uint16) bool {
	return w != nil && w[148] == 1 && binary.BigEndian.Uint64(w[132:140]) <= now && now < binary.BigEndian.Uint64(w[140:148]) && binary.BigEndian.Uint16(w[130:132])&scope == scope
}

// OpenSoftwareArchive02 is a candidate archive-only inbound reader. It returns
// authenticated text, never radio authority, an accepted grant or replay receipt.
func OpenSoftwareArchive02(input []byte, historical, current *Manifest, scalar []byte, context ArchiveContext) (string, error) {
	if len(input) < 426 || len(input) > 34082 || historical == nil || current == nil || historical.profile != 2 || current.profile != 2 || len(context.Account) != 16 || len(context.Device) != 16 || len(context.Line) != 16 || len(context.Reader) != 32 {
		return "", ErrShape
	}
	b := append([]byte(nil), input...)
	if b[4] != 2 || b[5] != 2 {
		return "", ErrShape
	}
	now := context.Now
	if historical.account != current.account || historical.root != current.root || now < current.comparison || !manifestWindow(current.issued, current.expires, now) {
		return "", ErrAuthentication
	}
	member := false
	for _, id := range current.lineage {
		if id == historical.digest {
			member = true
		}
	}
	if !member {
		return "", ErrAuthentication
	}
	observed := binary.BigEndian.Uint64(b[146:154])
	if observed == 0 || observed > now || !manifestWindow(historical.issued, historical.expires, observed) {
		return "", ErrAuthentication
	}
	if !bytes.Equal(b[10:26], context.Account) || !bytes.Equal(b[42:58], context.Device) || !bytes.Equal(b[58:74], context.Line) || !bytes.Equal(b[10:26], historical.account[:]) || binary.BigEndian.Uint64(b[74:82]) != historical.version || !bytes.Equal(b[82:114], historical.digest[:]) {
		return "", ErrAuthentication
	}
	signer := manifestKey(historical, 4, b[114:146])
	if !activeKey(signer, observed, 2) || !bytes.Equal(signer[98:114], context.Device) || !bytes.Equal(signer[114:130], context.Line) {
		return "", ErrAuthentication
	}
	envelope, err := VerifyEnvelope(b, signer[33:98], 2)
	if err != nil {
		return "", err
	}
	if string(b[179:envelope.prefix]) != context.Peer || b[envelope.bodyEnd] != 1 {
		return "", ErrAuthentication
	}
	w := b[envelope.bodyEnd+1 : envelope.unsignedEnd]
	if w[0] != 2 || !bytes.Equal(w[1:33], context.Reader) {
		return "", ErrAuthentication
	}
	oldReader := manifestKey(historical, 2, context.Reader)
	reader := manifestKey(current, 2, context.Reader)
	if !activeKey(oldReader, observed, 8) || !activeKey(reader, now, 8) {
		return "", ErrAuthentication
	}
	info, aad, err := envelope.WrapTranscript(0)
	if err != nil {
		return "", err
	}
	cek, err := OpenSoftwareCEK(scalar, reader[33:98], w[33:98], info, aad, w[98:])
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
	plain, err := gcm.Open(nil, b[envelope.prefix:envelope.prefix+12], b[envelope.prefix+16:envelope.bodyEnd], envelope.BodyAAD())
	if err != nil {
		return "", ErrAuthentication
	}
	defer clear(plain)
	if len(plain) < 1 || len(plain) > 32768 || !utf8.Valid(plain) || bytes.IndexByte(plain, 0) >= 0 || bytes.HasPrefix(plain, []byte{239, 187, 191}) {
		return "", ErrShape
	}
	return string(plain), nil
}

// OpenProtectedArchive02 refuses until a qualified native protected provider exists.
func OpenProtectedArchive02() (string, error) { return "", ErrProtectedUnavailable }

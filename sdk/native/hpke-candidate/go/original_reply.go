package hpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf8"
)

// OriginalScope is independently selected role3 grant identity, never event metadata.
type OriginalScope struct {
	Account, Device, Line, Interval, Connector, ReadGrant [16]byte
	Reader                                                [32]byte
	Peer                                                  string
}

// OriginalAuthority must be obtained through an independently authenticated grant
// integration. A callback is not HTTP provenance or a durable high-water store.
type OriginalAuthority struct {
	Scope        OriginalScope
	Revision     string
	Now, Expires uint64
	Manifest     *Manifest
}
type selectedReader struct {
	connector, grant [16]byte
	reader           [32]byte
}

// ReplySelection contains owned, dual-signed approval/installation evidence.
type ReplySelection struct {
	valid               bool
	scope               OriginalScope
	archive             [32]byte
	readers             []selectedReader
	root, enrolled      [65]byte
	generation, version uint64
	digest              [32]byte
}

const replyDisclosure = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately."

type replyCursor struct {
	raw []byte
	at  int
	ok  bool
}

func (p *replyCursor) take(n int) []byte {
	if !p.ok || n > len(p.raw)-p.at {
		p.ok = false
		return make([]byte, n)
	}
	b := p.raw[p.at : p.at+n]
	p.at += n
	return b
}
func (p *replyCursor) fixed(n int) []byte {
	b := p.take(n)
	if bytes.Equal(b, make([]byte, n)) {
		p.ok = false
	}
	return b
}
func (p *replyCursor) number() uint64 {
	n := binary.BigEndian.Uint64(p.take(8))
	if n == 0 || n > 0x7fffffffffffffff {
		p.ok = false
	}
	return n
}
func (p *replyCursor) text() string {
	b := p.take(int(p.take(1)[0]))
	if !utf8.Valid(b) {
		p.ok = false
	}
	return string(b)
}
func replyPeer(s string) bool {
	if len(s) < 3 || len(s) > 16 || s[0] != '+' || s[1] < '1' || s[1] > '9' {
		return false
	}
	for _, b := range []byte(s[2:]) {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
func (s OriginalScope) valid() bool {
	return s.Account != [16]byte{} && s.Device != [16]byte{} && s.Line != [16]byte{} && s.Interval != [16]byte{} && s.Connector != [16]byte{} && s.ReadGrant != [16]byte{} && s.Reader != [32]byte{} && replyPeer(s.Peer)
}

// VerifyOriginalReplySelection02 verifies both phone signatures and independently
// accepted activation provenance. It does not create a live role3 grant.
func VerifyOriginalReplySelection02(input, approval, installation []byte, activation *Manifest, accepted uint64, scope OriginalScope) (*ReplySelection, error) {
	if len(input) < 380 || len(input) > 1536 || activation == nil || activation.profile != 2 || !scope.valid() {
		return nil, ErrShape
	}
	raw := append([]byte(nil), input...)
	p := replyCursor{raw: raw, ok: true}
	if !bytes.Equal(p.take(5), []byte("ZTCA\x02")) {
		return nil, ErrShape
	}
	account, device, line := p.fixed(16), p.fixed(16), p.fixed(16)
	p.number()
	interval := p.fixed(16)
	p.fixed(16)
	p.fixed(16)
	p.fixed(32)
	expires, peer := p.number(), p.text()
	content := p.text()
	disclosure := p.take(32)
	archive, signer := p.fixed(32), p.fixed(32)
	generation, previous := p.number(), p.number()
	p.fixed(32)
	version, digest := p.number(), p.fixed(32)
	p.number()
	p.number()
	site, instance := p.text(), p.text()
	printable := func(s string) bool {
		if len(s) < 1 || len(s) > 64 {
			return false
		}
		for _, v := range []byte(s) {
			if v < 33 || v > 126 {
				return false
			}
		}
		return true
	}
	count := int(p.take(1)[0])
	if count < 1 || count > 6 {
		return nil, ErrShape
	}
	readers := make([]selectedReader, 0, count)
	chosen := false
	for i := 0; i < count; i++ {
		r := selectedReader{}
		copy(r.connector[:], p.fixed(16))
		copy(r.grant[:], p.fixed(16))
		copy(r.reader[:], p.fixed(32))
		if i > 0 && bytes.Compare(readers[i-1].reader[:], r.reader[:]) >= 0 {
			return nil, ErrShape
		}
		for _, old := range readers {
			if old.connector == r.connector || old.grant == r.grant || old.reader == r.reader {
				return nil, ErrShape
			}
		}
		if r.connector == scope.Connector && r.grant == scope.ReadGrant && r.reader == scope.Reader {
			chosen = true
		}
		readers = append(readers, r)
	}
	hash := sha256.Sum256([]byte(replyDisclosure))
	if !p.ok || p.at != len(raw) || !chosen || content != "conversation-content-v1" || !bytes.Equal(disclosure, hash[:]) || !printable(site) || !printable(instance) || version != previous+1 || peer != scope.Peer || accepted == 0 || accepted >= expires || !bytes.Equal(account, scope.Account[:]) || !bytes.Equal(device, scope.Device[:]) || !bytes.Equal(line, scope.Line[:]) || !bytes.Equal(interval, scope.Interval[:]) {
		return nil, ErrAuthentication
	}
	current, err := VerifyManifest(activation.raw, activation.rootTrust(), activation, 2, accepted)
	if err != nil {
		return nil, err
	}
	if current.account != scope.Account || current.generation != generation || current.version != version || !bytes.Equal(current.digest[:], digest) {
		return nil, ErrAuthentication
	}
	key := manifestKey(current, 4, signer)
	if !activeKey(key, accepted, 2) || !bytes.Equal(key[98:114], scope.Device[:]) || !bytes.Equal(key[114:130], scope.Line[:]) || !electionSignature(key[33:98], approval, "zrotext/conversation/approve/v2", raw) || !electionSignature(key[33:98], installation, "zrotext/conversation/install/v2", raw) {
		return nil, ErrAuthentication
	}
	out := &ReplySelection{valid: true, scope: scope, readers: readers, root: current.root, enrolled: current.enrolled, generation: generation, version: version, digest: current.digest}
	copy(out.archive[:], archive)
	return out, nil
}
func replyAuthority(value OriginalAuthority, scope OriginalScope) (OriginalAuthority, error) {
	if value.Scope != scope || len(value.Revision) == 0 || len(value.Revision) > 128 || value.Now == 0 || value.Now >= value.Expires || value.Expires > 0x7fffffffffffffff || value.Manifest == nil || value.Manifest.profile != 2 {
		return OriginalAuthority{}, ErrAuthentication
	}
	m, err := VerifyManifest(value.Manifest.raw, value.Manifest.rootTrust(), value.Manifest, 2, value.Now)
	if err != nil {
		return OriginalAuthority{}, err
	}
	value.Manifest = m
	return value, nil
}
func lineage(m *Manifest, d [32]byte) bool {
	for _, v := range m.lineage {
		if v == d {
			return true
		}
	}
	return false
}

// OpenSoftwareOriginalReply02 is explicitly exportable-key candidate opening.
// HTTP proof validation, persisted history/high-water and consume/status are not
// implemented by this callback-based reader. No implicit network or retry occurs.
func OpenSoftwareOriginalReply02(input []byte, event [16]byte, historical *Manifest, selection *ReplySelection, scope OriginalScope, scalar []byte, current func() (OriginalAuthority, error)) (string, error) {
	return openOriginalReply02(input, event, historical, selection, scope, current, func(public, enc, info, aad, ct []byte) ([]byte, error) {
		return OpenSoftwareCEK(scalar, public, enc, info, aad, ct)
	})
}
func openOriginalReply02(input []byte, event [16]byte, historical *Manifest, selection *ReplySelection, scope OriginalScope, readCurrent func() (OriginalAuthority, error), unwrap func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) (string, error) {
	if len(input) < 426 || len(input) > 34082 || event == [16]byte{} || historical == nil || historical.profile != 2 || selection == nil || !selection.valid || selection.scope != scope || !scope.valid() || readCurrent == nil {
		return "", ErrShape
	}
	b := append([]byte(nil), input...)
	if b[4] != 2 || b[5] != 2 || !bytes.Equal(b[26:42], event[:]) {
		return "", ErrAuthentication
	}
	response, err := readCurrent()
	if err != nil {
		return "", err
	}
	initial, err := replyAuthority(response, scope)
	if err != nil {
		return "", err
	}
	m := initial.Manifest
	if historical.account != scope.Account || m.account != scope.Account || historical.root != m.root || historical.enrolled != m.enrolled || m.root != selection.root || m.enrolled != selection.enrolled || historical.generation != m.generation || m.generation != selection.generation || historical.version < selection.version || !lineage(historical, selection.digest) || !lineage(m, historical.digest) {
		return "", ErrAuthentication
	}
	observed := binary.BigEndian.Uint64(b[146:154])
	if observed == 0 || observed > initial.Now || !manifestWindow(historical.issued, historical.expires, observed) || !bytes.Equal(b[10:26], scope.Account[:]) || !bytes.Equal(b[42:58], scope.Device[:]) || !bytes.Equal(b[58:74], scope.Line[:]) || binary.BigEndian.Uint64(b[74:82]) != historical.version || !bytes.Equal(b[82:114], historical.digest[:]) {
		return "", ErrAuthentication
	}
	signer := manifestKey(historical, 4, b[114:146])
	if !activeKey(signer, observed, 2) || !bytes.Equal(signer[98:114], scope.Device[:]) || !bytes.Equal(signer[114:130], scope.Line[:]) {
		return "", ErrAuthentication
	}
	envelope, err := VerifyEnvelope(b, signer[33:98], 2)
	if err != nil {
		return "", err
	}
	if string(b[179:envelope.prefix]) != scope.Peer || int(b[envelope.bodyEnd]) != 1+len(selection.readers) {
		return "", ErrAuthentication
	}
	selected := -1
	for i := 0; i < int(b[envelope.bodyEnd]); i++ {
		w := b[envelope.bodyEnd+1+i*146 : envelope.bodyEnd+1+(i+1)*146]
		role := byte(2)
		id := selection.archive
		if i > 0 {
			role = 3
			id = selection.readers[i-1].reader
		}
		if w[0] != role || !bytes.Equal(w[1:33], id[:]) || !activeKey(manifestKey(historical, role, id[:]), observed, 8) {
			return "", ErrAuthentication
		}
		if role == 3 && id == scope.Reader {
			selected = i
		}
	}
	reader := manifestKey(m, 3, scope.Reader[:])
	if selected < 0 || !activeKey(reader, initial.Now, 8) {
		return "", ErrAuthentication
	}
	w := b[envelope.bodyEnd+1+selected*146 : envelope.bodyEnd+1+(selected+1)*146]
	info, aad, err := envelope.WrapTranscript(selected)
	if err != nil {
		return "", err
	}
	cek, err := unwrap(reader[33:98], w[33:98], info, aad, w[98:])
	if err != nil {
		return "", err
	}
	defer clear(cek)
	if len(cek) != 32 {
		return "", ErrAuthentication
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, b[envelope.prefix:envelope.prefix+12], b[envelope.prefix+16:envelope.bodyEnd], envelope.BodyAAD())
	if err != nil {
		return "", ErrAuthentication
	}
	defer clear(plain)
	response, err = readCurrent()
	if err != nil {
		return "", err
	}
	final, err := replyAuthority(response, scope)
	if err != nil {
		return "", err
	}
	f := final.Manifest
	if final.Revision != initial.Revision || final.Now < initial.Now || final.Now >= initial.Expires || final.Now >= binary.BigEndian.Uint64(reader[140:148]) || f.root != m.root || f.enrolled != m.enrolled || f.generation != m.generation || f.version != m.version || f.digest != m.digest {
		return "", ErrAuthentication
	}
	if len(plain) < 1 || len(plain) > 32768 || !utf8.Valid(plain) || bytes.IndexByte(plain, 0) >= 0 || bytes.HasPrefix(plain, []byte{239, 187, 191}) {
		return "", ErrShape
	}
	return string(plain), nil
}

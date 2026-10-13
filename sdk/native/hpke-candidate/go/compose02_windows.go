//go:build windows

package hpke

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"unicode/utf8"
)

// Comparison02 supplies candidate comparison time; it is not a live authority grant.
type Comparison02 func() (uint64, error)

// Current02 must independently select a verified current manifest and comparison clock.
type Current02 func() (*Manifest, uint64, error)
type ComposeRequest02 struct {
	Current               Current02
	Manifest              *Manifest
	Comparison            Comparison02
	Message, Device, Line []byte
	Observed, Expires     uint64
	Peer, Content         string
	Signer                *HardwareSigner
	Recipients            []ComposeRecipient
}

func captureCompose02(r ComposeRequest02) ComposeRequest02 {
	r.Message = append([]byte(nil), r.Message...)
	r.Device = append([]byte(nil), r.Device...)
	r.Line = append([]byte(nil), r.Line...)
	v := make([]ComposeRecipient, len(r.Recipients))
	for i, k := range r.Recipients {
		v[i] = ComposeRecipient{k.Role, append([]byte(nil), k.ID...)}
	}
	r.Recipients = v
	return r
}
func authorizeCompose02(r ComposeRequest02) (*composePlan, error) {
	if r.Manifest == nil || r.Manifest.profile != 2 || r.Comparison == nil || r.Signer == nil || len(r.Message) != 16 || len(r.Device) != 16 || len(r.Line) != 16 || r.Observed > 0x7fffffffffffffff || r.Expires > 0x7fffffffffffffff || r.Expires <= r.Observed || r.Expires-r.Observed > 900000 || len(r.Peer) < 3 || len(r.Peer) > 16 || r.Peer[0] != '+' || r.Peer[1] < '1' || r.Peer[1] > '9' {
		return nil, ErrShape
	}
	for _, c := range r.Peer[2:] {
		if c < '0' || c > '9' {
			return nil, ErrShape
		}
	}
	if len(r.Content) < 1 || len(r.Content) > 32768 || !utf8.ValidString(r.Content) || bytes.IndexByte([]byte(r.Content), 0) >= 0 || bytes.HasPrefix([]byte(r.Content), []byte{239, 187, 191}) {
		return nil, ErrShape
	}
	now, e := r.Comparison()
	if e != nil {
		return nil, e
	}
	m, e := VerifyManifest(r.Manifest.raw, r.Manifest.rootTrust(), r.Manifest, 2, now)
	if e != nil {
		return nil, e
	}
	point, e := r.Signer.PublicPoint()
	if e != nil {
		return nil, e
	}
	id := sha256.Sum256(join([]byte("ZTSE/key/v1\x00"), []byte{1, 1}, point))
	signer := manifestKey(m, 5, id[:])
	if !activeKey(signer, now, 1) || !bytes.Equal(signer[114:130], r.Line) || !bytes.Equal(signer[33:98], point) {
		return nil, ErrAuthentication
	}
	if len(r.Recipients) < 2 || len(r.Recipients) > 8 {
		return nil, ErrShape
	}
	sort.Slice(r.Recipients, func(i, j int) bool {
		a, b := r.Recipients[i], r.Recipients[j]
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return bytes.Compare(a.ID, b.ID) < 0
	})
	counts := map[byte]int{}
	keys := make([][]byte, 0, len(r.Recipients))
	var identity []byte
	for i, k := range r.Recipients {
		if k.Role < 1 || k.Role > 3 || len(k.ID) != 32 || i > 0 && k.Role == r.Recipients[i-1].Role && bytes.Equal(k.ID, r.Recipients[i-1].ID) {
			return nil, ErrShape
		}
		counts[k.Role]++
		record := manifestKey(m, k.Role, k.ID)
		if !activeKey(record, now, 4) {
			return nil, ErrAuthentication
		}
		if k.Role == 1 && (!bytes.Equal(record[98:114], r.Device) || !bytes.Equal(record[114:130], r.Line)) {
			return nil, ErrAuthentication
		}
		keys = append(keys, record)
		identity = append(identity, join([]byte{k.Role}, k.ID, record[33:98])...)
	}
	if counts[1] != 1 || counts[2] != 1 {
		return nil, ErrAuthentication
	}
	fields := join(m.account[:], r.Message, r.Device, r.Line, binary.BigEndian.AppendUint64(nil, m.version), m.digest[:], id[:], binary.BigEndian.AppendUint64(nil, r.Observed), binary.BigEndian.AppendUint64(nil, r.Expires), []byte{1, byte(len(r.Peer))}, []byte(r.Peer))
	prefix := join([]byte{'Z', 'T', 'S', 'E', 2, 1, 0, 0}, binary.BigEndian.AppendUint16(nil, uint16(len(fields))), fields)
	text := []byte(r.Content)
	textHash := sha256.Sum256(text)
	intent := sha256.Sum256(join([]byte("ZTSE/native-outbound-intent/v2\x00"), prefix, textHash[:], identity, m.enrolled[:], m.root[:], binary.BigEndian.AppendUint64(nil, m.generation)))
	return &composePlan{prefix: prefix, text: text, public: point, intent: intent[:], recipients: keys, now: now}, nil
}
func recheckCompose02(r ComposeRequest02, p *composePlan) error {
	fresh, e := authorizeCompose02(r)
	if e != nil {
		return e
	}
	defer clear(fresh.text)
	if fresh.now < p.now || !bytes.Equal(fresh.intent, p.intent) {
		return ErrAuthentication
	}
	p.now = fresh.now
	return nil
}
func composeProtected02(r ComposeRequest02, p *composePlan) ([]byte, error) {
	envelope, e := composeProfile(p, r.Signer, 2)
	if e != nil {
		return nil, e
	}
	if e = recheckCompose02(r, p); e != nil {
		return nil, e
	}
	return envelope, nil
}

// ComposeProtected02 creates fresh candidate ciphertext. Never use fresh composition for retries.
func ComposeProtected02(request ComposeRequest02) ([]byte, error) {
	r := captureCompose02(request)
	p, e := authorizeCompose02(r)
	if e != nil {
		return nil, e
	}
	defer clear(p.text)
	return composeProtected02(r, p)
}

func requireCurrentCompose02(r ComposeRequest02, p *composePlan) error {
	if r.Current == nil {
		return ErrAuthentication
	}
	current, now, e := r.Current()
	if e != nil {
		return e
	}
	if current == nil || current.profile != 2 || current.account != r.Manifest.account || current.root != r.Manifest.root || current.generation != r.Manifest.generation || current.enrolled != r.Manifest.enrolled || now < p.now || r.Observed == 0 || r.Observed > now || now >= r.Expires {
		return ErrAuthentication
	}
	member := false
	for _, digest := range current.lineage {
		if digest == r.Manifest.digest {
			member = true
		}
	}
	if !member {
		return ErrAuthentication
	}
	freshRequest := r
	freshRequest.Manifest = current
	freshRequest.Comparison = func() (uint64, error) { return now, nil }
	fresh, e := authorizeCompose02(freshRequest)
	if e != nil {
		return e
	}
	defer clear(fresh.text)
	if !bytes.Equal(fresh.public, p.public) || len(fresh.recipients) != len(p.recipients) {
		return ErrAuthentication
	}
	for i, k := range fresh.recipients {
		if !bytes.Equal(k[:98], p.recipients[i][:98]) {
			return ErrAuthentication
		}
	}
	p.now = now
	return nil
}

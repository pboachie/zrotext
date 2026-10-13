//go:build windows

package hpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"unicode/utf8"
)

// CurrentSource must obtain independently authenticated current records and clock.
type CurrentSource func() (ElectionRecord, uint64, error)
type ComposeRecipient struct {
	Role byte
	ID   []byte
}
type ComposeRequest struct {
	Manifest          *Manifest
	Proof             *ElectionProof
	Authority         CurrentSource
	Message           []byte
	Observed, Expires uint64
	Peer, Content     string
	Signer            *HardwareSigner
	Recipients        []ComposeRecipient
}
type composePlan struct {
	prefix, text, public, intent []byte
	recipients                   [][]byte
	now                          uint64
}

func captureCompose(r ComposeRequest) ComposeRequest {
	r.Message = append([]byte(nil), r.Message...)
	v := make([]ComposeRecipient, len(r.Recipients))
	for i, k := range r.Recipients {
		v[i] = ComposeRecipient{k.Role, append([]byte(nil), k.ID...)}
	}
	r.Recipients = v
	return r
}
func authorizeCompose(r ComposeRequest) (*composePlan, error) {
	if r.Authority == nil || r.Signer == nil {
		return nil, ErrShape
	}
	current, now, e := r.Authority()
	if e != nil {
		return nil, e
	}
	c, e := RequireCurrentElection03(r.Proof, r.Manifest, current, now)
	if e != nil {
		return nil, e
	}
	m := r.Manifest
	if len(r.Message) != 16 || bytes.Equal(r.Message, make([]byte, 16)) || r.Observed == 0 || r.Observed > now || r.Expires <= now || r.Expires > 0x7fffffffffffffff || r.Expires-r.Observed > 900000 || len(r.Peer) < 3 || len(r.Peer) > 16 || r.Peer[0] != '+' || r.Peer[1] < '1' || r.Peer[1] > '9' {
		return nil, ErrShape
	}
	for _, v := range r.Peer[2:] {
		if v < '0' || v > '9' {
			return nil, ErrShape
		}
	}
	if len(r.Content) < 1 || len(r.Content) > 32768 || !utf8.ValidString(r.Content) || bytes.IndexByte([]byte(r.Content), 0) >= 0 || bytes.HasPrefix([]byte(r.Content), []byte{239, 187, 191}) {
		return nil, ErrShape
	}
	point, e := r.Signer.PublicPoint()
	if e != nil {
		return nil, e
	}
	id := sha256.Sum256(join([]byte("ZTSE/key/v1\x00"), []byte{1, 1}, point))
	signer := manifestKey(m, 5, id[:])
	if !activeKey(signer, now, 1) || !activeKey(signer, r.Observed, 1) || !bytes.Equal(signer[114:130], c.Bytes["lineId"]) || !bytes.Equal(signer[33:98], point) {
		return nil, ErrAuthentication
	}
	deadline := min(m.expires, binary.BigEndian.Uint64(signer[140:148]), c.Numbers["permissionExpiresAtMs"])
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
		if !activeKey(record, now, 4) || !activeKey(record, r.Observed, 4) {
			return nil, ErrAuthentication
		}
		if k.Role == 1 && (!bytes.Equal(k.ID, c.Bytes["selectedReaderKeyId"]) || !bytes.Equal(record[98:114], c.Bytes["deviceId"]) || !bytes.Equal(record[114:130], c.Bytes["lineId"])) {
			return nil, ErrAuthentication
		}
		deadline = min(deadline, binary.BigEndian.Uint64(record[140:148]))
		keys = append(keys, record)
		identity = append(identity, join([]byte{k.Role}, k.ID, record[33:98])...)
	}
	if counts[1] != 1 || counts[2] != 1 || r.Expires > deadline {
		return nil, ErrAuthentication
	}
	fields := join(c.Bytes["accountId"], r.Message, c.Bytes["deviceId"], c.Bytes["lineId"], binary.BigEndian.AppendUint64(nil, m.version), m.digest[:], id[:], binary.BigEndian.AppendUint64(nil, r.Observed), binary.BigEndian.AppendUint64(nil, r.Expires), []byte{1, byte(len(r.Peer))}, []byte(r.Peer))
	prefix := join([]byte{'Z', 'T', 'S', 'E', 3, 1, 0, 0}, binary.BigEndian.AppendUint16(nil, uint16(len(fields))), fields)
	text := []byte(r.Content)
	textHash := sha256.Sum256(text)
	intent := sha256.Sum256(join([]byte("ZTSE/native-outbound-intent/v1\x00"), prefix, textHash[:], identity, c.Bytes["bindingId"], binary.BigEndian.AppendUint64(nil, c.Numbers["bindingGeneration"]), c.Bytes["electionCommitment"], c.Bytes["electionBundleSha256"]))
	return &composePlan{prefix: prefix, text: text, public: point, intent: intent[:], recipients: keys, now: now}, nil
}
func recheckCompose(r ComposeRequest, p *composePlan) error {
	fresh, e := authorizeCompose(r)
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
func encryptCandidate(key, nonce, text, aad []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return gcm.Seal(nil, nonce, text, aad), nil
}
func wrapCandidate(point, cek, info, aad []byte) ([]byte, error) {
	peer, e := ecdh.P256().NewPublicKey(point)
	if e != nil {
		return nil, e
	}
	ephemeral, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	enc := ephemeral.PublicKey().Bytes()
	dh, e := ephemeral.ECDH(peer)
	if e != nil {
		return nil, e
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
	ct, e := encryptCandidate(key, nonce, cek, aad)
	if e != nil {
		return nil, e
	}
	return join(enc, ct), nil
}
func composeProfile(p *composePlan, signer *HardwareSigner, profile byte) ([]byte, error) {
	bodyLabel, wrapLabel := []byte("ZTSE/body/v3\x00"), []byte("ZTSE/wrap/v3\x00")
	bodyLabel[11] = '0' + profile
	wrapLabel[11] = '0' + profile
	cek := make([]byte, 32)
	if _, e := rand.Read(cek); e != nil {
		return nil, e
	}
	defer clear(cek)
	nonce := make([]byte, 12)
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	body, e := encryptCandidate(cek, nonce, p.text, join(bodyLabel, p.prefix))
	if e != nil {
		return nil, e
	}
	unsigned := join(p.prefix, nonce, binary.BigEndian.AppendUint32(nil, uint32(len(body))), body, []byte{byte(len(p.recipients))})
	for _, record := range p.recipients {
		suffix := join(p.prefix, record[:33])
		aad := []byte(nil)
		if profile == 3 {
			aad = join([]byte("ZTSE/wrap-aad/v3\x00"), suffix)
		}
		wrap, e := wrapCandidate(record[33:98], cek, join(wrapLabel, suffix), aad)
		if e != nil {
			return nil, e
		}
		unsigned = append(unsigned, record[:33]...)
		unsigned = append(unsigned, wrap...)
	}
	sig, e := signer.signProfile(unsigned, profile)
	if e != nil {
		return nil, e
	}
	envelope := join(unsigned, sig)
	if _, e = VerifyEnvelope(envelope, p.public, profile); e != nil {
		return nil, e
	}
	return envelope, nil
}

func composeProtected(r ComposeRequest, p *composePlan) ([]byte, error) {
	envelope, e := composeProfile(p, r.Signer, 3)
	if e != nil {
		return nil, e
	}
	if e = recheckCompose(r, p); e != nil {
		return nil, e
	}
	return envelope, nil
}

// ComposeProtected03 creates fresh candidate ciphertext. Use durable replay for retries.
func ComposeProtected03(request ComposeRequest) ([]byte, error) {
	r := captureCompose(request)
	p, e := authorizeCompose(r)
	if e != nil {
		return nil, e
	}
	defer clear(p.text)
	return composeProtected(r, p)
}

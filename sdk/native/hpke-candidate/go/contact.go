package hpke

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strings"

	whatwg "github.com/nationallibraryofnorway/whatwg-url/url"
	"golang.org/x/net/idna"
)

const contactStatementDomain = "ZT/contact-reader/authorization/v1"
const contactFieldDomain = "ZT/contact-field/commitment/v1"

// ValidateContactOrigin01 enforces the maintained canonical ASCII HTTPS origin grammar.
func ValidateContactOrigin01(origin string) error {
	if !contactOrigin(origin) {
		return ErrShape
	}
	return nil
}

// ContactExpected is independently supplied historical scope, not current permission.
type ContactExpected struct {
	Account, RootFingerprint, Contact, RoutingDigest []byte
	Origin                                           string
}

// ContactStatement is genuine owned historical provenance. Its zero value is invalid.
type ContactStatement struct {
	raw                                                         []byte
	account                                                     [16]byte
	origin                                                      string
	fingerprint, manifestDigest, readerID, digest, rootWriterID [32]byte
	readerPoint, rootPoint                                      [65]byte
	version, readerGeneration, issued, until                    uint64
}

// ContactField is signature integrity over opaque ciphertext; it is not decryption or access authority.
type ContactField struct {
	raw    []byte
	digest [32]byte
}

func (s *ContactStatement) Bytes() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.raw...)
}
func (f *ContactField) Bytes() []byte {
	if f == nil {
		return nil
	}
	return append([]byte(nil), f.raw...)
}
func (f *ContactField) Digest() []byte {
	if f == nil || len(f.raw) == 0 {
		return nil
	}
	return append([]byte(nil), f.digest[:]...)
}

func contactOrigin(s string) bool {
	if len(s) < 9 || len(s) > 512 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	u, e := whatwg.Parse(s)
	if e != nil || u.Scheme() != "https" || u.Username() != "" || u.Password() != "" || u.Pathname() != "/" || u.Search() != "" || u.Hash() != "" || "https://"+u.Host() != s {
		return false
	}
	// UTS46 section4.1 criterion4: with CheckHyphens=false a decoded
	// U-label must not start xn--. x/net's current IDNA implementation omits
	// this rule; apply it to decoded labels, not a hostname exception list.
	for _, label := range strings.Split(u.Hostname(), ".") {
		if strings.HasPrefix(label, "xn--") {
			decoded, err := idna.Punycode.ToUnicode(label)
			onlyASCII := true
			for _, c := range decoded {
				if c > 127 {
					onlyASCII = false
					break
				}
			}
			if err != nil || onlyASCII || strings.HasPrefix(decoded, "xn--") {
				return false
			}
		}
	}
	return true
}
func contactNonzero(b []byte, n int) bool { return len(b) == n && !bytes.Equal(b, make([]byte, n)) }
func contactPositive(v uint64) bool       { return v > 0 && v <= 0x7fffffffffffffff }
func contactTranscript(domain string, b []byte) []byte {
	out := append([]byte(domain), 0)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
	return append(out, b...)
}
func contactVerify(point, raw []byte, domain string) error {
	if len(raw) < 64 || len(point) != 65 {
		return ErrShape
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil {
		return ErrShape
	}
	sig := raw[len(raw)-64:]
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		return ErrAuthentication
	}
	digest := sha256.Sum256(contactTranscript(domain, raw[:len(raw)-64]))
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s) {
		return ErrAuthentication
	}
	return nil
}

// VerifyContactStatement02 rechecks an accepted generation-one profile02 manifest
// at the statement's declared issue time. It never advances or resets live trust.
func VerifyContactStatement02(input []byte, accepted *Manifest, account []byte, origin string, fingerprint []byte) (*ContactStatement, error) {
	if len(input) < 314 || len(input) > 817 || accepted == nil || accepted.profile != 2 || accepted.generation != 1 || !contactNonzero(account, 16) || !contactNonzero(fingerprint, 32) || !contactOrigin(origin) {
		return nil, ErrShape
	}
	b := append([]byte(nil), input...)
	n := int(binary.BigEndian.Uint16(b[38:40]))
	if !bytes.Equal(b[:6], []byte("ZTKA\x01\x03")) || n < 9 || n > 512 || len(b) != 305+n || !contactNonzero(b[6:22], 16) || !contactNonzero(b[22:38], 16) {
		return nil, ErrShape
	}
	at := 40 + n
	st := &ContactStatement{raw: b, origin: string(b[40:at])}
	if !contactOrigin(st.origin) || st.origin != origin || binary.BigEndian.Uint64(b[at:at+8]) != 1 {
		return nil, ErrAuthentication
	}
	st.version = binary.BigEndian.Uint64(b[at+8 : at+16])
	st.readerGeneration = binary.BigEndian.Uint64(b[at+16 : at+24])
	at += 24
	copy(st.account[:], b[22:38])
	copy(st.fingerprint[:], b[at:at+32])
	at += 32
	copy(st.manifestDigest[:], b[at:at+32])
	at += 32
	copy(st.readerID[:], b[at:at+32])
	at += 32
	copy(st.readerPoint[:], b[at:at+65])
	at += 65
	st.issued = binary.BigEndian.Uint64(b[at : at+8])
	st.until = binary.BigEndian.Uint64(b[at+8 : at+16])
	if !contactPositive(st.version) || !contactPositive(st.readerGeneration) || !contactPositive(st.issued) || !contactPositive(st.until) || st.until <= st.issued || st.until-st.issued > 86400000 || !contactNonzero(st.fingerprint[:], 32) || !contactNonzero(st.manifestDigest[:], 32) || !contactNonzero(st.readerID[:], 32) {
		return nil, ErrShape
	}
	// Only this private historical replay removes a local comparison floor, and
	// only on owned copies of already authenticated evidence of the same identity.
	previous := *accepted
	previous.comparison = 0
	root := accepted.rootTrust()
	root.comparison = 0
	m, e := VerifyManifest(accepted.raw, root, &previous, 2, st.issued)
	if e != nil {
		return nil, e
	}
	reader := manifestKey(m, 2, st.readerID[:])
	var writer []byte
	for i := 0; i < int(m.raw[150]); i++ {
		w := m.raw[151+i*149 : 151+(i+1)*149]
		if w[0] == 6 {
			writer = w
		}
	}
	if !activeKey(reader, st.issued, 12) || !activeKey(writer, st.issued, 0) || binary.BigEndian.Uint16(reader[130:132]) != 12 || binary.BigEndian.Uint16(writer[130:132]) != 0 || st.account != m.account || !bytes.Equal(st.account[:], account) || st.version != m.version || st.manifestDigest != m.digest || !bytes.Equal(st.readerPoint[:], reader[33:98]) || st.issued < m.issued || st.until > m.expires || st.until > binary.BigEndian.Uint64(reader[140:148]) || st.until > binary.BigEndian.Uint64(writer[140:148]) {
		return nil, ErrAuthentication
	}
	copy(st.rootPoint[:], writer[33:98])
	copy(st.rootWriterID[:], writer[1:33])
	pin := append([]byte("ZTRP\x02"), account...)
	pin = binary.BigEndian.AppendUint64(pin, 1)
	pin = append(pin, st.rootPoint[:]...)
	compared := sha256.Sum256(append([]byte("ZTSE/root-pin/v2\x00"), pin...))
	if compared != st.fingerprint || !bytes.Equal(compared[:], fingerprint) {
		return nil, ErrAuthentication
	}
	if e = contactVerify(st.rootPoint[:], b, contactStatementDomain); e != nil {
		return nil, e
	}
	st.digest = sha256.Sum256(b)
	return st, nil
}

// ContactFieldInput carries already encrypted bytes. Neither name nor notes plaintext is accepted.
type ContactFieldInput struct {
	Kind                                 byte
	SealRevision                         uint64
	RequestID, Encapsulation, Ciphertext []byte
}

func contactExpected(st *ContactStatement, e ContactExpected) bool {
	return st != nil && len(st.raw) > 0 && contactNonzero(e.Account, 16) && contactNonzero(e.RootFingerprint, 32) && contactNonzero(e.Contact, 16) && contactNonzero(e.RoutingDigest, 32) && contactOrigin(e.Origin) && bytes.Equal(e.Account, st.account[:]) && bytes.Equal(e.RootFingerprint, st.fingerprint[:]) && e.Origin == st.origin
}
func contactUnsigned(st *ContactStatement, e ContactExpected, f ContactFieldInput) ([]byte, error) {
	if !contactExpected(st, e) || (f.Kind != 1 && f.Kind != 2) || !contactPositive(f.SealRevision) || !contactNonzero(f.RequestID, 16) || len(f.Encapsulation) != 65 || len(f.Ciphertext) < 17 || len(f.Ciphertext) > 2064 || (f.Kind == 1 && len(f.Ciphertext) > 272) {
		return nil, ErrShape
	}
	if x, _ := elliptic.Unmarshal(elliptic.P256(), f.Encapsulation); x == nil {
		return nil, ErrShape
	}
	out := append([]byte("ZTCO\x01"), f.Kind)
	out = append(out, e.Account...)
	out = append(out, e.Contact...)
	for _, v := range []uint64{f.SealRevision, 1, st.version, st.readerGeneration} {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	for _, v := range [][]byte{st.readerID[:], st.manifestDigest[:], st.digest[:], e.RoutingDigest, f.RequestID, st.rootWriterID[:], f.Encapsulation} {
		out = append(out, v...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(f.Ciphertext)))
	return append(out, f.Ciphertext...), nil
}

func VerifyContactField01(input []byte, st *ContactStatement, expected ContactExpected) (*ContactField, error) {
	if len(input) < 396 || len(input) > 2443 || !contactExpected(st, expected) {
		return nil, ErrShape
	}
	b := append([]byte(nil), input...)
	if !bytes.Equal(b[:5], []byte("ZTCO\x01")) || uint64(len(b)) != 379+uint64(binary.BigEndian.Uint32(b[311:315])) {
		return nil, ErrShape
	}
	f := ContactFieldInput{Kind: b[5], SealRevision: binary.BigEndian.Uint64(b[38:46]), RequestID: b[198:214], Encapsulation: b[246:311], Ciphertext: b[315 : len(b)-64]}
	unsigned, e := contactUnsigned(st, expected, f)
	if e != nil || !bytes.Equal(unsigned, b[:len(b)-64]) {
		return nil, ErrAuthentication
	}
	if e = contactVerify(st.rootPoint[:], b, contactFieldDomain); e != nil {
		return nil, e
	}
	return &ContactField{raw: b, digest: sha256.Sum256(b)}, nil
}

package hpke

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// RootTrust is created only from a separately compared generation-one root pin.
type RootTrust struct {
	account [16]byte
	point   [65]byte
}

// Manifest is owned cryptographic provenance, not live or durable authority.
type Manifest struct {
	raw                                  []byte
	profile, predecessor                 byte
	version, issued, expires, comparison uint64
	digest                               [32]byte
	account                              [16]byte
	root                                 [65]byte
}

func EnrollRoot(pin, compared []byte) (*RootTrust, error) {
	if len(pin) != 94 || len(compared) != 32 || !bytes.Equal(pin[:5], []byte("ZTRP\x02")) || binary.BigEndian.Uint64(pin[21:29]) != 1 || bytes.Equal(pin[5:21], make([]byte, 16)) {
		return nil, ErrShape
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pin[29:])
	if x == nil || y == nil {
		return nil, ErrShape
	}
	digest := sha256.Sum256(append([]byte("ZTSE/root-pin/v2\x00"), pin...))
	if !bytes.Equal(digest[:], compared) {
		return nil, ErrAuthentication
	}
	r := &RootTrust{}
	copy(r.account[:], pin[5:21])
	copy(r.point[:], pin[29:])
	return r, nil
}
func manifestNumber(b []byte, at int) (uint64, error) {
	v := binary.BigEndian.Uint64(b[at : at+8])
	if v > 0x7fffffffffffffff {
		return 0, ErrShape
	}
	return v, nil
}
func manifestWindow(issued, expiry, now uint64) bool {
	return now > 0 && now <= 0x7fffffffffffffff && issued > 0 && expiry > issued && expiry-issued <= 86400000 && issued <= now+300000 && now < expiry
}

// VerifyManifest accepts genesis02, exact successors, or alternate valid signatures
// for the same unsigned current manifest. No profile downgrade or03 genesis.
func VerifyManifest(input []byte, root *RootTrust, previous *Manifest, expected byte, now uint64) (*Manifest, error) {
	if root == nil || (expected != 2 && expected != 3) || len(input) < 364 || len(input) > 9753 || now == 0 || now > 0x7fffffffffffffff {
		return nil, ErrShape
	}
	b := append([]byte(nil), input...)
	if !bytes.Equal(b[:4], []byte("ZTMA")) || b[4] != expected {
		return nil, ErrShape
	}
	offset := 0
	predecessor := byte(2)
	if expected == 3 {
		offset = 2
		if b[5] != 3 || (b[6] != 2 && b[6] != 3) {
			return nil, ErrShape
		}
		predecessor = b[6]
	}
	count := int(b[150+offset])
	if count < 1 || count > 64 || len(b) != 215+offset+149*count {
		return nil, ErrShape
	}
	generation, err := manifestNumber(b, 21+offset)
	if err != nil || generation != 1 {
		return nil, ErrShape
	}
	version, err := manifestNumber(b, 29+offset)
	if err != nil || version == 0 {
		return nil, ErrShape
	}
	issued, err := manifestNumber(b, 37+offset)
	if err != nil {
		return nil, err
	}
	expiry, err := manifestNumber(b, 45+offset)
	if err != nil || !manifestWindow(issued, expiry, now) {
		return nil, ErrShape
	}
	if !bytes.Equal(b[5+offset:21+offset], root.account[:]) || !bytes.Equal(b[85+offset:150+offset], root.point[:]) {
		return nil, ErrAuthentication
	}
	roots, archives := 0, 0
	seen := map[string]bool{}
	var last []byte
	for i := 0; i < count; i++ {
		w := b[151+offset+i*149 : 151+offset+(i+1)*149]
		role := w[0]
		if role < 1 || role > 6 {
			return nil, ErrShape
		}
		scope := binary.BigEndian.Uint16(w[130:132])
		allowed := []uint16{0, 4, 12, 4, 2, 1, 0}[role]
		if (role == 3 && (scope != 4 && scope != 8 && scope != 12)) || (role != 3 && scope != allowed) {
			return nil, ErrShape
		}
		deviceBound := role == 1 || role == 4
		lineBound := deviceBound || role == 5
		if bytes.Equal(w[98:114], make([]byte, 16)) == deviceBound || bytes.Equal(w[114:130], make([]byte, 16)) == lineBound {
			return nil, ErrShape
		}
		from, e := manifestNumber(w, 132)
		if e != nil {
			return nil, e
		}
		until, e := manifestNumber(w, 140)
		if e != nil || from > until || (w[148] != 1 && w[148] != 2) {
			return nil, ErrShape
		}
		if last != nil && bytes.Compare(last, w[:33]) >= 0 {
			return nil, ErrShape
		}
		last = w[:33]
		public := w[33:98]
		x, y := elliptic.Unmarshal(elliptic.P256(), public)
		if x == nil || y == nil || seen[string(public)] {
			return nil, ErrShape
		}
		seen[string(public)] = true
		algorithm := []byte{1, 1}
		if role <= 3 {
			algorithm = []byte{0, 16}
		}
		id := sha256.Sum256(append(append([]byte("ZTSE/key/v1\x00"), algorithm...), public...))
		if !bytes.Equal(id[:], w[1:33]) {
			return nil, ErrAuthentication
		}
		if role == 6 {
			roots++
			if !bytes.Equal(public, root.point[:]) || w[148] != 1 || from > issued || until < expiry {
				return nil, ErrShape
			}
		}
		if role == 2 && w[148] == 1 {
			archives++
		}
	}
	if roots != 1 || archives != 1 {
		return nil, ErrShape
	}
	unsigned := b[:len(b)-64]
	sig := b[len(b)-64:]
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		return nil, ErrAuthentication
	}
	label := []byte("ZTSE/manifest/v2\x00")
	if expected == 3 {
		label = []byte("ZTSE/manifest/v3\x00")
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(unsigned)))
	sum := sha256.Sum256(append(append(label, length...), unsigned...))
	x, y := elliptic.Unmarshal(elliptic.P256(), root.point[:])
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, sum[:], r, s) {
		return nil, ErrAuthentication
	}
	digest := sha256.Sum256(unsigned)
	prevDigest := b[53+offset : 85+offset]
	if previous == nil {
		if expected != 2 || version != 1 || !bytes.Equal(prevDigest, make([]byte, 32)) {
			return nil, ErrAuthentication
		}
	} else {
		if previous.account != root.account || previous.root != root.point || now < previous.comparison {
			return nil, ErrAuthentication
		}
		if version == previous.version {
			if expected != previous.profile || predecessor != previous.predecessor || digest != previous.digest {
				return nil, ErrAuthentication
			}
		} else {
			if previous.version == 0x7fffffffffffffff || version != previous.version+1 || !bytes.Equal(prevDigest, previous.digest[:]) || expected < previous.profile || (expected == 3 && predecessor != previous.profile) {
				return nil, ErrAuthentication
			}
			if expected == 3 && previous.profile == 2 && !manifestWindow(previous.issued, previous.expires, now) {
				return nil, ErrAuthentication
			}
		}
	}
	return &Manifest{b, expected, predecessor, version, issued, expiry, now, digest, root.account, root.point}, nil
}
func (m *Manifest) Digest() [32]byte { return m.digest }
func (m *Manifest) Version() uint64  { return m.version }

package hpke

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// ElectionRecord carries independently authenticated application fields, not packet echoes.
// Binary and numeric fields are closed sets; numbers use positive signed-storage integers.
type ElectionRecord struct {
	Bytes   map[string][]byte
	Numbers map[string]uint64
}
type ElectionProof struct {
	accepted ElectionRecord
	manifest *Manifest
}

var acceptedUUIDs = []string{"accountId", "deviceId", "lineId", "oldBindingId", "newBindingId"}
var acceptedTimes = []string{"vaultGeneration", "oldBindingGeneration", "newBindingGeneration", "priorManifestVersion", "acceptedManifestVersion", "acceptedAtMs"}
var acceptedDigests = []string{"rootFingerprint", "oldBindingProofDigest", "selectedReaderKeyId", "priorManifestDigest", "priorSignedManifestSha256", "acceptedManifestDigest", "acceptedSignedManifestSha256", "electionCoreSha256", "electionCommitment", "electionBundleSha256"}
var currentUUIDs = []string{"accountId", "deviceId", "lineId", "bindingId"}
var currentTimes = []string{"bindingGeneration", "vaultGeneration", "manifestVersion", "comparedAtMs", "permissionExpiresAtMs", "profile", "manifestProfile"}
var currentDigests = []string{"selectedReaderKeyId", "rootFingerprint", "manifestDigest", "electionCommitment", "electionBundleSha256"}

func electionRecord(input ElectionRecord, current bool) (ElectionRecord, error) {
	uuids, times, digests := acceptedUUIDs, acceptedTimes, acceptedDigests
	if current {
		uuids, times, digests = currentUUIDs, currentTimes, currentDigests
	}
	out := ElectionRecord{Bytes: map[string][]byte{}, Numbers: map[string]uint64{}}
	if len(input.Bytes) != len(uuids)+len(digests) || len(input.Numbers) != len(times) {
		return out, ErrShape
	}
	for _, group := range []struct {
		names []string
		size  int
	}{{uuids, 16}, {digests, 32}} {
		for _, name := range group.names {
			v := input.Bytes[name]
			if len(v) != group.size || bytes.Equal(v, make([]byte, group.size)) {
				return out, ErrShape
			}
			out.Bytes[name] = append([]byte(nil), v...)
		}
	}
	for _, name := range times {
		v := input.Numbers[name]
		if v == 0 || v > 0x7fffffffffffffff {
			return out, ErrShape
		}
		out.Numbers[name] = v
	}
	if current && (out.Numbers["profile"] != 3 || out.Numbers["manifestProfile"] != 3 || out.Numbers["permissionExpiresAtMs"] <= out.Numbers["comparedAtMs"]) {
		return out, ErrShape
	}
	return out, nil
}
func electionFrame(domain string, payload []byte) []byte {
	b := append([]byte(domain+"\x00"), make([]byte, 4)...)
	binary.BigEndian.PutUint32(b[len(b)-4:], uint32(len(payload)))
	return append(b, payload...)
}
func electionHash(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func electionSignature(point, raw []byte, domain string, payload []byte) bool {
	if len(point) != 65 || len(raw) != 64 {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil {
		return false
	}
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	order := elliptic.P256().Params().N
	if r.Sign() <= 0 || r.Cmp(order) >= 0 || s.Sign() <= 0 || s.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		return false
	}
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, electionHash(electionFrame(domain, payload)), r, s)
}

// VerifyAcceptedElection03 binds original evidence to independently authenticated expectations.
func VerifyAcceptedElection03(bundle, expectedCore []byte, record ElectionRecord, prior *Manifest, signed02, signed03, devicePoint, ownerPoint []byte) (*ElectionProof, error) {
	if len(bundle) != 628 || len(expectedCore) != 500 || prior == nil || prior.profile != 2 {
		return nil, ErrShape
	}
	a, err := electionRecord(record, false)
	if err != nil {
		return nil, err
	}
	n, b := a.Numbers, a.Bytes
	bundle = append([]byte(nil), bundle...)
	core := bundle[:500]
	if !bytes.Equal(signed02, prior.raw) || n["acceptedAtMs"] < prior.comparison || !manifestWindow(prior.issued, prior.expires, n["acceptedAtMs"]) || !bytes.Equal(core, expectedCore) || !bytes.Equal(core[:8], []byte{'Z', 'T', 'P', 'E', 3, 1, 2, 3}) || !bytes.Equal(core[496:], make([]byte, 4)) {
		return nil, ErrAuthentication
	}
	for _, part := range [][2]int{{56, 72}, {352, 384}, {400, 432}, {432, 464}, {464, 496}} {
		if bytes.Equal(core[part[0]:part[1]], make([]byte, part[1]-part[0])) {
			return nil, ErrAuthentication
		}
	}
	positions := map[string]int{"accountId": 8, "deviceId": 24, "lineId": 40, "oldBindingId": 72, "oldBindingProofDigest": 104, "rootFingerprint": 136, "priorManifestDigest": 184, "acceptedManifestDigest": 224, "selectedReaderKeyId": 256}
	for name, at := range positions {
		if !bytes.Equal(core[at:at+len(b[name])], b[name]) {
			return nil, ErrAuthentication
		}
	}
	for name, at := range map[string]int{"oldBindingGeneration": 88, "newBindingGeneration": 96, "vaultGeneration": 168, "priorManifestVersion": 176, "acceptedManifestVersion": 216} {
		v, e := manifestNumber(core, at)
		if e != nil || v != n[name] {
			return nil, ErrAuthentication
		}
	}
	issued, err := manifestNumber(core, 384)
	if err != nil {
		return nil, err
	}
	expires, err := manifestNumber(core, 392)
	if err != nil || issued == 0 || issued > n["acceptedAtMs"] || n["acceptedAtMs"] >= expires || expires-issued > 300000 || n["newBindingGeneration"] <= n["oldBindingGeneration"] || n["vaultGeneration"] != 1 || n["priorManifestVersion"] == 0x7fffffffffffffff || n["acceptedManifestVersion"] != n["priorManifestVersion"]+1 {
		return nil, ErrAuthentication
	}
	for name, value := range map[string][]byte{"priorSignedManifestSha256": signed02, "acceptedSignedManifestSha256": signed03, "electionCoreSha256": core, "electionBundleSha256": bundle, "electionCommitment": electionFrame("ZTSE/line/payload-profile/commitment/v1", core)} {
		if !bytes.Equal(electionHash(value), b[name]) {
			return nil, ErrAuthentication
		}
	}
	root := &RootTrust{account: prior.account, point: prior.root}
	m, err := VerifyManifest(signed03, root, prior, 3, n["acceptedAtMs"])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(m.account[:], b["accountId"]) || m.version != n["acceptedManifestVersion"] || !bytes.Equal(m.digest[:], b["acceptedManifestDigest"]) || prior.version != n["priorManifestVersion"] || !bytes.Equal(prior.digest[:], b["priorManifestDigest"]) {
		return nil, ErrAuthentication
	}
	pin := append([]byte("ZTRP\x02"), m.account[:]...)
	pin = append(pin, 0, 0, 0, 0, 0, 0, 0, 1)
	pin = append(pin, m.root[:]...)
	if !bytes.Equal(electionHash(append([]byte("ZTSE/root-pin/v2\x00"), pin...)), b["rootFingerprint"]) {
		return nil, ErrAuthentication
	}
	for i, point := range [][]byte{devicePoint, ownerPoint} {
		if !bytes.Equal(electionHash(append([]byte("ZTSE/key/v1\x00\x01\x01"), point...)), core[288+i*32:320+i*32]) {
			return nil, ErrAuthentication
		}
	}
	if !electionSignature(devicePoint, bundle[500:564], "ZTSE/line/payload-profile/device/v1", core) || !electionSignature(ownerPoint, bundle[564:], "ZTSE/line/payload-profile/owner/v1", append(append([]byte(nil), core...), electionHash(bundle[500:564])...)) {
		return nil, ErrAuthentication
	}
	return &ElectionProof{accepted: a, manifest: m}, nil
}

// AcceptedManifest returns an opaque verified snapshot suitable for continuing the chain.
func (p *ElectionProof) AcceptedManifest() *Manifest {
	if p == nil {
		return nil
	}
	return p.manifest
}

// RequireCurrentElection03 verifies present external authority; historical signatures never renew it.
func RequireCurrentElection03(proof *ElectionProof, m *Manifest, record ElectionRecord, now uint64) (ElectionRecord, error) {
	if proof == nil || proof.manifest == nil || m == nil {
		return ElectionRecord{}, ErrShape
	}
	c, err := electionRecord(record, true)
	if err != nil {
		return c, err
	}
	a := proof.accepted
	n, b := c.Numbers, c.Bytes
	if now < a.Numbers["acceptedAtMs"] || now < n["comparedAtMs"] || now >= n["permissionExpiresAtMs"] || now < m.comparison || !manifestWindow(m.issued, m.expires, now) {
		return c, ErrAuthentication
	}
	for cn, an := range map[string]string{"accountId": "accountId", "deviceId": "deviceId", "lineId": "lineId", "bindingId": "newBindingId", "selectedReaderKeyId": "selectedReaderKeyId", "rootFingerprint": "rootFingerprint", "electionCommitment": "electionCommitment", "electionBundleSha256": "electionBundleSha256"} {
		if !bytes.Equal(b[cn], a.Bytes[an]) {
			return c, ErrAuthentication
		}
	}
	if n["bindingGeneration"] != a.Numbers["newBindingGeneration"] || n["vaultGeneration"] != 1 || n["manifestVersion"] < a.Numbers["acceptedManifestVersion"] || m.profile != 3 || m.version != n["manifestVersion"] || m.root != proof.manifest.root || m.account != proof.manifest.account || !bytes.Equal(m.account[:], b["accountId"]) || !bytes.Equal(m.digest[:], b["manifestDigest"]) {
		return c, ErrAuthentication
	}
	for _, digest := range m.lineage {
		if digest == proof.manifest.digest {
			return c, nil
		}
	}
	return c, ErrAuthentication
}

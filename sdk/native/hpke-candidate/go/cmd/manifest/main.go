package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"os"
)

func unhex(s string) []byte {
	v, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return v
}
func must(m *hpke.Manifest, e error) *hpke.Manifest {
	if e != nil {
		panic(e)
	}
	return m
}
func refuse(_ *hpke.Manifest, e error) {
	if e == nil {
		panic("must refuse")
	}
}
func main() {
	var d struct {
		Now         uint64 `json:"nowMs"`
		Pin         string `json:"rootPinHex"`
		Fingerprint string `json:"rootFingerprintHex"`
		Manifests   map[string]struct {
			Signed string `json:"signedHex"`
			Digest string `json:"semanticDigestHex"`
		} `json:"manifests"`
	}
	if e := json.NewDecoder(io.LimitReader(os.Stdin, 1000000)).Decode(&d); e != nil {
		panic(e)
	}
	pin, fingerprint := unhex(d.Pin), unhex(d.Fingerprint)
	root, e := hpke.EnrollRoot(pin, fingerprint)
	if e != nil {
		panic(e)
	}
	row := func(name string) []byte { return unhex(d.Manifests[name].Signed) }
	p := must(hpke.VerifyManifest(row("prior02"), root, nil, 2, d.Now))
	next := must(hpke.VerifyManifest(row("successor03"), root, p, 3, d.Now))
	after := must(hpke.VerifyManifest(row("after03"), root, next, 3, d.Now))
	alternate := must(hpke.VerifyManifest(row("alternateSignature03"), root, next, 3, d.Now))
	if next.Digest() != alternate.Digest() || after.Version() != 3 {
		panic("identity")
	}
	for name, snapshot := range map[string]*hpke.Manifest{"prior02": p, "successor03": next, "after03": after} {
		digest := snapshot.Digest()
		if !bytes.Equal(digest[:], unhex(d.Manifests[name].Digest)) {
			panic("digest")
		}
	}
	refuse(hpke.VerifyManifest(row("successor03"), root, nil, 3, d.Now))
	refuse(hpke.VerifyManifest(row("genesis03ContractOnly"), root, nil, 3, d.Now))
	refuse(hpke.VerifyManifest(row("sameVersionFork03"), root, next, 3, d.Now))
	refuse(hpke.VerifyManifest(row("prior02"), root, next, 2, d.Now))
	refuse(hpke.VerifyManifest(row("after03"), root, p, 3, d.Now))
	refuse(hpke.VerifyManifest(row("successor03"), root, p, 3, d.Now-1))
	refuse(hpke.VerifyManifest(row("successor03"), root, p, 2, d.Now))
	for _, time := range []uint64{0, d.Now + 86400001, ^uint64(0)} {
		refuse(hpke.VerifyManifest(row("successor03"), root, p, 3, time))
	}
	original := row("successor03")
	captured := append([]byte(nil), original...)
	snapshot := must(hpke.VerifyManifest(captured, root, p, 3, d.Now))
	clear(captured)
	if snapshot.Digest() != next.Digest() {
		panic("alias")
	}
	for at := range original {
		bad := append([]byte(nil), original...)
		bad[at] ^= 128
		refuse(hpke.VerifyManifest(bad, root, p, 3, d.Now))
	}
	for _, size := range []int{0, 4, 363, len(original) - 1} {
		refuse(hpke.VerifyManifest(original[:size], root, p, 3, d.Now))
	}
	refuse(hpke.VerifyManifest(append(original, 0), root, p, 3, d.Now))
	for at := range pin {
		bad := append([]byte(nil), pin...)
		bad[at] ^= 128
		if _, e := hpke.EnrollRoot(bad, fingerprint); e == nil {
			panic("root mutation")
		}
	}
	fmt.Println("manifest roots,02/03 chain,current semantic identity,fork,gap,downgrade,clock and corruption controls passed")
}

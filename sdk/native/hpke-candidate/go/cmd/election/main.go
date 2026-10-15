package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func main() {
	var f map[string]json.RawMessage
	if e := json.NewDecoder(os.Stdin).Decode(&f); e != nil {
		panic(e)
	}
	b := func(name string) []byte {
		var s string
		if e := json.Unmarshal(f[name], &s); e != nil {
			panic(e)
		}
		v, e := base64.StdEncoding.Strict().DecodeString(s)
		if e != nil {
			panic(e)
		}
		return v
	}
	record := func(name string) hpke.ElectionRecord {
		var raw map[string]json.RawMessage
		if e := json.Unmarshal(f[name], &raw); e != nil {
			panic(e)
		}
		r := hpke.ElectionRecord{Bytes: map[string][]byte{}, Numbers: map[string]uint64{}}
		for k, v := range raw {
			if v[0] == '"' {
				var s string
				if e := json.Unmarshal(v, &s); e != nil {
					panic(e)
				}
				x, e := base64.StdEncoding.Strict().DecodeString(s)
				if e != nil {
					panic(e)
				}
				r.Bytes[k] = x
			} else {
				var n uint64
				if e := json.Unmarshal(v, &n); e != nil {
					panic(e)
				}
				r.Numbers[k] = n
			}
		}
		return r
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	if e != nil {
		panic(e)
	}
	prior, e := hpke.VerifyManifest(b("signed02"), root, nil, 2, 10000)
	if e != nil {
		panic(e)
	}
	verify := func(bundle, core []byte, a hpke.ElectionRecord) (*hpke.ElectionProof, error) {
		return hpke.VerifyAcceptedElection03(bundle, core, a, prior, b("signed02"), b("signed03"), b("deviceSigningPoint"), b("ownerApprovalPoint"))
	}
	proof, e := verify(b("bundle"), b("core"), record("accepted"))
	if e != nil {
		panic(e)
	}
	if _, e = hpke.RequireCurrentElection03(proof, proof.AcceptedManifest(), record("authority"), 30000); e != nil {
		panic(e)
	}
	count := 1
	for name := range record("accepted").Bytes {
		if name == "newBindingId" {
			continue
		}
		a := record("accepted")
		a.Bytes[name][0] ^= 1
		if _, e = verify(b("bundle"), b("core"), a); e == nil {
			panic(name)
		}
		count++
	}
	for name := range record("accepted").Numbers {
		a := record("accepted")
		a.Numbers[name] = 0
		if _, e = verify(b("bundle"), b("core"), a); e == nil {
			panic(name)
		}
		count++
	}
	for name := range record("authority").Bytes {
		a := record("authority")
		a.Bytes[name][0] ^= 1
		if _, e = hpke.RequireCurrentElection03(proof, proof.AcceptedManifest(), a, 30000); e == nil {
			panic(name)
		}
		count++
	}
	for name := range record("authority").Numbers {
		a := record("authority")
		a.Numbers[name] = 0
		if _, e = hpke.RequireCurrentElection03(proof, proof.AcceptedManifest(), a, 30000); e == nil {
			panic(name)
		}
		count++
	}
	for _, at := range []int{500, 564} {
		bundle := b("bundle")
		bundle[at] ^= 1
		a := record("accepted")
		h := sha256.Sum256(bundle)
		a.Bytes["electionBundleSha256"] = h[:]
		if _, e = verify(bundle, b("core"), a); e == nil {
			panic("signature after rehash")
		}
		count++
	}
	for _, now := range []uint64{0, 9999, record("authority").Numbers["permissionExpiresAtMs"], 0x8000000000000000} {
		if _, e = hpke.RequireCurrentElection03(proof, proof.AcceptedManifest(), record("authority"), now); e == nil {
			panic("time")
		}
		count++
	}
	a := record("accepted")
	a.Bytes["extra"] = make([]byte, 16)
	if _, e = verify(b("bundle"), b("core"), a); e == nil {
		panic("extra")
	}
	count++
	context := hpke.ElectedContext{Message: b("message"), Peer: "+12", Now: 30000}
	opened, e := hpke.OpenSoftwareElected03(b("envelope"), proof.AcceptedManifest(), proof, record("authority"), b("readerScalar"), context)
	if e != nil {
		panic(e)
	}
	var expected string
	if e = json.Unmarshal(f["bodyText"], &expected); e != nil {
		panic(e)
	}
	if opened != expected {
		panic("plaintext")
	}
	count++
	raw := b("envelope")
	for i := range raw {
		mutated := append([]byte(nil), raw...)
		mutated[i] ^= 1
		if _, e = hpke.OpenSoftwareElected03(mutated, proof.AcceptedManifest(), proof, record("authority"), b("readerScalar"), context); e == nil {
			panic("corrupt envelope")
		}
	}
	wrong := context
	wrong.Message = append([]byte(nil), context.Message...)
	wrong.Message[0] ^= 1
	if _, e = hpke.OpenSoftwareElected03(raw, proof.AcceptedManifest(), proof, record("authority"), b("readerScalar"), wrong); e == nil {
		panic("message")
	}
	count++
	wrong = context
	wrong.Peer = "+13"
	if _, e = hpke.OpenSoftwareElected03(raw, proof.AcceptedManifest(), proof, record("authority"), b("readerScalar"), wrong); e == nil {
		panic("peer")
	}
	count++

	fmt.Printf("native accepted/current election %d controls passed\n", count)
}

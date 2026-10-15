package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"math/big"
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
	check := func(e error) {
		if e != nil {
			panic(e)
		}
	}
	refuse := func(e error) {
		if e == nil {
			panic("unexpected acceptance")
		}
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	check(e)
	prior, e := hpke.VerifyManifest(b("predecessor"), root, nil, 2, 10000)
	check(e)
	active, e := hpke.VerifyManifest(b("activation"), root, prior, 2, 10000)
	check(e)
	successor, e := hpke.VerifyManifest(b("successor"), root, active, 2, 10000)
	check(e)
	revoked, e := hpke.VerifyManifest(b("revoked"), root, active, 2, 10000)
	check(e)
	scope := hpke.OriginalScope{Peer: "+12"}
	copy(scope.Account[:], b("account"))
	copy(scope.Device[:], b("device"))
	copy(scope.Line[:], b("line"))
	copy(scope.Interval[:], b("interval"))
	copy(scope.Connector[:], b("connector"))
	copy(scope.ReadGrant[:], b("readGrant"))
	copy(scope.Reader[:], b("originalReader"))
	var event [16]byte
	copy(event[:], b("event"))
	raw, approval, installation := b("selection"), b("approval"), b("installation")
	selection, e := hpke.VerifyOriginalReplySelection02(raw, approval, installation, active, 10000, scope)
	check(e)
	for i := range raw {
		bad := append([]byte(nil), raw...)
		bad[i] ^= 1
		_, e = hpke.VerifyOriginalReplySelection02(bad, approval, installation, active, 10000, scope)
		refuse(e)
	}
	for _, which := range []bool{false, true} {
		sig := append([]byte(nil), approval...)
		if which {
			sig = append([]byte(nil), installation...)
		}
		s := new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(sig[32:]))
		s.FillBytes(sig[32:])
		a, z := sig, installation
		if which {
			a, z = approval, sig
		}
		_, e = hpke.VerifyOriginalReplySelection02(raw, a, z, active, 10000, scope)
		refuse(e)
	}
	for _, when := range []uint64{0, 20000, ^uint64(0)} {
		_, e = hpke.VerifyOriginalReplySelection02(raw, approval, installation, active, when, scope)
		refuse(e)
	}
	_, e = hpke.VerifyOriginalReplySelection02(raw, approval, installation, prior, 10000, scope)
	refuse(e)
	wrongScope := scope
	wrongScope.Connector[0] ^= 1
	_, e = hpke.VerifyOriginalReplySelection02(raw, approval, installation, active, 10000, wrongScope)
	refuse(e)
	authority := func(m *hpke.Manifest) hpke.OriginalAuthority {
		return hpke.OriginalAuthority{Scope: scope, Revision: "1", Now: 10000, Expires: 20000, Manifest: m}
	}
	var expected string
	check(json.Unmarshal(f["text"], &expected))
	for _, m := range []*hpke.Manifest{active, successor} {
		calls := 0
		value, e := hpke.OpenSoftwareOriginalReply02(b("inbound"), event, active, selection, scope, b("originalScalar"), func() (hpke.OriginalAuthority, error) { calls++; return authority(m), nil })
		check(e)
		if value != expected || calls != 2 {
			panic("opening/call count")
		}
	}
	for _, mutate := range []func(*hpke.OriginalAuthority){func(a *hpke.OriginalAuthority) { a.Revision = "2" }, func(a *hpke.OriginalAuthority) { a.Now = 9999 }, func(a *hpke.OriginalAuthority) { a.Now = 20000 }, func(a *hpke.OriginalAuthority) { a.Expires = 10000 }, func(a *hpke.OriginalAuthority) { a.Scope.ReadGrant[0] ^= 1 }, func(a *hpke.OriginalAuthority) { a.Manifest = successor }, func(a *hpke.OriginalAuthority) { a.Manifest = revoked }} {
		calls := 0
		value, e := hpke.OpenSoftwareOriginalReply02(b("inbound"), event, active, selection, scope, b("originalScalar"), func() (hpke.OriginalAuthority, error) {
			calls++
			a := authority(active)
			if calls == 2 {
				mutate(&a)
			}
			return a, nil
		})
		refuse(e)
		if value != "" || calls != 2 {
			panic("final refusal")
		}
	}
	for _, name := range []string{"archiveOnly", "inbound"} {
		calls := 0
		scalar := b("originalScalar")
		m := active
		if name == "inbound" {
			m = revoked
		}
		value, e := hpke.OpenSoftwareOriginalReply02(b(name), event, active, selection, scope, scalar, func() (hpke.OriginalAuthority, error) { calls++; return authority(m), nil })
		refuse(e)
		if value != "" || calls != 1 {
			panic("early refusal")
		}
	}
	calls := 0
	badScalar := make([]byte, 32)
	badScalar[31] = 11
	_, e = hpke.OpenSoftwareOriginalReply02(b("inbound"), event, active, selection, scope, badScalar, func() (hpke.OriginalAuthority, error) { calls++; return authority(active), nil })
	refuse(e)
	if calls != 1 {
		panic("wrong key reached final")
	}
	badEvent := event
	badEvent[0] ^= 1
	_, e = hpke.OpenSoftwareOriginalReply02(b("inbound"), badEvent, active, selection, scope, b("originalScalar"), func() (hpke.OriginalAuthority, error) { panic("wrong event called authority") })
	refuse(e)
	raw[0] ^= 1
	approval[0] ^= 1
	installation[0] ^= 1
	value, e := hpke.OpenSoftwareOriginalReply02(b("inbound"), event, active, selection, scope, b("originalScalar"), func() (hpke.OriginalAuthority, error) { return authority(active), nil })
	check(e)
	if value != expected {
		panic("selection alias")
	}
	fmt.Println("Go native original role3 selection, maintained ciphertext, current/final refusal and immutable proof controls passed")
}

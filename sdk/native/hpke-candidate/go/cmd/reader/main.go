package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"os"
)

func main() {
	var d map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1000000)).Decode(&d); err != nil {
		panic(err)
	}
	stringValue := func(name string) string {
		var s string
		if e := json.Unmarshal(d[name], &s); e != nil {
			panic(e)
		}
		return s
	}
	b := func(name string) []byte {
		v, e := base64.StdEncoding.Strict().DecodeString(stringValue(name))
		if e != nil {
			panic(e)
		}
		return v
	}
	var now uint64
	if e := json.Unmarshal(d["now"], &now); e != nil {
		panic(e)
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	if e != nil {
		panic(e)
	}
	m, e := hpke.VerifyManifest(b("manifest"), root, nil, 2, now)
	if e != nil {
		panic(e)
	}
	c := hpke.ArchiveContext{Account: b("account"), Device: b("device"), Line: b("line"), Reader: b("reader"), Peer: "+12", Now: now}
	scalar, raw := b("archiveScalar"), b("inbound")
	value, e := hpke.OpenSoftwareArchive02(raw, m, m, scalar, c)
	if e != nil || value != stringValue("text") {
		panic(fmt.Sprint("open ", e))
	}
	refuse := func(raw, scalar []byte, c hpke.ArchiveContext) {
		if _, e := hpke.OpenSoftwareArchive02(raw, m, m, scalar, c); e == nil {
			panic("must refuse")
		}
	}
	live, e := hpke.VerifyManifest(b("liveSuccessor"), root, m, 2, now)
	if e != nil {
		panic(e)
	}
	if value, e := hpke.OpenSoftwareArchive02(raw, m, live, scalar, c); e != nil || value != stringValue("text") {
		panic("live successor")
	}
	rotated, e := hpke.VerifyManifest(b("rotatedSuccessor"), root, m, 2, now)
	if e != nil {
		panic(e)
	}
	if _, e := hpke.OpenSoftwareArchive02(raw, m, rotated, scalar, c); e == nil {
		panic("rotated reader")
	}
	if _, e := hpke.OpenSoftwareArchive02(raw, m, rotated, make([]byte, 32), c); e != hpke.ErrAuthentication {
		panic("revocation before unwrap")
	}
	c.Peer = "+13"
	refuse(raw, scalar, c)
	c.Peer = "+12"
	for _, time := range []uint64{0, now - 1, 100000, ^uint64(0)} {
		c.Now = time
		refuse(raw, scalar, c)
	}
	c.Now = now
	for i := 0; i < 4; i++ {
		bad := c
		if i == 0 {
			bad.Account = make([]byte, 16)
		} else if i == 1 {
			bad.Device = make([]byte, 16)
		} else if i == 2 {
			bad.Line = make([]byte, 16)
		} else {
			bad.Reader = make([]byte, 32)
		}
		refuse(raw, scalar, bad)
	}
	refuse(b("outbound"), scalar, c)
	refuse(raw, make([]byte, 32), c)
	if _, e := hpke.OpenProtectedArchive02(); e == nil {
		panic("protected fallback")
	}
	for at := range raw {
		bad := append([]byte(nil), raw...)
		bad[at] ^= 128
		refuse(bad, scalar, c)
	}
	fmt.Println("actual maintained TS inbound opens natively; routing/time/profile/custody and all-byte corruption refuse")
}

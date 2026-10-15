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
	var batch struct{ Cases []map[string]json.RawMessage }
	must(json.NewDecoder(io.LimitReader(os.Stdin, 1000000)).Decode(&batch))
	if len(batch.Cases) != 14 {
		panic("case count")
	}
	for _, f := range batch.Cases {
		b := func(name string) []byte {
			var s string
			must(json.Unmarshal(f[name], &s))
			v, e := base64.StdEncoding.Strict().DecodeString(s)
			must(e)
			return v
		}
		record := func(name string) hpke.ElectionRecord {
			var values map[string]json.RawMessage
			must(json.Unmarshal(f[name], &values))
			r := hpke.ElectionRecord{Bytes: map[string][]byte{}, Numbers: map[string]uint64{}}
			for k, v := range values {
				if v[0] == '"' {
					var s string
					must(json.Unmarshal(v, &s))
					p, e := base64.StdEncoding.Strict().DecodeString(s)
					must(e)
					r.Bytes[k] = p
				} else {
					var n uint64
					must(json.Unmarshal(v, &n))
					r.Numbers[k] = n
				}
			}
			return r
		}
		root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
		must(e)
		prior, e := hpke.VerifyManifest(b("signed02"), root, nil, 2, 10000)
		must(e)
		proof, e := hpke.VerifyAcceptedElection03(b("bundle"), b("core"), record("accepted"), prior, b("signed02"), b("signed03"), b("deviceSigningPoint"), b("ownerApprovalPoint"))
		must(e)
		envelope := b("envelope")
		_, e = hpke.VerifyEnvelope(envelope, b("signerPoint"), 3)
		must(e)
		var p struct {
			Name, BodyText string
			Accept         bool
			Now            uint64
		}
		raw, e := json.Marshal(f)
		must(e)
		must(json.Unmarshal(raw, &p))
		value, e := hpke.OpenSoftwareElected03(envelope, proof.AcceptedManifest(), proof, record("authority"), b("readerScalar"), hpke.ElectedContext{Message: b("message"), Peer: "+12", Now: p.Now})
		if (e == nil) != p.Accept || (e == nil && value != p.BodyText) {
			panic("reader policy: " + p.Name)
		}
	}
	fmt.Println("14 authenticated native reader time-policy cases passed")
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}

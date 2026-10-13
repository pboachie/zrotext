// Public synthetic interoperability probe. No service or persistent custody effects.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

type request struct {
	Operation, Origin, Statement, Field string
	Fixture                             map[string]json.RawMessage
	Scalar                              string
	Cancel                              bool
}

func text(f map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(f[k], &s)
	return s
}
func decode(s string) []byte { b, _ := base64.StdEncoding.Strict().DecodeString(s); return b }
func run(r request) map[string]any {
	no := map[string]any{"accepted": false}
	if r.Operation == "origin" {
		return map[string]any{"accepted": hpke.ValidateContactOrigin01(r.Origin) == nil}
	}
	f := r.Fixture
	root, e := hpke.EnrollRoot(decode(text(f, "rootPin")), decode(text(f, "fingerprint")))
	if e != nil {
		return no
	}
	m, e := hpke.VerifyManifest(decode(text(f, "manifest")), root, nil, 2, 10000)
	if e != nil {
		return no
	}
	selected := r.Statement
	if selected == "" {
		selected = "statement"
	}
	if selected == "nextStatement" {
		m, e = hpke.VerifyManifest(decode(text(f, "nextManifest")), root, m, 2, 10000)
		if e != nil {
			return no
		}
	}
	st, e := hpke.VerifyContactStatement02(decode(text(f, selected)), m, decode(text(f, "account")), text(f, "origin"), decode(text(f, "fingerprint")))
	if e != nil {
		return no
	}
	if r.Operation == "statement" {
		return map[string]any{"accepted": true}
	}
	expected := hpke.ContactExpected{Account: decode(text(f, "account")), Origin: text(f, "origin"), RootFingerprint: decode(text(f, "fingerprint")), Contact: decode(text(f, "contact")), RoutingDigest: decode(text(f, "routing"))}
	field := r.Field
	if field == "" {
		field = "name"
	}
	b := decode(text(f, field))
	if r.Operation == "verify" {
		v, e := hpke.VerifyContactField01(b, st, expected)
		if e != nil {
			return no
		}
		return map[string]any{"accepted": true, "bytes": base64.StdEncoding.EncodeToString(v.Bytes())}
	}
	if len(b) < 396 {
		return no
	}
	input := hpke.ContactFieldInput{Kind: b[5], SealRevision: binary.BigEndian.Uint64(b[38:46]), RequestID: b[198:214], Encapsulation: b[246:311], Ciphertext: b[315 : len(b)-64]}
	scalar := make([]byte, 32)
	scalar[31] = 7
	if r.Scalar != "" {
		scalar = decode(r.Scalar)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if r.Cancel {
		cancel()
	}
	produced, e := hpke.ProduceSoftwareContactField01(ctx, scalar, st, expected, input)
	if e != nil {
		return no
	}
	return map[string]any{"accepted": true, "bytes": base64.StdEncoding.EncodeToString(produced.Bytes())}
}
func main() {
	var requests []request
	if json.NewDecoder(os.Stdin).Decode(&requests) != nil {
		os.Exit(2)
	}
	out := make([]map[string]any, 0, len(requests))
	for _, r := range requests {
		out = append(out, run(r))
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(2)
	}
}

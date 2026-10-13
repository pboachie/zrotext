// Synthetic historical interoperability probe; no service effects.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

type request struct {
	Operation, Mutation, Previous, PreviousStatement, Statement string
	Fixture                                                     map[string]json.RawMessage
	Replacements                                                *[]string
	Legacy                                                      *uint64
	Cancel                                                      bool
	Scalar                                                      string
}

func decode(s string) []byte  { b, _ := base64.StdEncoding.Strict().DecodeString(s); return b }
func encoded(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type fixture struct {
	st, next *hpke.ContactStatement
	expected hpke.ContactExpected
	fields   map[string]*hpke.ContactField
	wire     map[string]string
}

func setup(f map[string]string) (*fixture, error) {
	root, e := hpke.EnrollRoot(decode(f["rootPin"]), decode(f["fingerprint"]))
	if e != nil {
		return nil, e
	}
	m, e := hpke.VerifyManifest(decode(f["manifest"]), root, nil, 2, 10000)
	if e != nil {
		return nil, e
	}
	n, e := hpke.VerifyManifest(decode(f["nextManifest"]), root, m, 2, 10000)
	if e != nil {
		return nil, e
	}
	st, e := hpke.VerifyContactStatement02(decode(f["statement"]), m, decode(f["account"]), f["origin"], decode(f["fingerprint"]))
	if e != nil {
		return nil, e
	}
	next, e := hpke.VerifyContactStatement02(decode(f["nextStatement"]), n, decode(f["account"]), f["origin"], decode(f["fingerprint"]))
	if e != nil {
		return nil, e
	}
	x := &fixture{st: st, next: next, wire: f, expected: hpke.ContactExpected{Account: decode(f["account"]), Origin: f["origin"], RootFingerprint: decode(f["fingerprint"]), Contact: decode(f["contact"]), RoutingDigest: decode(f["routing"])}, fields: map[string]*hpke.ContactField{}}
	for _, name := range []string{"name", "notes", "replacement"} {
		s := st
		if name == "replacement" {
			s = next
		}
		v, e := hpke.VerifyContactField01(decode(f[name]), s, x.expected)
		if e != nil {
			return nil, e
		}
		x.fields[name] = v
	}
	return x, nil
}
func (x *fixture) statement(k string) *hpke.ContactStatement {
	if k == "update" || k == "clear" {
		return x.next
	}
	return x.st
}
func (x *fixture) replacements(k string) []*hpke.ContactField {
	switch k {
	case "create", "converted":
		return []*hpke.ContactField{x.fields["name"], x.fields["notes"]}
	case "update":
		return []*hpke.ContactField{x.fields["replacement"]}
	}
	return nil
}
func legacy(k string) uint64 {
	if k == "converted" {
		return 7
	}
	return 0
}
func (x *fixture) transition(k string) (*hpke.ContactTransition, error) {
	if k == "none" {
		return nil, nil
	}
	if k != "create" && k != "update" {
		return nil, errors.New("prior")
	}
	var previous *hpke.ContactTransition
	var e error
	if k == "update" {
		previous, e = x.transition("create")
		if e != nil {
			return nil, e
		}
	}
	m, e := hpke.VerifyContactMutation01(decode(x.wire[k]), x.statement(k), x.expected, legacy(k))
	if e != nil {
		return nil, e
	}
	return hpke.VerifyContactTransition01(previous, m, x.replacements(k))
}
func input(b []byte) (hpke.ContactMutationInput, error) {
	var m hpke.ContactMutationInput
	if len(b) != 368 {
		return m, errors.New("width")
	}
	m.Operation = b[5]
	m.ExpectedRevision = binary.BigEndian.Uint64(b[38:46])
	m.Revision = binary.BigEndian.Uint64(b[46:54])
	m.LegacyGeneration = binary.BigEndian.Uint64(b[214:222])
	copy(m.RequestID[:], b[54:70])
	copy(m.PreviousDigest[:], b[70:102])
	for i, s := range []*hpke.ContactSlot{&m.Name, &m.Notes} {
		at := 222 + 41*i
		s.Tag = b[at]
		s.SealRevision = binary.BigEndian.Uint64(b[at+1 : at+9])
		copy(s.Digest[:], b[at+9:at+41])
	}
	return m, nil
}
func run(r request) map[string]any {
	out := map[string]any{"accepted": false, "mutationVerified": false}
	wire := map[string]string{}
	for key, value := range r.Fixture {
		var text string
		if json.Unmarshal(value, &text) == nil {
			wire[key] = text
		}
	}
	x, e := setup(wire)
	if e != nil {
		return out
	}
	k := r.Mutation
	if k == "" {
		k = "create"
	}
	l := legacy(k)
	if r.Legacy != nil {
		l = *r.Legacy
	}
	if r.Operation == "produce-chain" {
		outputs := map[string]string{}
		var previous *hpke.ContactTransition
		var ps *hpke.ContactStatement
		for _, name := range []string{"create", "update", "clear", "converted"} {
			if name == "converted" {
				previous = nil
				ps = nil
			}
			m, err := input(decode(x.wire[name]))
			if err != nil {
				return out
			}
			if previous != nil {
				copy(m.PreviousDigest[:], previous.Mutation().Digest())
			}
			scalar := make([]byte, 32)
			scalar[31] = 7
			p, err := hpke.ProduceSoftwareContactMutation01(context.Background(), scalar, x.statement(name), x.expected, m, legacy(name), previous, ps, x.replacements(name))
			if err != nil {
				return out
			}
			outputs[name] = encoded(p.Bytes())
			previous = p.Verified()
			ps = x.statement(name)
		}
		out["accepted"] = true
		out["mutations"] = outputs
		return out
	}
	selected := x.statement(k)
	if r.Statement == "statement" {
		selected = x.st
	}
	if r.Statement == "nextStatement" {
		selected = x.next
	}
	prior := r.Previous
	if prior == "" {
		prior = "none"
		if k == "update" {
			prior = "create"
		}
		if k == "clear" {
			prior = "update"
		}
	}
	previous, e := x.transition(prior)
	if e != nil {
		return out
	}
	fs := x.replacements(k)
	if r.Replacements != nil {
		fs = nil
		for _, key := range *r.Replacements {
			fs = append(fs, x.fields[key])
		}
	}
	if r.Operation == "produce" {
		m, err := input(decode(x.wire[k]))
		if err != nil {
			return out
		}
		var ps *hpke.ContactStatement
		if previous != nil {
			ps = x.statement(prior)
		}
		switch r.PreviousStatement {
		case "none":
			ps = nil
		case "statement":
			ps = x.st
		case "nextStatement":
			ps = x.next
		}
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
		p, err := hpke.ProduceSoftwareContactMutation01(ctx, scalar, selected, x.expected, m, l, previous, ps, fs)
		if err != nil {
			return out
		}
		out["accepted"] = true
		out["bytes"] = encoded(p.Bytes())
		return out
	}
	m, e := hpke.VerifyContactMutation01(decode(x.wire[k]), selected, x.expected, l)
	if e != nil {
		return out
	}
	out["mutationVerified"] = true
	if r.Operation == "verify" {
		out["accepted"] = true
		return out
	}
	t, e := hpke.VerifyContactTransition01(previous, m, fs)
	if e != nil {
		return out
	}
	out["accepted"] = true
	retained := map[string]string{}
	for i, name := range []string{"name", "notes"} {
		if f := t.Field(byte(i + 1)); f != nil {
			retained[name] = encoded(f.Bytes())
		}
	}
	out["fields"] = retained
	return out
}
func main() {
	if hardware() {
		return
	}
	var rows []request
	if json.NewDecoder(os.Stdin).Decode(&rows) != nil {
		os.Exit(2)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, run(r))
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(2)
	}
}

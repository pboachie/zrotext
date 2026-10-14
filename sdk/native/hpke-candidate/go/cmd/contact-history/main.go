// Synthetic historical interoperability probe; no service effects.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

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
	if k != "create" && k != "update" && k != "clear" && k != "converted" {
		return nil, errors.New("prior")
	}
	var previous *hpke.ContactTransition
	var e error
	if k == "update" || k == "clear" {
		prior := "create"
		if k == "clear" {
			prior = "update"
		}
		previous, e = x.transition(prior)
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

type command struct {
	Operation, Path, Root, Adapter, Expected, Save, Mutation, Origin string
	Fixture                                                          map[string]string
	Maximum                                                          int
	Create, Reduction                                                bool
}

func main() {
	histories := map[string]*hpke.ContactHistory{}
	tokens := map[string]*hpke.ContactLocalToken{}
	defer func() {
		for _, h := range histories {
			h.Close()
		}
	}()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1000000)
	out := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		var c command
		result := map[string]any{"accepted": false}
		e := json.Unmarshal(scan.Bytes(), &c)
		if e == nil {
			result, e = run(c, histories, tokens)
		}
		if e != nil {
			result = map[string]any{"accepted": false}
		}
		if out.Encode(result) != nil {
			return
		}
	}
}
func run(c command, hs map[string]*hpke.ContactHistory, ts map[string]*hpke.ContactLocalToken) (map[string]any, error) {
	yes := map[string]any{"accepted": true}
	f := c.Fixture
	ctx := context.Background()
	if c.Operation == "root" {
		j, e := hpke.OpenJournal(c.Root, decode(f["rootPin"]), decode(f["fingerprint"]))
		if e != nil {
			return nil, e
		}
		defer j.Close()
		if _, e = j.AppendManifest(decode(f["manifest"]), 0, 10000, nil); e != nil {
			return nil, e
		}
		_, e = j.AppendManifest(decode(f["nextManifest"]), 1, 10000, nil)
		return yes, e
	}
	if c.Operation == "open" {
		if hs[c.Adapter] != nil {
			return nil, errors.New("already open")
		}
		origin := f["origin"]
		if c.Origin != "" {
			origin = c.Origin
		}
		h, e := hpke.OpenContactHistory(c.Path, c.Root, decode(f["rootPin"]), decode(f["fingerprint"]), origin, c.Maximum, c.Create, c.Reduction)
		if e != nil {
			return nil, e
		}
		hs[c.Adapter] = h
		return yes, nil
	}
	h := hs[c.Adapter]
	if h == nil {
		return nil, errors.New("adapter")
	}
	if c.Operation == "close-keep" {
		h.Close()
		return yes, nil
	}
	if c.Operation == "close" {
		h.Close()
		delete(hs, c.Adapter)
		return yes, nil
	}
	var r hpke.ContactHistoryResult
	var e error
	switch c.Operation {
	case "lookup":
		var id [16]byte
		copy(id[:], decode(f["contact"]))
		r, e = h.Lookup(ctx, id)
	case "accept":
		x, err := setup(f)
		if err != nil {
			return nil, err
		}
		t, err := x.transition(c.Mutation)
		if err != nil {
			return nil, err
		}
		r, e = h.Accept(ctx, ts[c.Expected], t, x.statement(c.Mutation))
	case "stop":
		r, e = h.MarkUnavailable(ctx, ts[c.Expected])
	default:
		return nil, errors.New("operation")
	}
	if e != nil {
		return nil, e
	}
	yes["kind"] = r.Kind
	yes["reason"] = r.Reason
	if c.Save != "" && r.Record != nil {
		ts[c.Save] = r.Record
	}
	if r.Metadata != nil {
		yes["revision"] = r.Metadata.Revision
		yes["digest"] = encoded(r.Metadata.Digest[:])
		yes["name"] = encoded(r.Metadata.Name.Digest[:])
		yes["notes"] = encoded(r.Metadata.Notes.Digest[:])
	}
	return yes, nil
}

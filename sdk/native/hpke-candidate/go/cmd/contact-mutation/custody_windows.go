package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func must(e error) {
	if e != nil {
		panic("protected transition consumer failed")
	}
}
func hardware() bool {
	if len(os.Args) == 1 {
		return false
	}
	if len(os.Args) != 2 || os.Args[1] != "--hardware" {
		panic("unsupported arguments")
	}
	receipt, e := os.CreateTemp("", "zrotext-contact-owned-*.json")
	must(e)
	key, e := h.CreateContactRootSigner(func(alias string) error {
		if e := json.NewEncoder(receipt).Encode(map[string]string{"pending_alias": alias}); e != nil {
			return e
		}
		return receipt.Sync()
	})
	if e != nil {
		_ = receipt.Close()
		must(e)
	}
	defer func() {
		alias := key.Alias()
		point, pointErr := key.PublicPoint()
		must(key.DeleteCreated())
		must(pointErr)
		if reopened, e := h.OpenContactRootSigner(alias, point); e == nil {
			reopened.Close()
			panic("deleted key reopened")
		}
		must(receipt.Truncate(0))
		_, e = receipt.Seek(0, 0)
		must(e)
		must(json.NewEncoder(receipt).Encode(map[string]bool{"owned_key_deleted": true}))
		must(receipt.Sync())
		must(receipt.Close())
		must(json.NewEncoder(os.Stdout).Encode(map[string]bool{"owned_key_deleted": true}))
	}()
	point, e := key.PublicPoint()
	must(e)
	if wrong, e := h.OpenHardwareSigner(key.Alias(), point); e == nil {
		wrong.Close()
		panic("contact alias entered envelope capability")
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{"alias": key.Alias(), "public": encoded(point)}))
	raw := map[string]json.RawMessage{}
	must(json.NewDecoder(os.Stdin).Decode(&raw))
	wire := map[string]string{}
	for name, value := range raw {
		var text string
		if json.Unmarshal(value, &text) == nil {
			wire[name] = text
		}
	}
	root, e := h.EnrollRoot(decode(wire["rootPin"]), decode(wire["fingerprint"]))
	must(e)
	m, e := h.VerifyManifest(decode(wire["manifest"]), root, nil, 2, 10000)
	must(e)
	n, e := h.VerifyManifest(decode(wire["nextManifest"]), root, m, 2, 10000)
	must(e)
	expected := h.ContactExpected{Account: decode(wire["account"]), Origin: wire["origin"], RootFingerprint: decode(wire["fingerprint"]), Contact: decode(wire["contact"]), RoutingDigest: decode(wire["routing"])}
	st, e := h.VerifyContactStatement02(decode(wire["statement"]), m, expected.Account, expected.Origin, expected.RootFingerprint)
	must(e)
	next, e := h.VerifyContactStatement02(decode(wire["nextStatement"]), n, expected.Account, expected.Origin, expected.RootFingerprint)
	must(e)
	fields := map[string]*h.ContactField{}
	encodedFields := map[string]string{}
	for _, name := range []string{"name", "notes", "replacement"} {
		selected := st
		if name == "replacement" {
			selected = next
		}
		b := decode(wire[name])
		if len(b) < 396 {
			panic("field shape")
		}
		f := h.ContactFieldInput{Kind: b[5], SealRevision: binary.BigEndian.Uint64(b[38:46]), RequestID: b[198:214], Encapsulation: b[246:311], Ciphertext: b[315 : len(b)-64]}
		produced, e := h.ProduceProtectedContactField01(context.Background(), key, selected, expected, f)
		must(e)
		fields[name] = produced.Verified()
		encodedFields[name] = encoded(produced.Bytes())
	}
	slot := func(name string) h.ContactSlot {
		f := fields[name]
		s := h.ContactSlot{Tag: 1, SealRevision: binary.BigEndian.Uint64(f.Bytes()[38:46])}
		copy(s.Digest[:], f.Digest())
		return s
	}
	var previous *h.ContactTransition
	var previousStatement *h.ContactStatement
	mutations := map[string]string{}
	for _, name := range []string{"create", "update", "clear", "converted"} {
		selected := st
		if name == "update" || name == "clear" {
			selected = next
		}
		m, e := input(decode(wire[name]))
		must(e)
		var replacements []*h.ContactField
		switch name {
		case "create", "converted":
			previous = nil
			previousStatement = nil
			m.Name = slot("name")
			m.Notes = slot("notes")
			replacements = []*h.ContactField{fields["name"], fields["notes"]}
		case "update":
			m.Name = slot("name")
			m.Notes = slot("replacement")
			replacements = []*h.ContactField{fields["replacement"]}
		case "clear":
			m.Notes = slot("replacement")
		}
		if previous != nil {
			copy(m.PreviousDigest[:], previous.Mutation().Digest())
		}
		call := func(ctx context.Context, closed bool, scope h.ContactExpected) (*h.ContactMutationProduction, error) {
			borrowed, err := h.OpenContactRootSigner(key.Alias(), point)
			if err != nil {
				return nil, err
			}
			defer borrowed.Close()
			if borrowed.DeleteCreated() == nil {
				panic("borrowed deletion accepted")
			}
			if closed {
				borrowed.Close()
			}
			return h.ProduceProtectedContactMutation01(ctx, borrowed, selected, scope, m, m.LegacyGeneration, previous, previousStatement, replacements)
		}
		result, e := call(context.Background(), false, expected)
		must(e)
		if _, e = call(context.Background(), true, expected); e == nil {
			panic("closed provider accepted")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e = call(cancelled, false, expected); e == nil {
			panic("cancelled accepted")
		}
		wrong := expected
		wrong.RoutingDigest = make([]byte, 32)
		if _, e = call(context.Background(), false, wrong); e == nil {
			panic("foreign scope accepted")
		}
		mutations[name] = encoded(result.Bytes())
		previous = result.Verified()
		previousStatement = selected
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"fields": encodedFields, "mutations": mutations, "refusals": 12}))
	return true
}

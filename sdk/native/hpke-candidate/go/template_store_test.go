package hpke

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestTemplateSaveMessageOwnsExactCASAndCanonicalReceipt(t *testing.T) {
	var s EncryptedTemplateScope
	for _, p := range [][]byte{s.Account[:], s.Device[:], s.Line[:], s.Interval[:], s.Template[:], s.PeerDigest[:], s.Reader[:], s.ManifestDigest[:]} {
		p[0] = 1
	}
	s.BindingGeneration = 1
	s.Revision = 128
	s.Expires = 20000
	s.TrustGeneration = 1
	s.ManifestVersion = 1
	aad, e := s.AAD()
	if e != nil {
		t.Fatal(e)
	}
	wire := append(aad, make([]byte, 86)...)
	wire[222] = 4
	binary.BigEndian.PutUint32(wire[287:291], uint32(len(wire)-291))
	r, e := NewTemplateSaveRequest(s, "11111111-1111-1111-1111-111111111111", 127, wire)
	if e != nil {
		t.Fatal(e)
	}
	wire[0] ^= 1
	body := r.Body()
	body[0] ^= 1
	headers := r.Headers()
	headers["idempotency-key"] = "mutated"
	if r.Body()[0] != 'Z' || r.Headers()["idempotency-key"] == "mutated" || r.Revision() != 128 {
		t.Fatal("request aliases caller")
	}
	if _, e = r.Receipt([]byte(`{"revision":128}`)); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{`{"revision":127}`, `{"revision":128,"revision":128}`, ` {"revision":128}`, `{"revision":128.0}`, `{"revision":128,"extra":0}`} {
		if _, e = r.Receipt([]byte(v)); e == nil {
			t.Fatal("noncanonical receipt accepted")
		}
	}
	for _, v := range [][]byte{append([]byte{239, 187, 191}, []byte(`{"revision":128}`)...), bytes.Repeat([]byte{' '}, 257)} {
		if _, e = r.Receipt(v); e == nil {
			t.Fatal("bounded receipt accepted")
		}
	}
	if _, e = NewTemplateSaveRequest(s, "11111111-1111-1111-1111-111111111111", 126, r.Body()); e == nil {
		t.Fatal("wrong CAS")
	}
	for _, id := range []string{"00000000-0000-0000-0000-000000000000", "INVALID", "11111111-1111-1111-1111-11111111111A"} {
		if _, e = NewTemplateSaveRequest(s, id, 127, r.Body()); e == nil {
			t.Fatal("request id accepted")
		}
	}
	s.Revision = 129
	if _, e = NewTemplateSaveRequest(s, "11111111-1111-1111-1111-111111111111", 128, r.Body()); e == nil {
		t.Fatal("revision cap")
	}
}

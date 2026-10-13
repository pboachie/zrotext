package hpke

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

const templateContentType = "application/vnd.zrotext.workflow-template.v1"

// TemplateSaveRequest captures only opaque ciphertext and CAS/request identity.
// It is not a review ticket, acknowledgement, owner credential, or send grant.
type TemplateSaveRequest struct {
	body     []byte
	request  string
	expected uint8
	digest   [32]byte
}

func NewTemplateSaveRequest(scope EncryptedTemplateScope, request string, expected uint8, envelope []byte) (*TemplateSaveRequest, error) {
	aad, e := scope.AAD()
	if e != nil || !originalUUID(request) || expected > 127 || scope.Revision != uint64(expected)+1 || len(envelope) < 308 || len(envelope) > 33075 {
		return nil, ErrShape
	}
	wire := append([]byte(nil), envelope...)
	if !bytes.Equal(wire[:222], aad) || int(binary.BigEndian.Uint32(wire[287:291])) != len(wire)-291 {
		return nil, ErrShape
	}
	return &TemplateSaveRequest{wire, request, expected, sha256.Sum256(wire)}, nil
}
func (r *TemplateSaveRequest) Body() []byte { return append([]byte(nil), r.body...) }
func (r *TemplateSaveRequest) Path() string { return "/v1/owner/workflow/templates" }
func (r *TemplateSaveRequest) Headers() map[string]string {
	return map[string]string{"content-type": templateContentType, "idempotency-key": r.request, "x-zrotext-template-revision": strconv.Itoa(int(r.expected))}
}
func (r *TemplateSaveRequest) Revision() uint8         { return r.expected + 1 }
func (r *TemplateSaveRequest) EncryptedDigest() string { return hex.EncodeToString(r.digest[:]) }

// Receipt requires the exact canonical response used by the maintained owner
// client, including no duplicate fields/BOM/whitespace. It acknowledges saving only.
func (r *TemplateSaveRequest) Receipt(body []byte) (uint8, error) {
	if r == nil || len(body) > 256 {
		return 0, ErrShape
	}
	canonical, _ := json.Marshal(struct {
		Revision uint8 `json:"revision"`
	}{r.Revision()})
	if !bytes.Equal(body, canonical) {
		return 0, ErrShape
	}
	return r.Revision(), nil
}

func parseTemplateScope(wire []byte) (EncryptedTemplateScope, error) {
	var s EncryptedTemplateScope
	if len(wire) < 308 || len(wire) > 33075 || !bytes.Equal(wire[:6], []byte{'Z', 'T', 'W', 'T', 1, 1}) || wire[222] != 4 || int(binary.BigEndian.Uint32(wire[287:291])) != len(wire)-291 {
		return s, ErrShape
	}
	for i, p := range [][]byte{s.Account[:], s.Device[:], s.Line[:], s.Interval[:], s.Template[:]} {
		copy(p, wire[6+i*16:22+i*16])
	}
	for i, p := range []*uint64{&s.BindingGeneration, &s.Revision, &s.Expires, &s.TrustGeneration, &s.ManifestVersion} {
		*p = binary.BigEndian.Uint64(wire[86+i*8 : 94+i*8])
	}
	for i, p := range [][]byte{s.PeerDigest[:], s.Reader[:], s.ManifestDigest[:]} {
		copy(p, wire[126+i*32:158+i*32])
	}
	_, e := s.AAD()
	return s, e
}

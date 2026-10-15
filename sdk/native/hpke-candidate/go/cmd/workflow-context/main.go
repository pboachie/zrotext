package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func must(e error) {
	if e != nil {
		panic("fixture setup refused")
	}
}
func bytes(v any) []byte {
	b, e := base64.StdEncoding.Strict().DecodeString(v.(string))
	must(e)
	return b
}
func scope(v map[string]any) h.WorkflowContextScope {
	var s h.WorkflowContextScope
	for k, p := range map[string][]byte{"accountId": s.Account[:], "deviceId": s.Device[:], "lineId": s.Line[:], "intervalId": s.Interval[:], "contextId": s.Context[:], "peerDigest": s.PeerDigest[:], "readerId": s.Reader[:], "manifestDigest": s.ManifestDigest[:]} {
		b := bytes(v[k])
		if len(b) != len(p) {
			panic("scope size")
		}
		copy(p, b)
	}
	for k, p := range map[string]*uint64{"bindingGeneration": &s.BindingGeneration, "revision": &s.Revision, "expiresMs": &s.Expires, "trustGeneration": &s.TrustGeneration, "manifestVersion": &s.ManifestVersion} {
		n, e := v[k].(json.Number).Int64()
		must(e)
		if n < 0 {
			panic("negative fixture")
		}
		*p = uint64(n)
	}
	kind, e := v["kind"].(json.Number).Int64()
	must(e)
	if kind < 0 || kind > 255 {
		panic("kind")
	}
	s.Kind = byte(kind)
	return s
}

type opener func(h.ContextAuthoritySource, h.WorkflowContextScope, h.WorkflowContextRole, []byte, []byte, byte) ([]byte, error)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--limits" {
		limits()
		return
	}
	open, cleanup := selectReader()
	defer cleanup()
	var input struct {
		Fixture map[string]any
		Cases   []struct {
			Scope                     map[string]any
			Envelope, Mode, Canonical string
			Clock                     []uint64
			FailFinal                 bool
			Role                      byte
			ProviderMode              byte
		}
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.UseNumber()
	must(decoder.Decode(&input))
	f := input.Fixture
	root, e := h.EnrollRoot(bytes(f["rootPin"]), bytes(f["fingerprint"]))
	must(e)
	m, e := h.VerifyManifest(bytes(f["manifest"]), root, nil, 2, 10000)
	must(e)
	var scalar []byte
	if v, ok := f["selectedScalar"]; ok {
		scalar = bytes(v)
	}
	defer clear(scalar)
	results := []any{}
	for _, c := range input.Cases {
		s := scope(c.Scope)
		calls := 0
		source := func() (*h.Manifest, uint64, error) {
			calls++
			if c.FailFinal && calls > 1 {
				return nil, 0, h.ErrAuthentication
			}
			at := calls - 1
			if at >= len(c.Clock) {
				at = len(c.Clock) - 1
			}
			return m, c.Clock[at], nil
		}
		result := map[string]any{"accepted": false}
		if c.Mode == "seal" {
			content := bytes(c.Canonical)
			wire, e := h.SealBoundedWorkflowContext(context.Background(), source, s, h.WorkflowContextRole(c.Role), content)
			if e == nil {
				result["accepted"] = true
				result["envelope"] = base64.StdEncoding.EncodeToString(wire)
			}
		} else {
			content, e := open(source, s, h.WorkflowContextRole(c.Role), scalar, bytes(c.Envelope), c.ProviderMode)
			if e == nil {
				result["accepted"] = true
				result["canonical"] = base64.StdEncoding.EncodeToString(content)
				clear(content)
			}
		}
		result["calls"] = calls
		results = append(results, result)
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": results}))
}

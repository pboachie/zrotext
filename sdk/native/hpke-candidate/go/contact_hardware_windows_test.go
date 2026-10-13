//go:build windows

package hpke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This fixture-only test can access private signing internals. No enrollment or
// statement-signing primitive is exported by the contact capability.
func TestContactProtectedHardware(t *testing.T) {
	source := os.Getenv("ZROTEXT_CONTACT_FIXTURE_ROOT")
	if source == "" {
		t.Skip("explicit synthetic protected fixture checkout required")
	}
	run := func(path string, payload any, args ...string) map[string]json.RawMessage {
		t.Helper()
		cmd := exec.Command("node", append([]string{path}, args...)...)
		if payload != nil {
			b, e := json.Marshal(payload)
			if e != nil {
				t.Fatal(e)
			}
			cmd.Stdin = bytes.NewReader(b)
		}
		out, e := cmd.Output()
		if e != nil {
			t.Fatal("synthetic oracle failed")
		}
		var v map[string]json.RawMessage
		if json.Unmarshal(out, &v) != nil {
			t.Fatal("oracle JSON")
		}
		return v
	}
	text := func(f map[string]json.RawMessage, k string) string {
		var v string
		if json.Unmarshal(f[k], &v) != nil {
			t.Fatal("fixture field")
		}
		return v
	}
	dec := func(s string) []byte {
		b, e := base64.StdEncoding.Strict().DecodeString(s)
		if e != nil {
			t.Fatal("fixture base64")
		}
		return b
	}
	put := func(f map[string]json.RawMessage, k string, b []byte) {
		f[k], _ = json.Marshal(base64.StdEncoding.EncodeToString(b))
	}
	interop := filepath.Join(source, "sdk/native/sealed-candidate/python/contact-producer-interop.mjs")
	f := run(filepath.Join(source, "sdk/native/sealed-candidate/python/contact-interop.mjs"), nil)
	receipt, e := os.CreateTemp("", "zrotext-contact-pending-*.json")
	if e != nil {
		t.Fatal(e)
	}
	key, e := CreateContactRootSigner(func(alias string) error {
		b, _ := json.Marshal(map[string]string{"alias": alias, "state": "pending"})
		if _, e := receipt.Write(b); e != nil {
			return e
		}
		return receipt.Sync()
	})
	if e != nil {
		_ = receipt.Close()
		t.Fatal("protected provider qualification failed")
	}
	defer func() {
		alias := key.Alias()
		point, _ := key.PublicPoint()
		if e := key.DeleteCreated(); e != nil {
			t.Error("exact owned key deletion failed")
			return
		}
		if reopened, e := OpenContactRootSigner(alias, point); e == nil {
			reopened.Close()
			t.Error("deleted key reopened")
		}
		_ = receipt.Truncate(0)
		_, _ = receipt.Seek(0, 0)
		_, _ = receipt.WriteString("{\"state\":\"deleted\"}")
		_ = receipt.Sync()
		_ = receipt.Close()
	}()
	point, e := key.PublicPoint()
	if e != nil {
		t.Fatal(e)
	}
	alias := key.Alias()
	if _, e := OpenHardwareSigner(alias, point); e == nil {
		t.Fatal("contact alias entered envelope capability")
	}
	template := run(interop, map[string]any{"fixture": f, "point": base64.StdEncoding.EncodeToString(point)}, "--root-template")
	f["rootPin"], f["fingerprint"] = template["rootPin"], template["fingerprint"]
	// Setup only: independently synthetic enrollment requires its own signatures.
	setupSign := func(domain string, unsigned []byte) []byte {
		digest := sha256.Sum256(contactTranscript(domain, unsigned))
		key.signer.native.mu.Lock()
		sig, e := key.signer.signDigest(digest[:])
		key.signer.native.mu.Unlock()
		if e != nil {
			t.Fatal(e)
		}
		return append(append([]byte(nil), unsigned...), sig...)
	}
	unsigned := dec(text(template, "manifestUnsigned"))
	put(f, "manifest", setupSign("ZTSE/manifest/v2", unsigned))
	next := append([]byte(nil), unsigned...)
	binary.BigEndian.PutUint64(next[29:37], 2)
	digest := sha256.Sum256(unsigned)
	copy(next[53:85], digest[:])
	put(f, "nextManifest", setupSign("ZTSE/manifest/v2", next))
	statements := run(interop, map[string]any{"fixture": f}, "--statement-template")
	put(f, "statement", setupSign(contactStatementDomain, dec(text(statements, "statementUnsigned"))))
	put(f, "nextStatement", setupSign(contactStatementDomain, dec(text(statements, "nextStatementUnsigned"))))
	root, e := EnrollRoot(dec(text(f, "rootPin")), dec(text(f, "fingerprint")))
	if e != nil {
		t.Fatal(e)
	}
	first, e := VerifyManifest(dec(text(f, "manifest")), root, nil, 2, 10000)
	if e != nil {
		t.Fatal(e)
	}
	second, e := VerifyManifest(dec(text(f, "nextManifest")), root, first, 2, 10000)
	if e != nil {
		t.Fatal(e)
	}
	var outputs []map[string]string
	for _, row := range []struct {
		field, statement string
		m                *Manifest
	}{{"name", "statement", first}, {"notes", "statement", first}, {"replacement", "nextStatement", second}} {
		st, e := VerifyContactStatement02(dec(text(f, row.statement)), row.m, dec(text(f, "account")), text(f, "origin"), dec(text(f, "fingerprint")))
		if e != nil {
			t.Fatal(e)
		}
		b := dec(text(f, row.field))
		input := ContactFieldInput{Kind: b[5], SealRevision: binary.BigEndian.Uint64(b[38:46]), RequestID: b[198:214], Encapsulation: b[246:311], Ciphertext: b[315 : len(b)-64]}
		expected := ContactExpected{Account: dec(text(f, "account")), Origin: text(f, "origin"), RootFingerprint: dec(text(f, "fingerprint")), Contact: dec(text(f, "contact")), RoutingDigest: dec(text(f, "routing"))}
		if row.field == "name" {
			func() {
				key.signer.native.mu.Lock()
				defer key.signer.native.mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() { _, e := ProduceProtectedContactField01(ctx, key, st, expected, input); done <- e }()
				select {
				case e := <-done:
					if e == nil {
						t.Fatal("blocked provider published")
					}
				case <-time.After(time.Second):
					t.Fatal("provider inspection escaped deadline")
				}
				if len(contactAdmission) != 1 {
					t.Fatal("blocked provider released admission")
				}
			}()
		}
		out, e := ProduceProtectedContactField01(context.Background(), key, st, expected, input)
		if e != nil {
			t.Fatal(e)
		}
		outputs = append(outputs, map[string]string{"bytes": base64.StdEncoding.EncodeToString(out.Bytes()), "statement": row.statement})
		reopened, e := OpenContactRootSigner(alias, point)
		if e != nil {
			t.Fatal(e)
		}
		reopened.Close()
		if _, e = ProduceProtectedContactField01(context.Background(), reopened, st, expected, input); e == nil {
			t.Fatal("closed provider accepted")
		}
	}
	oracle, e := filepath.Abs("../contact-field-interop.mjs")
	if e != nil {
		t.Fatal(e)
	}
	result := run(oracle, map[string]any{"fixture": f, "outputs": outputs}, source, "--consume")
	if string(result["verified"]) != "true" || string(result["fields"]) != "3" {
		t.Fatal("independent contact verification failed")
	}
	t.Log("3 actual protected fields independently verified; closed provider and envelope alias refused")
}

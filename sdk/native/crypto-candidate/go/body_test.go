package candidatebody

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestSharedVectorsAndTamperBoundaries(t *testing.T) {
	b, e := os.ReadFile("../../../../protocol/v1/vectors/ztse-body-text-01.json")
	if e != nil {
		t.Fatal(e)
	}
	type vectorCase struct{ Name, Hex, Verdict, Reason, Text, EnvelopeHex, CekHex string }
	var v struct {
		Status                        string
		TextCases, AuthenticatedCases []vectorCase
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if v.Status != "UNAPPROVED_TEST_ONLY" || len(v.AuthenticatedCases) != 7 {
		t.Fatal("wrong corpus")
	}
	for _, c := range v.TextCases {
		t.Run(c.Name, func(t *testing.T) {
			raw := unhex(t, c.Hex)
			s, e := Decode(raw)
			if c.Verdict == "accept" {
				if e != nil || s != string(raw) {
					t.Fatal(e)
				}
			} else if e == nil || e.Error() != c.Reason {
				t.Fatalf("%v expected %s", e, c.Reason)
			}
		})
	}
	for _, c := range v.AuthenticatedCases {
		t.Run(c.Name, func(t *testing.T) {
			// Test fixture extraction is not an envelope or authority verifier.
			env := unhex(t, c.EnvelopeHex)
			if env[4] != 1 && env[4] != 2 {
				t.Fatal("profile")
			}
			end := 10 + int(binary.BigEndian.Uint16(env[8:10]))
			n := int(binary.BigEndian.Uint32(env[end+12 : end+16]))
			aad := append([]byte(fmt.Sprintf("ZTSE/body/v%d\x00", env[4])), env[:end]...)
			a := [4][]byte{unhex(t, c.CekHex), env[end : end+12], aad, env[end+16 : end+16+n]}
			s, e := Open(a[0], a[1], a[2], a[3])
			if c.Verdict != "accept" {
				if e == nil || e.Error() != c.Reason {
					t.Fatalf("%v expected %s", e, c.Reason)
				}
				return
			}
			if e != nil || s != c.Text {
				t.Fatal("plaintext mismatch", e)
			}
			clone := func() [4][]byte {
				var b [4][]byte
				for i := range a {
					b[i] = append([]byte(nil), a[i]...)
				}
				return b
			}
			check := func(b [4][]byte, want error) {
				t.Helper()
				s, e := Open(b[0], b[1], b[2], b[3])
				if e != want || s != "" {
					t.Fatalf("%v expected %v", e, want)
				}
			}
			for i := range a {
				b := clone()
				b[i][len(b[i])-1] ^= 1
				check(b, ErrAuthentication)
				b = clone()
				b[i] = nil
				check(b, ErrShape)
			}
			damaged := clone()
			damaged[3][0] ^= 1
			check(damaged, ErrAuthentication)
			for i, n := range []int{31, 11, 36865, 32785} {
				b := clone()
				b[i] = make([]byte, n)
				check(b, ErrShape)
			}
		})
	}
}

func TestAuthenticatedBoundaries(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	nonce := bytes.Repeat([]byte{8}, 12)
	aad := bytes.Repeat([]byte{9}, 36864)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	for _, tc := range []struct {
		plain []byte
		err   error
	}{
		{bytes.Repeat([]byte{'a'}, 32768), nil},
		{[]byte{255}, ErrUtf8}, {[]byte{0}, ErrNul}, {[]byte{239, 187, 191}, ErrBom},
	} {
		encrypted := aead.Seal(nil, nonce, tc.plain, aad)
		got, err := Open(key, nonce, aad, encrypted)
		if err != tc.err || (err == nil && got != string(tc.plain)) {
			t.Fatalf("boundary: %v", err)
		}
		encrypted[0] ^= 1
		if _, err := Open(key, nonce, aad, encrypted); err != ErrAuthentication {
			t.Fatalf("tamper before text: %v", err)
		}
	}
}

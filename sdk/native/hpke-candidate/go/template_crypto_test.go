package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestTemplateContentLengthDoesNotWidenCEK(t *testing.T) {
	key, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	scalar := key.Bytes()
	defer clear(scalar)
	point := key.PublicKey().Bytes()
	for _, size := range []int{0, 1, 31, 32, 33, 32768, 32769} {
		plain := bytes.Repeat([]byte{7}, size)
		wrapped, e := sealTemplateHPKE(point, plain, []byte("synthetic-info"), []byte("synthetic-aad"))
		if e != nil {
			t.Fatal(e)
		}
		opened, e := openSoftwareContent(scalar, point, wrapped[:65], []byte("synthetic-info"), []byte("synthetic-aad"), wrapped[65:])
		if size == 0 || size > 32768 {
			if e == nil {
				t.Fatal("content length accepted")
			}
		} else if e != nil || !bytes.Equal(opened, plain) {
			t.Fatal("content mismatch", size, e)
		}
		clear(opened)
		cek, e := OpenSoftwareCEK(scalar, point, wrapped[:65], []byte("synthetic-info"), []byte("synthetic-aad"), wrapped[65:])
		if (e == nil) != (size == 32) {
			t.Fatal("public CEK width changed", size, e)
		}
		clear(cek)
	}
}

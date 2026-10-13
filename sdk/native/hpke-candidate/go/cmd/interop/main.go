package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"os"
)

func must(ok bool) {
	if !ok {
		panic("independent HPKE assertion failed")
	}
}
func main() {
	var corpus struct {
		Format string
		Cases  []map[string]any
	}
	must(json.NewDecoder(io.LimitReader(os.Stdin, 1000000)).Decode(&corpus) == nil)
	must(corpus.Format == "zrotext-native-hpke-interop-v1")
	must(len(corpus.Cases) == 6)
	for _, c := range corpus.Cases {
		var args [6][]byte
		for i, f := range []string{"recipient_private_hex", "recipient_public_hex", "enc_hex", "info_hex", "aad_hex", "ciphertext_hex"} {
			var e error
			args[i], e = hex.DecodeString(c[f].(string))
			must(e == nil)
		}
		open := func(a [6][]byte) ([]byte, error) { return hpke.OpenSoftwareCEK(a[0], a[1], a[2], a[3], a[4], a[5]) }
		clone := func() [6][]byte {
			var a [6][]byte
			for i := range args {
				a[i] = bytes.Clone(args[i])
			}
			return a
		}
		expected, e := hex.DecodeString(c["plaintext_hex"].(string))
		must(e == nil)
		plain, e := open(args)
		must(e == nil && bytes.Equal(plain, expected))
		clear(plain)
		for field := 0; field < 6; field++ {
			bad := clone()
			if len(bad[field]) == 0 {
				bad[field] = []byte{1}
			} else {
				bad[field][len(bad[field])-1] ^= 1
			}
			_, e := open(bad)
			must(e != nil)
		}
		for field, length := range []int{31, 64, 64, 36865, 36865, 47} {
			bad := clone()
			bad[field] = make([]byte, length)
			_, e := open(bad)
			must(e != nil)
		}
		bad := clone()
		clear(bad[0])
		_, e = open(bad)
		must(e != nil)
	}
	_, e := hpke.OpenProtectedCEK()
	must(e == hpke.ErrProtectedUnavailable)
	fmt.Println("Go: six independent HPKE cases plus context/shape/custody negatives passed")
}

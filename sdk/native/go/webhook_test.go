package webhook

import (
	"strings"
	"testing"
)

var key = []byte("0123456789abcdef0123456789abcdef")
var body = []byte(`{"event":"test"}`)

const signature = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405"

func TestServerVectorAndSymmetricWindow(t *testing.T) {
	for _, now := range []uint64{1700000000, 1700000300, 1699999700} {
		if err := Verify(key, "1700000000", signature, body, now, 300); err != nil {
			t.Fatal(err)
		}
	}
	for _, now := range []uint64{1700000301, 1699999699, ^uint64(0)} {
		if err := Verify(key, "1700000000", signature, body, now, 300); err != ErrTimestampOutOfWindow {
			t.Fatal(err)
		}
	}
}
func TestExactBodyKeyAndTimestamp(t *testing.T) {
	for _, c := range []struct {
		key, body []byte
		timestamp string
	}{
		{key, []byte(`{}`), "1700000000"}, {[]byte("wrong"), body, "1700000000"}, {key, body, "1700000001"},
	} {
		if err := Verify(c.key, c.timestamp, signature, c.body, 1700000000, 300); err != ErrSignatureMismatch {
			t.Fatal(err)
		}
	}
}
func TestMalformedHeaders(t *testing.T) {
	for _, ts := range []string{"", "01700000000", "1700000000.0", "-1", "1e9", "1700000000\n", "99999999999999999", "nonascii"} {
		if err := Verify(key, ts, signature, body, 1700000000, 300); err != ErrBadTimestamp {
			t.Fatalf("%q: %v", ts, err)
		}
	}
	for _, sig := range []string{"", "v1=aa", strings.ToUpper(signature), signature + "\n", "v2=" + signature[3:]} {
		if err := Verify(key, "1700000000", sig, body, 1700000000, 300); err != ErrBadSignatureFormat {
			t.Fatalf("%q: %v", sig, err)
		}
	}
}

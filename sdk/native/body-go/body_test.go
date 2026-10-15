package bodytext

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestEverySharedCandidateVector(t *testing.T) {
	raw, err := os.ReadFile("../../../protocol/v1/vectors/ztse-body-text-01.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Status    string
		TextCases []struct {
			Name, Hex, Verdict, Reason string
			Text                       *string
			TextLength                 *int
		}
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Status != "UNAPPROVED_TEST_ONLY" || len(vector.TextCases) == 0 {
		t.Fatal("unexpected corpus")
	}
	for _, c := range vector.TextCases {
		t.Run(c.Name, func(t *testing.T) {
			b, err := hex.DecodeString(c.Hex)
			if err != nil {
				t.Fatal(err)
			}
			text, err := Validate(b)
			if c.Verdict == "accept" {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(text), b) {
					t.Fatal("bytes changed")
				}
				if c.Text != nil && text != *c.Text {
					t.Fatal("text mismatch")
				}
				if c.TextLength != nil && len(text) != *c.TextLength {
					t.Fatal("length mismatch")
				}
			} else if err == nil || err.Error() != c.Reason {
				t.Fatalf("got %v, expected %s", err, c.Reason)
			}
		})
	}
}
func TestNormalizationAndMultibyteBounds(t *testing.T) {
	for _, b := range [][]byte{{'e', 0xcc, 0x81}, {0xc3, 0xa9}} {
		s, e := Validate(b)
		if e != nil || !bytes.Equal([]byte(s), b) {
			t.Fatal("normalization")
		}
	}
	if _, e := Validate(bytes.Repeat([]byte{0xc3, 0xa9}, 16384)); e != nil {
		t.Fatal(e)
	}
	if _, e := Validate(bytes.Repeat([]byte{0xc3, 0xa9}, 16385)); e != ErrLength {
		t.Fatal(e)
	}
}

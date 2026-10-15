// Package bodytext implements candidate ZTSE body text rules. It provides no
// envelope authentication, key handling, trust policy, or action authority.
package bodytext

import (
	"bytes"
	"errors"
	"unicode/utf8"
)

const MaxBodyTextBytes = 32768

var (
	ErrLength = errors.New("length")
	ErrNul    = errors.New("nul")
	ErrBom    = errors.New("bom")
	ErrUtf8   = errors.New("utf8")
)

// Validate returns strict UTF-8 without normalization or BOM stripping.
// Callers must authenticate the ciphertext and enforce trust/context first.
// Returned Go strings cannot promise memory zeroization; callers own lifecycle.
func Validate(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > MaxBodyTextBytes {
		return "", ErrLength
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return "", ErrNul
	}
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return "", ErrBom
	}
	if !utf8.Valid(raw) {
		return "", ErrUtf8
	}
	return string(raw), nil
}

// Package webhook verifies ZROtext webhooks using the exact raw request body.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const ToleranceSeconds uint64 = 300

var (
	ErrBadTimestamp         = errors.New("bad_timestamp")
	ErrTimestampOutOfWindow = errors.New("timestamp_out_of_window")
	ErrBadSignatureFormat   = errors.New("bad_signature_format")
	ErrSignatureMismatch    = errors.New("signature_mismatch")
)

// Verify checks the signature and a symmetric replay window. key contains the
// decoded signing secret. Callers must deduplicate event IDs after verification.
func Verify(key []byte, timestamp, signature string, body []byte, now, tolerance uint64) error {
	if len(timestamp) == 0 || len(timestamp) > 16 || (len(timestamp) > 1 && timestamp[0] == '0') {
		return ErrBadTimestamp
	}
	for _, c := range timestamp {
		if c < '0' || c > '9' {
			return ErrBadTimestamp
		}
	}
	seconds, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	var delta uint64
	if now >= seconds {
		delta = now - seconds
	} else {
		delta = seconds - now
	}
	if delta > tolerance {
		return ErrTimestampOutOfWindow
	}
	if !strings.HasPrefix(signature, "v1=") || len(signature) != 67 {
		return ErrBadSignatureFormat
	}
	for _, c := range signature[3:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrBadSignatureFormat
		}
	}
	digest, err := hex.DecodeString(signature[3:])
	if err != nil {
		return ErrBadSignatureFormat
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), digest) {
		return ErrSignatureMismatch
	}
	return nil
}

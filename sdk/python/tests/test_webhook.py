import base64
import unittest

from zrotext_client import (
    WebhookVerificationError,
    secret_from_base64url,
    sign_webhook,
    verify_webhook,
)

# Pinned in crates/server/src/webhook_egress.rs
# (signature_uses_exact_raw_body_and_timestamp).
KEY_BYTES = b"0123456789abcdef0123456789abcdef"
BODY = '{"event":"test"}'
TS = 1_700_000_000
SIG = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405"


def base(**override):
    args = dict(signing_key=KEY_BYTES, timestamp=str(TS), signature=SIG, body=BODY, now_seconds=TS)
    args.update(override)
    return args


class WebhookVerifyTest(unittest.TestCase):
    def reason(self, **override):
        with self.assertRaises(WebhookVerificationError) as ctx:
            verify_webhook(**base(**override))
        return ctx.exception.reason

    def test_signing_reproduces_server_vector(self):
        self.assertEqual(sign_webhook(KEY_BYTES, TS, BODY), SIG)
        self.assertEqual(sign_webhook(KEY_BYTES, TS, BODY.encode()), SIG)

    def test_valid_delivery_verifies_for_str_and_bytes(self):
        verify_webhook(**base())
        verify_webhook(**base(body=BODY.encode()))

    def test_exact_body_timestamp_and_secret_are_bound(self):
        self.assertEqual(self.reason(body='{ "event":"test"}'), "signature_mismatch")
        self.assertEqual(self.reason(timestamp=str(TS + 1)), "signature_mismatch")
        self.assertEqual(self.reason(signing_key=b"x" * 32), "signature_mismatch")

    def test_five_minute_window_is_inclusive_and_symmetric(self):
        verify_webhook(**base(now_seconds=TS + 300))
        verify_webhook(**base(now_seconds=TS - 300))
        self.assertEqual(self.reason(now_seconds=TS + 301), "timestamp_out_of_window")
        self.assertEqual(self.reason(now_seconds=TS - 301), "timestamp_out_of_window")

    def test_malformed_timestamp_and_signature(self):
        for t in ("", "01700000000", "1700000000.0", " 1700000000", "-1", "1e9"):
            self.assertEqual(self.reason(timestamp=t), "bad_timestamp", t)
        for s in ("", SIG[3:], SIG.upper(), SIG + "0", "v2=" + SIG[3:], SIG[:-1]):
            self.assertEqual(self.reason(signature=s), "bad_signature_format", s)

    def test_secret_from_base64url(self):
        raw = bytes(255 - i for i in range(32))
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.assertEqual(len(encoded), 43)
        self.assertEqual(secret_from_base64url(encoded), raw)
        with self.assertRaises(ValueError):
            secret_from_base64url("not+base64/")


if __name__ == "__main__":
    unittest.main()

import json
import os
import threading
import unittest
import urllib.request
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer

from zrotext_client import (
    AlphaApiError,
    AlphaClient,
    OutcomeUnknownError,
    requires_reconciliation,
)

MESSAGE = "7d3f1a52-0c1e-4b6a-9a77-3f2f7f0b1c11"
DEVICE = "0a8b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
CLIENT_ID = "11111111-2222-4333-8444-555555555555"
REQUEST = dict(
    client_message_id=CLIENT_ID,
    device_id=DEVICE,
    recipient_e164="+15550100001",
    test_case_id="smoke-1",
    expires_at_ms=1_900_000_000_000,
)


class Stub:
    """Local loopback server; handler(rec, h) writes the response."""

    def __init__(self, handler):
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                rec = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": self.rfile.read(length).decode() if length else "",
                }
                outer.seen.append(rec)
                handler(rec, self)

            do_GET = do_POST = _handle

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.server_address[1]
        # Bypass any proxy environment so the test never leaves loopback.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.client = AlphaClient(f"http://127.0.0.1:{port}", "test-token", timeout=2, opener=opener)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def reply_json(h, status, body, headers=None):
    payload = json.dumps(body).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(payload)))
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    h.end_headers()
    h.wfile.write(payload)


class AlphaClientTest(unittest.TestCase):
    def stub(self, handler):
        s = Stub(handler)
        self.addCleanup(s.close)
        return s

    def test_submit_sends_bearer_explicit_key_and_snake_case_body(self):
        s = self.stub(lambda r, h: reply_json(h, 202, {"message_id": MESSAGE, "created": True}))
        out = s.client.submit(idempotency_key="key-1.a_b", **REQUEST)
        self.assertEqual((out.message_id, out.created), (MESSAGE, True))
        rec = s.seen[0]
        self.assertEqual((rec["method"], rec["path"]), ("POST", "/v1/alpha/messages"))
        self.assertEqual(rec["headers"]["authorization"], "Bearer test-token")
        self.assertEqual(rec["headers"]["idempotency-key"], "key-1.a_b")
        self.assertEqual(
            json.loads(rec["body"]),
            {
                "client_message_id": CLIENT_ID,
                "device_id": DEVICE,
                "recipient_e164": "+15550100001",
                "test_case_id": "smoke-1",
                "expires_at_ms": 1_900_000_000_000,
            },
        )

    def test_submit_validates_before_any_request(self):
        s = self.stub(lambda r, h: reply_json(h, 202, {"message_id": MESSAGE, "created": True}))
        for bad in ("", "has space", "x" * 129, "café", None):
            with self.assertRaises(ValueError):
                s.client.submit(idempotency_key=bad, **REQUEST)
        with self.assertRaises(ValueError):
            s.client.submit(idempotency_key="k", **{**REQUEST, "recipient_e164": "5550100001"})
        with self.assertRaises(ValueError):
            s.client.submit(idempotency_key="k", **{**REQUEST, "test_case_id": "no spaces"})
        with self.assertRaises(ValueError):
            s.client.submit(idempotency_key="k", **{**REQUEST, "device_id": "nope"})
        self.assertEqual(s.seen, [])

    def test_idempotency_key_is_required(self):
        s = self.stub(lambda r, h: reply_json(h, 202, {"message_id": MESSAGE, "created": True}))
        with self.assertRaises(TypeError):
            s.client.submit(**REQUEST)

    def test_idempotent_replay_surfaces_created_false(self):
        s = self.stub(lambda r, h: reply_json(h, 202, {"message_id": MESSAGE, "created": False}))
        self.assertFalse(s.client.submit(idempotency_key="k", **REQUEST).created)

    def test_api_error_exposes_status_code_retry_after_and_is_not_retried(self):
        s = self.stub(lambda r, h: reply_json(h, 429, {"code": "rate_limited"}, {"Retry-After": "60"}))
        with self.assertRaises(AlphaApiError) as ctx:
            s.client.submit(idempotency_key="k", **REQUEST)
        self.assertEqual(
            (ctx.exception.status, ctx.exception.code, ctx.exception.retry_after_seconds),
            (429, "rate_limited", 60),
        )
        self.assertEqual(len(s.seen), 1)

    def test_bare_503_has_no_code(self):
        def handler(r, h):
            h.send_response(503)
            h.send_header("Retry-After", "1")
            h.send_header("Content-Length", "0")
            h.end_headers()

        s = self.stub(handler)
        with self.assertRaises(AlphaApiError) as ctx:
            s.client.get_status(MESSAGE)
        self.assertEqual((ctx.exception.status, ctx.exception.code, ctx.exception.retry_after_seconds), (503, None, 1))

    def test_transport_failure_is_unknown_outcome_and_not_retried(self):
        s = self.stub(lambda r, h: h.connection.close())
        with self.assertRaises(OutcomeUnknownError) as ctx:
            s.client.submit(idempotency_key="k", **REQUEST)
        self.assertEqual(ctx.exception.operation, "submit")
        self.assertEqual(len(s.seen), 1)

    def test_malformed_success_body_is_unknown_outcome(self):
        s = self.stub(lambda r, h: reply_json(h, 202, {"nope": True}))
        with self.assertRaises(OutcomeUnknownError):
            s.client.submit(idempotency_key="k", **REQUEST)

    def test_redirect_is_not_followed(self):
        s = Stub(lambda r, h: (h.send_response(307), h.send_header("Location", "http://127.0.0.1:1/"),
                               h.send_header("Content-Length", "0"), h.end_headers()))
        self.addCleanup(s.close)
        # The default opener is used here; keep loopback out of any proxy environment.
        with mock.patch.dict(os.environ, {"no_proxy": "127.0.0.1", "NO_PROXY": "127.0.0.1"}):
            client = AlphaClient(f"http://127.0.0.1:{s.server.server_address[1]}", "t", timeout=2)
        with self.assertRaises(AlphaApiError) as ctx:
            client.get_status(MESSAGE)
        self.assertEqual(ctx.exception.status, 307)
        self.assertEqual(len(s.seen), 1)

    def test_get_status_parses_snapshot_and_flags_unknown(self):
        body = {
            "message_id": MESSAGE,
            "device_id": DEVICE,
            "state": "unknown",
            "state_version": 4,
            "created_at_ms": 1,
            "updated_at_ms": 2,
        }
        s = self.stub(lambda r, h: reply_json(h, 200, body))
        st = s.client.get_status(MESSAGE)
        self.assertEqual((s.seen[0]["method"], s.seen[0]["path"]), ("GET", f"/v1/alpha/messages/{MESSAGE}"))
        self.assertEqual((st.state, st.state_version, st.created_at_ms, st.updated_at_ms), ("unknown", 4, 1, 2))
        self.assertTrue(requires_reconciliation(st.state))
        self.assertTrue(requires_reconciliation("delivery_unknown"))
        self.assertFalse(requires_reconciliation("delivered"))

    def test_cancel_204_then_409_conflict(self):
        calls = []

        def handler(r, h):
            calls.append(1)
            if len(calls) == 1:
                h.send_response(204)
                h.end_headers()
            else:
                reply_json(h, 409, {"code": "conflict"})

        s = self.stub(handler)
        self.assertIsNone(s.client.cancel(MESSAGE))
        self.assertEqual((s.seen[0]["method"], s.seen[0]["path"]), ("POST", f"/v1/alpha/messages/{MESSAGE}/cancel"))
        with self.assertRaises(AlphaApiError) as ctx:
            s.client.cancel(MESSAGE)
        self.assertEqual(ctx.exception.code, "conflict")


if __name__ == "__main__":
    unittest.main()

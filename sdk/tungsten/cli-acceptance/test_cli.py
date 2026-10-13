"""Synthetic subprocess acceptance for the generated CLI, never a live gateway."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IDENTITY = "11111111-2222-4333-8444-555555555555"
TOKEN = secrets.token_urlsafe(24)
KEY = "synthetic-cli-idempotency"


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.calls = []
        self.status = 503
        self.payload = {"code": "unavailable"}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                owner.calls.append((self.command, self.path, dict(self.headers), body))
                payload = json.dumps(owner.payload).encode()
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.env = {k:v for k,v in os.environ.items() if not k.startswith("ZROTEXT_") and k.upper() not in {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"}}
        self.env.update(ZROTEXT_API_KEY=TOKEN, XDG_CONFIG_HOME=self.scratch.name, NO_PROXY="127.0.0.1")
        self.base = [str(self.binary), "--json", "--base-url", f"http://127.0.0.1:{self.server.server_port}"]
        self.submit = ["public", "alpha-messages", "submit", "--client-message-id", IDENTITY,
                       "--device-id", IDENTITY, "--recipient-e164", "+15550100001", "--test-case-id", "synthetic",
                       "--expires-at-ms", "1999999999999", "--idempotency-key", KEY]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.scratch.cleanup()

    def invoke(self, args, expected):
        result = subprocess.run(self.base + args, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        for secret in (TOKEN, KEY):
            self.assertNotIn(secret, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_preview_and_partial_confirmation_send_nothing(self):
        for flags, code in [([], 6), (["--yes"], 6), (["--dry-run"], 0)]:
            value = self.invoke(self.submit + flags, code)
            self.assertEqual(value["request"]["headers"]["Authorization"], "<redacted>")
            self.assertEqual(value["request"]["headers"]["Idempotency-Key"], "<redacted>")
            self.assertEqual(value["safety"], "irreversible")
            self.assertTrue(value["confirmation_token"])
            self.assertEqual(self.calls, [])

    def test_missing_credentials_and_missing_idempotency_fail_before_send(self):
        del self.env["ZROTEXT_API_KEY"]
        value = self.invoke(self.submit + ["--yes", "--i-understand"], 7)
        self.assertEqual(value["category"], "AUTH_FAILED")
        self.env["ZROTEXT_API_KEY"] = TOKEN
        value = self.invoke(self.submit[:-2] + ["--yes", "--i-understand"], 2)
        self.assertEqual(value["category"], "VALIDATION_FAILED")
        self.assertEqual(self.calls, [])

    def test_confirmed_ambiguous_send_is_single_attempt(self):
        value = self.invoke(self.submit + ["--yes", "--i-understand"], 5)
        self.assertEqual(value["category"], "OUTCOME_UNKNOWN")
        self.assertEqual(value["trace"]["attempts"], 1)
        self.assertEqual(len(self.calls), 1)
        method, path, headers, body = self.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/alpha/messages"))
        headers = {k.lower():v for k,v in headers.items()}
        self.assertEqual(headers["authorization"], "Bearer " + TOKEN)
        self.assertEqual(headers["idempotency-key"], KEY)
        self.assertEqual(json.loads(body)["client_message_id"], IDENTITY)
        self.assertEqual(json.loads(body)["test_case_id"], "synthetic")

    def test_status_reconciliation_is_read_only_and_does_not_resubmit(self):
        self.status = 200
        self.payload = dict(message_id=IDENTITY, device_id=IDENTITY, state="unknown", state_version=1, created_at_ms=1, updated_at_ms=1)
        value = self.invoke(["public", "alpha-messages", "get-status", "--message-id", IDENTITY], 0)
        self.assertEqual(value["state"], "unknown")
        self.assertEqual([(c[0], c[1]) for c in self.calls], [("GET", "/v1/alpha/messages/" + IDENTITY)])

    def test_failed_status_read_makes_one_attempt(self):
        value = self.invoke(["public", "alpha-messages", "get-status", "--message-id", IDENTITY], 4)
        self.assertEqual(value["trace"]["attempts"], 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "GET")

    def test_auth_status_never_prints_credentials_or_calls_transport(self):
        self.invoke(["auth", "status"], 0)
        self.assertEqual(self.calls, [])


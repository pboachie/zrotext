"""Run every example in docs/SEND-FIRST-MESSAGE.md against a local stub or a pinned vector."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs" / "SEND-FIRST-MESSAGE.md").read_text(encoding="utf-8")
SPEC = json.loads((ROOT / "protocol/v1/openapi/public-v1.json").read_text(encoding="utf-8"))
SCHEMAS = SPEC["components"]["schemas"]

# Vector pinned by signature_uses_exact_raw_body_and_timestamp in crates/server/src/webhook_egress.rs.
SECRET = b"0123456789abcdef0123456789abcdef"
TIMESTAMP = "1700000000"
BODY = b'{"event":"test"}'
SIGNATURE = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405"

BEARER = "stub-bearer"
DEVICE = "00000000-0000-4000-8000-000000000001"
ACCEPTED = {"message_id": "00000000-0000-4000-8000-0000000000b1", "created": True}
STATUS = {"message_id": ACCEPTED["message_id"], "device_id": DEVICE, "state": "queued",
          "state_version": 1, "created_at_ms": 1790000000000, "updated_at_ms": 1790000000500}


def example(name):
    match = re.search(r"```\w+\n(?:# |// )example: " + re.escape(name) + r"\n(.*?)```", DOC, re.S)
    assert match, f"missing example {name}"
    return match.group(0).split("\n", 2)[2].rsplit("```", 1)[0]


def json_blocks():
    return [json.loads(text) for text in re.findall(r"```json\n(.*?)\n```", DOC, re.S)]


def conforms(value, schema):
    assert set(schema["required"]) <= set(value), value
    assert set(value) <= set(schema["properties"]), value
    for key, item in value.items():
        spec = schema["properties"][key]
        if "$ref" in spec:
            spec = SCHEMAS[spec["$ref"].rsplit("/", 1)[1]]
        if "enum" in spec:
            assert item in spec["enum"], (key, item)
        if "pattern" in spec:
            assert re.search(spec["pattern"], item), (key, item)
        kind = {"string": str, "integer": int, "boolean": bool}[spec["type"]]
        assert isinstance(item, kind), (key, item)


class Stub(BaseHTTPRequestHandler):
    seen = []

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        Stub.seen.append(("POST", self.path, dict(self.headers), json.loads(raw)))
        self._reply(202, ACCEPTED)

    def do_GET(self):
        Stub.seen.append(("GET", self.path, dict(self.headers), None))
        self._reply(200, STATUS)

    def log_message(self, *args):
        pass


class SendFirstMessageDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.env = dict(os.environ, ZT_BASE_URL=f"http://127.0.0.1:{cls.server.server_port}",
                       ZT_DEVICE_ID=DEVICE, MESSAGE_ID=ACCEPTED["message_id"])
        cls.env["ZT_API_KEY"] = BEARER

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Stub.seen.clear()

    def run_example(self, name, command, suffix):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"example{suffix}"
            path.write_text(example(name), encoding="utf-8")
            return subprocess.run(command(path), env=self.env, capture_output=True,
                                  text=True, timeout=30, check=True)

    def check_submit(self):
        method, path, headers, body = Stub.seen[-1]
        self.assertEqual((method, path), ("POST", "/v1/alpha/messages"))
        self.assertEqual(headers["Authorization"], "Bearer " + BEARER)
        self.assertEqual(headers["Idempotency-Key"], "demo-0001")
        conforms(body, SCHEMAS["AlphaSubmitRequest"])
        self.assertEqual(body["device_id"], DEVICE)

    def check_status(self):
        self.assertEqual(Stub.seen[-1][:2], ("GET", f"/v1/alpha/messages/{ACCEPTED['message_id']}"))
        self.assertEqual(Stub.seen[-1][2]["Authorization"], "Bearer " + BEARER)

    def test_documented_json_matches_the_schemas(self):
        accepted, status = json_blocks()
        conforms(accepted, SCHEMAS["AlphaAccepted"])
        conforms(status, SCHEMAS["AlphaStatus"])

    def test_documented_states_match_the_schema(self):
        listed = re.search(r"`state` is one of (.*?)\. The", DOC, re.S).group(1)
        self.assertEqual(re.findall(r"`(\w+)`", listed), SCHEMAS["MessageState"]["enum"])

    def test_documented_error_codes_exist(self):
        for code in ("invalid_request", "unauthorized", "payment_hold", "not_found", "conflict",
                     "rate_limited", "queue_full", "quota_exceeded", "billing_pending",
                     "unavailable", "recipient_suppressed"):
            self.assertIn(code, SCHEMAS["Error"]["properties"]["code"]["enum"])
            self.assertIn(f"`{code}`", DOC)

    @unittest.skipUnless(shutil.which("curl"), "curl not installed")
    def test_curl_examples(self):
        self.run_example("submit-curl", lambda p: ["sh", str(p)], ".sh")
        self.check_submit()
        self.run_example("status-curl", lambda p: ["sh", str(p)], ".sh")
        self.check_status()

    def test_python_examples(self):
        out = self.run_example("submit-python", lambda p: [sys.executable, str(p)], ".py")
        self.assertIn(ACCEPTED["message_id"], out.stdout)
        self.check_submit()
        out = self.run_example("status-python", lambda p: [sys.executable, str(p)], ".py")
        self.assertEqual(out.stdout.strip(), "queued")
        self.check_status()

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_javascript_examples(self):
        out = self.run_example("submit-js", lambda p: ["node", str(p)], ".mjs")
        self.assertIn(ACCEPTED["message_id"], out.stdout)
        self.check_submit()
        out = self.run_example("status-js", lambda p: ["node", str(p)], ".mjs")
        self.assertEqual(out.stdout.strip(), "queued")
        self.check_status()

    def test_python_webhook_verifier(self):
        scope = {}
        exec(example("webhook-verify-python"), scope)
        verify, now = scope["verify"], 1_700_000_100
        self.assertTrue(verify(SECRET, TIMESTAMP, BODY, SIGNATURE, now))
        self.assertFalse(verify(SECRET, TIMESTAMP, b'{ "event":"test"}', SIGNATURE, now))
        self.assertFalse(verify(SECRET, "1700000001", BODY, SIGNATURE, now))
        self.assertFalse(verify(SECRET, TIMESTAMP, BODY, SIGNATURE, 1_700_000_301))
        self.assertFalse(verify(SECRET, "-1", BODY, SIGNATURE, now))

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_javascript_webhook_verifier(self):
        driver = example("webhook-verify-js") + f"""
const secret = Buffer.from({SECRET.decode()!r});
const body = Buffer.from({BODY.decode()!r});
const ok = (v) => v ? "1" : "0";
console.log([
  verify(secret, "{TIMESTAMP}", body, "{SIGNATURE}", 1700000100),
  verify(secret, "{TIMESTAMP}", Buffer.from('{{ "event":"test"}}'), "{SIGNATURE}", 1700000100),
  verify(secret, "{TIMESTAMP}", body, "{SIGNATURE}", 1700000301),
  verify(secret, "{TIMESTAMP}", body, "v1=short", 1700000100),
].map(ok).join(""));
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verify.mjs"
            path.write_text(driver, encoding="utf-8")
            out = subprocess.run(["node", str(path)], capture_output=True, text=True,
                                 timeout=30, check=True)
        self.assertEqual(out.stdout.strip(), "1000")

    def test_vector_matches_server_test(self):
        source = (ROOT / "crates/server/src/webhook_egress.rs").read_text(encoding="utf-8")
        for pinned in (SECRET.decode(), SIGNATURE, BODY.decode(), "1_700_000_000"):
            self.assertIn(pinned, source)


if __name__ == "__main__":
    unittest.main()

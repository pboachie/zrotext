"""Real local HTTP acceptance for the isolated installed Python wheel.

Two executed expected failures preserve upstream redirect/deadline gates.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import sys
from threading import Thread
import time
import unittest
from urllib.parse import parse_qs, urlsplit

import tungsten_runtime
import zrotext_sdk
from tungsten_runtime import ClientOptions
from zrotext_sdk import ZrotextClient

IDENTITY = "11111111-2222-4333-8444-555555555555"
AUTH = {"bearerAuth": "synthetic-bearer"}
OWNER = {"ownerSession": {"__Host-zrotext_session": "synthetic-session",
         "__Host-zrotext_csrf": "synthetic-csrf", "origin": "https://owner.example.test"}}
STATUS = dict(message_id=IDENTITY, device_id=IDENTITY, state="unknown",
              state_version=1, created_at_ms=1, updated_at_ms=1)


def reply(request, value=STATUS, status=200, headers=None):
    data = value if isinstance(value, bytes) else json.dumps(value).encode()
    request.send_response(status)
    request.send_header("Content-Type", "application/json")
    request.send_header("Content-Length", str(len(data)))
    for key, value in (headers or {}).items():
        request.send_header(key, value)
    request.end_headers()
    request.wfile.write(data)


class InstalledWire(unittest.TestCase):
    def fixture(self, handler, auth=AUTH, timeout_ms=1000):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                seen.append(dict(method=self.command, path=self.path,
                                 headers=dict(self.headers), body=data))
                try:
                    handler(self, len(seen))
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
            do_POST = do_GET
        server = ThreadingHTTPServer(("localhost", 0), Handler)
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        def close():
            server.shutdown(); server.server_close(); thread.join(2)
        self.addCleanup(close)
        client = ZrotextClient(ClientOptions(base_url=f"http://{server.server_address[0]}:{server.server_port}",
                    auth=auth, timeout_ms=timeout_ms, validate_responses="strict"))
        self.addCleanup(client.close)
        return client, seen

    def test_imports_are_installed(self):
        for module in (zrotext_sdk, tungsten_runtime):
            self.assertTrue(Path(module.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()))

    def test_real_bearer_and_encoded_path(self):
        client, seen = self.fixture(lambda request, count: reply(request))
        self.assertTrue(client.public.alpha_messages.get_status(message_id=IDENTITY).ok)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["path"], f"/v1/alpha/messages/{IDENTITY}")
        headers = {key.lower(): value for key, value in seen[0]["headers"].items()}
        self.assertEqual(headers["authorization"], "Bearer synthetic-bearer")
        self.assertNotIn("cookie", headers)

    def test_preflight_rejections_never_dispatch(self):
        client, seen = self.fixture(lambda request, count: reply(request), auth={})
        self.assertEqual(client.public.alpha_messages.get_status(message_id=IDENTITY).error["category"], "AUTH_FAILED")
        self.assertFalse(client.public.alpha_messages.get_status(message_id="invalid").ok)
        self.assertFalse(client.workflow.tools.readiness().ok)
        self.assertEqual(seen, [])

    def test_owner_pagination_and_csrf(self):
        client, seen = self.fixture(lambda request, count: reply(request,
            dict(messages=[], next_cursor=IDENTITY if count == 1 else None)), auth=OWNER)
        pages = list(client.public.owner_messages.list_pages())
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(page.ok for page in pages))
        self.assertEqual(len(seen), 2)
        self.assertNotIn("before", parse_qs(urlsplit(seen[0]["path"]).query))
        self.assertEqual(parse_qs(urlsplit(seen[1]["path"]).query)["before"], [IDENTITY])
        for request in seen:
            headers = {key.lower(): value for key, value in request["headers"].items()}
            self.assertEqual(headers["x-zrotext-csrf"], "synthetic-csrf")
            self.assertIn("__Host-zrotext_session=synthetic-session", headers["cookie"])
            self.assertNotIn("authorization", headers)

    def test_malformed_and_strict_responses_do_not_retry(self):
        for value in (b"{broken", {}, dict(STATUS, state="invented")):
            with self.subTest(value=value):
                client, seen = self.fixture(lambda request, count: reply(request, value))
                self.assertFalse(client.public.alpha_messages.get_status(message_id=IDENTITY).ok)
                self.assertEqual(len(seen), 1)

    def test_rate_limit_and_disabled_gate_do_not_retry(self):
        for status in (404, 429, 503):
            with self.subTest(status=status):
                client, seen = self.fixture(lambda request, count: reply(request, {}, status,
                                                        {"Retry-After": "0"}))
                self.assertFalse(client.public.alpha_messages.get_status(message_id=IDENTITY).ok)
                self.assertEqual(len(seen), 1)

    def test_disabled_sealed_route_preserves_gated_refusal(self):
        client, seen = self.fixture(lambda request, count: reply(request, {}, 404))
        self.assertFalse(client.sealed.messages.get(message_id=IDENTITY).ok)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["path"], f"/v1/sealed/messages/{IDENTITY}")

    def test_stalled_read_timeout_is_single_attempt(self):
        def stall(request, count):
            time.sleep(0.5)
            reply(request)
        client, seen = self.fixture(stall, timeout_ms=100)
        started = time.monotonic()
        result = client.public.alpha_messages.get_status(message_id=IDENTITY)
        self.assertFalse(result.ok)
        self.assertLess(time.monotonic() - started, 0.45)
        self.assertEqual(len(seen), 1)

    def test_mutation_and_cross_origin_redirects_do_not_dispatch_destination(self):
        for mutation in (False, True):
            with self.subTest(mutation=mutation):
                client, seen = self.fixture(lambda request, count: reply(request, {}, 302,
                    {"Location": "/redirected" if mutation else "https://other.example.test/redirected"}))
                result = (client.public.alpha_messages.cancel if mutation else
                          client.public.alpha_messages.get_status)(message_id=IDENTITY)
                self.assertFalse(result.ok)
                self.assertEqual(len(seen), 1)

    def test_confirmation_and_caller_key_survive_unknown_outcome(self):
        def lost(request, count):
            request.connection.shutdown(socket.SHUT_RDWR)
            request.connection.close()
        client, seen = self.fixture(lost)
        args = dict(client_message_id=IDENTITY, device_id=IDENTITY,
                    recipient_e164="+15550100001", test_case_id="synthetic",
                    expires_at_ms=int(time.time() * 1000) + 60000)
        opts = {"idempotency_key": "synthetic.intent-1"}
        self.assertFalse(client.public.alpha_messages.submit(**args, opts=opts).ok)
        self.assertEqual(seen, [])
        preview = client.public.alpha_messages.preview_submit(**args, opts=opts)
        self.assertTrue(preview.ok)
        result = client.public.alpha_messages.submit(**args, opts={**opts,
                            "confirm": preview.value["confirmation_token"]})
        self.assertFalse(result.ok)
        self.assertEqual(result.error["category"], "OUTCOME_UNKNOWN")
        self.assertEqual(len(seen), 1)
        headers = {key.lower(): value for key, value in seen[0]["headers"].items()}
        self.assertEqual(headers["idempotency-key"], opts["idempotency_key"])
        self.assertEqual(json.loads(seen[0]["body"])["client_message_id"], IDENTITY)
        self.assertNotIn("synthetic-bearer", str(result.error))

    @unittest.expectedFailure
    def test_required_no_redirect_policy_upstream_65(self):
        client, seen = self.fixture(lambda request, count: reply(request, {}, 302, {"Location": "/again"}))
        result = client.public.alpha_messages.get_status(message_id=IDENTITY)
        self.assertFalse(result.ok)
        print(f"UNQUALIFIED #65 observation: {len(seen)} HTTP requests", flush=True)
        self.assertEqual(len(seen), 1, "UNQUALIFIED: Tungsten #65 follows same-origin read redirects")

    @unittest.expectedFailure
    def test_required_whole_body_deadline_upstream_66(self):
        def slow(request, count):
            data = json.dumps(STATUS).encode()
            request.send_response(200)
            request.send_header("Content-Type", "application/json")
            request.send_header("Content-Length", str(len(data)))
            request.end_headers()
            time.sleep(0.25)
            request.wfile.write(data[:1]); request.wfile.flush()
            time.sleep(0.25)
            request.wfile.write(data[1:]); request.wfile.flush()
        client, seen = self.fixture(slow, timeout_ms=300)
        started = time.monotonic()
        result = client.public.alpha_messages.get_status(message_id=IDENTITY)
        elapsed = time.monotonic() - started
        self.assertEqual(len(seen), 1)
        self.assertFalse(result.ok)
        print(f"UNQUALIFIED #66 observation: elapsed={elapsed:.3f}s, limit=0.300s", flush=True)
        self.assertLess(elapsed, 0.45, "UNQUALIFIED: Tungsten #66 settles only after the next body chunk")



class ExactKnownFailures(unittest.TextTestResult):
    """Do not let expectedFailure hide fixture errors or different regressions."""
    def addExpectedFailure(self, test, error):
        markers = {
            "test_required_no_redirect_policy_upstream_65":
                "UNQUALIFIED: Tungsten #65 follows same-origin read redirects",
            "test_required_whole_body_deadline_upstream_66":
                "UNQUALIFIED: Tungsten #66 settles only after the next body chunk",
        }
        marker = markers.get(test._testMethodName)
        if marker and issubclass(error[0], AssertionError) and marker in str(error[1]):
            super().addExpectedFailure(test, error)
        else:
            self.addError(test, error)


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(resultclass=ExactKnownFailures, verbosity=2))

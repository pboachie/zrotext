"""Synthetic wire checks run against the installed generated Python wheel."""
import json
import time
import unittest

import httpx
from tungsten_runtime import ClientOptions
from zrotext_sdk import ZrotextClient
from zrotext_sdk._descriptors import API, OPERATIONS

IDENTITY = "11111111-2222-4333-8444-555555555555"
OWNER = {"ownerSession": {
    "__Host-zrotext_session": "synthetic-session",
    "__Host-zrotext_csrf": "synthetic-csrf",
    "origin": "https://owner.example.test",
}}


class WireContract(unittest.TestCase):
    def client(self, handler, auth=None):
        seen = []

        def send(request):
            seen.append(request)
            return handler(request)

        client = ZrotextClient(ClientOptions(
            base_url="https://gateway.example.test",
            auth=auth or {"bearerAuth": "synthetic-test-token"},
            validate_responses="strict", transport=httpx.MockTransport(send),
        ))
        self.addCleanup(client.close)
        return client, seen

    def test_surface_and_retry_defaults(self):
        for op in OPERATIONS:
            self.assertNotIn(op["path"], ("/v1/messages", "/v1/devices", "/v1/usage"))
            self.assertFalse(op["path"].startswith("/v1/messages/"))
        for tier in ("read_only", "mutating"):
            self.assertEqual(API["retries"][tier]["max"], 0)

    def test_status_bearer_and_strict_model(self):
        client, seen = self.client(lambda _: httpx.Response(200, json={
            "message_id": IDENTITY, "device_id": IDENTITY, "state": "unknown",
            "state_version": 1, "created_at_ms": 1, "updated_at_ms": 1,
        }))
        result = client.public.alpha_messages.get_status(message_id=IDENTITY)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.value.state, "unknown")
        self.assertEqual(len(seen), 1)
        self.assertEqual(str(seen[0].url), f"https://gateway.example.test/v1/alpha/messages/{IDENTITY}")
        self.assertEqual(seen[0].headers["authorization"], "Bearer synthetic-test-token")

    def test_redirect_malformed_and_disabled_gate_are_not_retried(self):
        for response in (httpx.Response(302, headers={"location": "https://other.example.test"}),
                         httpx.Response(200, json={}), httpx.Response(200, content=b"{broken"),
                         httpx.Response(404)):
            with self.subTest(status=response.status_code, body=response.content):
                client, seen = self.client(lambda _, response=response: response)
                result = client.public.alpha_messages.get_status(message_id=IDENTITY)
                self.assertFalse(result.ok)
                self.assertEqual(len(seen), 1)

    def test_read_timeout_and_uncertain_mutation_are_single_attempt(self):
        def timeout(request):
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        for method in ("get_status", "cancel"):
            with self.subTest(method=method):
                client, seen = self.client(timeout)
                result = getattr(client.public.alpha_messages, method)(message_id=IDENTITY)
                self.assertFalse(result.ok)
                self.assertEqual(len(seen), 1)
                if method == "cancel":
                    self.assertEqual(result.error["category"], "OUTCOME_UNKNOWN")

    def test_workflow_auth_is_not_alpha_auth(self):
        client, seen = self.client(lambda _: self.fail("must not send"))
        result = client.workflow.tools.readiness()
        self.assertFalse(result.ok)
        self.assertEqual(result.error["category"], "AUTH_FAILED")
        self.assertEqual(seen, [])

    def test_invalid_identifier_never_reaches_transport(self):
        client, seen = self.client(lambda _: self.fail("must not send"))
        self.assertFalse(client.public.alpha_messages.get_status(message_id="invalid").ok)
        self.assertEqual(seen, [])

    def test_owner_pagination_forwards_cursor_and_stops(self):
        cursors = iter((IDENTITY, None))
        client, seen = self.client(lambda _: httpx.Response(200, json={
            "messages": [], "next_cursor": next(cursors),
        }), OWNER)
        pages = list(client.public.owner_messages.list_pages())
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(page.ok for page in pages), pages)
        self.assertNotIn("before", seen[0].url.params)
        self.assertEqual(seen[1].url.params["before"], IDENTITY)

    def test_owner_csrf_and_origin(self):
        client, seen = self.client(lambda _: httpx.Response(204), OWNER)
        result = client.public.webhooks.enable(endpoint_id=IDENTITY)
        self.assertTrue(result.ok, result)
        self.assertEqual(seen[0].headers["origin"], "https://owner.example.test")
        self.assertEqual(seen[0].headers["x-zrotext-csrf"], "synthetic-csrf")
        self.assertIn("__Host-zrotext_session=synthetic-session", seen[0].headers["cookie"])
        self.assertIn("__Host-zrotext_csrf=synthetic-csrf", seen[0].headers["cookie"])

    def test_missing_csrf_rejected_before_transport(self):
        client, seen = self.client(lambda _: self.fail("must not send"), {
            "ownerSession": {"__Host-zrotext_session": "synthetic-session"},
        })
        self.assertFalse(client.public.webhooks.enable(endpoint_id=IDENTITY).ok)
        self.assertEqual(seen, [])

    def test_confirmation_and_caller_owned_key_survive_uncertainty(self):
        client, seen = self.client(lambda _: httpx.Response(503))
        args = dict(client_message_id=IDENTITY, device_id=IDENTITY,
                    recipient_e164="+15550100001", test_case_id="synthetic",
                    expires_at_ms=int(time.time() * 1000) + 60000)
        opts = {"idempotency_key": "synthetic.intent-1"}
        self.assertFalse(client.public.alpha_messages.submit(**args, opts=opts).ok)
        self.assertEqual(seen, [])
        preview = client.public.alpha_messages.preview_submit(**args, opts=opts)
        self.assertTrue(preview.ok, preview)
        result = client.public.alpha_messages.submit(**args, opts={
            **opts, "confirm": preview.value["confirmation_token"],
        })
        self.assertFalse(result.ok)
        self.assertEqual(result.error["category"], "OUTCOME_UNKNOWN")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].headers["idempotency-key"], opts["idempotency_key"])
        self.assertEqual(json.loads(seen[0].content), args)


if __name__ == "__main__":
    unittest.main()

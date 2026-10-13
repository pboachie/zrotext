"""Run actual installed generated runtime and legacy client with synthetic transports."""
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error

import httpx
from tungsten_runtime import ClientOptions
from zrotext_sdk import ZrotextClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from zrotext_client import AlphaClient, OutcomeUnknownError
import alpha_python as example

ID = "11111111-2222-4333-8444-555555555555"
INTENT = {"client_message_id": ID, "device_id": ID, "recipient_e164": "+15550100001",
          "test_case_id": "synthetic", "expires_at_ms": 4102444800000}
STATUS = {"message_id": ID, "device_id": ID, "state": "delivery_unknown", "state_version": 1,
          "created_at_ms": 1, "updated_at_ms": 1}


class LegacyResponse(io.BytesIO):
    def __init__(self, value, status):
        super().__init__(json.dumps(value).encode())
        self.status = status
        self.headers = {"Content-Type": "application/json"}


class LegacyOpener:
    def __init__(self, value, status=200, failure=False):
        self.value, self.status, self.failure = value, status, failure
        self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        if self.failure:
            raise urllib.error.URLError("synthetic interruption")
        return LegacyResponse(self.value, self.status)


class MigrationExamples(unittest.TestCase):
    def clients(self, value, status=200, failure=False):
        opener = LegacyOpener(value, status, failure)
        legacy = AlphaClient("https://gateway.example.test", "synthetic-token", opener=opener, timeout=35)
        requests = []
        def transport(request):
            requests.append(request)
            if failure:
                raise httpx.ReadError("synthetic interruption", request=request)
            return httpx.Response(status, json=value)
        generated = ZrotextClient(ClientOptions(base_url="https://gateway.example.test",
            auth={"bearerAuth": "synthetic-token"}, timeout_ms=35000,
            validate_responses="strict", transport=httpx.MockTransport(transport)))
        self.addCleanup(generated.close)
        return legacy, generated, opener.requests, requests

    def test_status_dataclass_and_result_model_use_same_scoped_wire(self):
        legacy, generated, before_requests, after_requests = self.clients(STATUS)
        before = example.read_legacy_status(legacy, ID)
        after = example.read_generated_status(generated, ID)
        self.assertEqual(before.message_id, ID)
        self.assertTrue(after.ok)
        self.assertEqual(after.value.message_id, ID)
        self.assertTrue(example.needs_reconciliation(before.state))
        self.assertTrue(example.needs_reconciliation(after.value.state))
        self.assertEqual(before_requests[0].full_url, str(after_requests[0].url))
        self.assertEqual(before_requests[0].get_header("Authorization"), after_requests[0].headers["Authorization"])

    def test_generated_review_requirement_preserves_body_and_replay_key(self):
        legacy, generated, before_requests, after_requests = self.clients({"message_id": ID, "created": False}, 202)
        key = "synthetic-intent-1"
        before = example.submit_legacy(legacy, INTENT, key)
        missing = example.submit_generated_reviewed(generated, INTENT, key, None)
        self.assertFalse(missing.ok)
        self.assertEqual(missing.error["category"], "CONFIRMATION_REQUIRED")
        self.assertEqual(after_requests, [])
        preview = example.preview_generated(generated, INTENT, key)
        self.assertTrue(preview.ok)
        self.assertEqual(after_requests, [])
        after = example.submit_generated_reviewed(generated, INTENT, key, preview.value["confirmation_token"])
        self.assertTrue(after.ok)
        self.assertEqual(before.message_id, after.value.message_id)
        self.assertEqual(json.loads(before_requests[0].data), json.loads(after_requests[0].content))
        self.assertEqual(before_requests[0].get_header("Idempotency-key"), key)
        self.assertEqual(after_requests[0].headers["Idempotency-Key"], key)

    def test_unknown_exception_versus_err_neither_retries(self):
        legacy, generated, before_requests, after_requests = self.clients({}, failure=True)
        key = "synthetic-intent-2"
        with self.assertRaises(OutcomeUnknownError):
            example.submit_legacy(legacy, INTENT, key)
        preview = example.preview_generated(generated, INTENT, key)
        result = example.submit_generated_reviewed(generated, INTENT, key, preview.value["confirmation_token"])
        self.assertFalse(result.ok)
        self.assertEqual(result.error["category"], "OUTCOME_UNKNOWN")
        self.assertEqual((len(before_requests), len(after_requests)), (1, 1))

    def test_strict_malformed_response_is_not_success(self):
        _, generated, _, requests = self.clients({})
        result = example.read_generated_status(generated, ID)
        self.assertFalse(result.ok)
        self.assertEqual(len(requests), 1)

    def test_generated_same_origin_redirect_is_a_replacement_blocker(self):
        requests = []
        def transport(request):
            requests.append(str(request.url))
            if request.url.path == '/redirected':
                return httpx.Response(200, json=STATUS)
            return httpx.Response(302, headers={'location': '/redirected'})
        with ZrotextClient(ClientOptions(base_url='https://gateway.example.test',
                auth={'bearerAuth': 'synthetic-token'}, validate_responses='strict',
                transport=httpx.MockTransport(transport))) as generated:
            result = example.read_generated_status(generated, ID)
        self.assertTrue(result.ok)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[1], 'https://gateway.example.test/redirected')
        # Exercise the actual urllib redirect handler without network I/O.
        from zrotext_client.alpha import _NoRedirect
        handler = _NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, 'Found', {}, requests[1]))


if __name__ == "__main__":
    unittest.main()

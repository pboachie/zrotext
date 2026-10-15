"""Native workflow behavior without Node, radio effects, or external networking."""
import base64
import copy
import http.client
import io
import json
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from workflow_client import WorkflowClient, WorkflowError, action_digest, workflow_functions
import workflow_validation as validation

ID = "10000000-0000-4000-8000-000000000001"
OTHER = "10000000-0000-4000-8000-000000000002"
CREDENTIAL = "ztw_" + base64.urlsafe_b64encode(bytes([7]) * 32).rstrip(b"=").decode()
PARAMS = {"request_id": ID, "context_id": ID}
CONTACT = {"kind": "contact", "result": {"contact_id": ID, "purpose": "transactional", "peer_digest": "ab" * 32}}
KEY = {"account_id": ID, "action_id": ID, "revision": 1, "binding_digest": "ab" * 32}


def reply(value, status=200):
    return status, "application/json", json.dumps(value).encode()


class NativeWorkflowTests(unittest.TestCase):
    def client(self):
        return WorkflowClient("https://gateway.example", CREDENTIAL)

    def test_vector_digest_and_input_snapshot(self):
        vector = json.loads((Path(__file__).resolve().parents[3] / "protocol/v1/vectors/workflow-action-01.json").read_text())
        self.assertEqual(action_digest(vector["action"]), vector["binding_digest"])
        value = copy.deepcopy(vector["action"])
        value["revision"] = 1.0
        self.assertEqual(action_digest(value), vector["binding_digest"])
        value["revision"] = True
        with self.assertRaises(WorkflowError):
            action_digest(value)
        functions = workflow_functions()
        functions.clear()
        self.assertEqual(len(workflow_functions()), 8)

    def test_only_rate_limit_retries_identical_snapshot(self):
        client = self.client()
        inputs = copy.deepcopy(PARAMS)
        seen = []
        def exchange(body):
            seen.append(body)
            inputs["context_id"] = OTHER
            return reply({"error": {"code": "rate_limited"}}, 429) if len(seen) == 1 else reply(CONTACT)
        with patch.object(client, "_exchange", exchange):
            self.assertEqual(client.call("workflow.contact.read", inputs, 3), CONTACT)
        self.assertIs(seen[0], seen[1])
        self.assertEqual(json.loads(seen[0])["params"], PARAMS)

    def test_integral_float_emits_integer_wire_token_like_typescript(self):
        client = self.client()
        result = {"kind": "cancel", "result": {"key": KEY, "message_id": ID, "state": "cancelled"}}
        with patch.object(client, "_exchange", return_value=reply(result)) as exchange:
            client.cancel(ID, {**KEY, "revision": 1.0})
        raw = exchange.call_args.args[0]
        self.assertIn(b'"revision":1,', raw)
        self.assertIs(type(json.loads(raw)["params"]["key"]["revision"]), int)

    def test_unknown_outcomes_never_retry_or_leak_diagnostics(self):
        cases = [TimeoutError("private"), reply({"error": {"code": "unavailable"}}, 503),
                 reply({"diagnostic": "private"}, 403), (302, "application/json", b"{}"),
                 (200, "text/html", b"private"), (200, "application/json", b"\xff"),
                 (200, "application/json", b"x" * 131073), reply({**CONTACT, "extra": True})]
        for case in cases:
            with self.subTest(case=type(case).__name__):
                client = self.client()
                with patch.object(client, "_exchange", side_effect=case if isinstance(case, Exception) else [case]) as exchange:
                    with self.assertRaises(WorkflowError) as caught:
                        client.call("workflow.contact.read", PARAMS, 3)
                self.assertEqual(caught.exception.state, "unknown")
                self.assertEqual(caught.exception.attempts, 1)
                self.assertNotIn("private", str(caught.exception))
                self.assertEqual(exchange.call_count, 1)

    def test_invalid_authority_and_wrong_realm_refused_before_transport(self):
        for bad in ("owner-token", CREDENTIAL + "=", "ztw_" + "B" * 43):
            with self.assertRaises(WorkflowError):
                WorkflowClient("https://gateway.example", bad)
        client = self.client()
        with patch.object(client, "_exchange") as exchange:
            for method, params in (("workflow.action.approve", PARAMS),
                                   ("workflow.contact.read", {**PARAMS, "plaintext": "synthetic"}),
                                   ("workflow.contact.read", {**PARAMS, "context_id": True})):
                with self.assertRaises(WorkflowError) as caught:
                    client.call(method, params)
                self.assertEqual(caught.exception.attempts, 0)
            exchange.assert_not_called()

    def test_arbitrary_precision_integer_is_redacted_before_request_and_after_response(self):
        client = self.client()
        with patch.object(client, "_exchange") as exchange:
            with self.assertRaises(WorkflowError) as caught:
                client.cancel(ID, {**KEY, "revision": 10**1000})
            self.assertEqual((caught.exception.code, caught.exception.attempts), ("invalid_request", 0))
            exchange.assert_not_called()
        result = {"kind": "cancel", "result": {"key": {**KEY, "revision": 10**1000}, "message_id": ID, "state": "cancelled"}}
        with patch.object(client, "_exchange", return_value=reply(result)):
            with self.assertRaises(WorkflowError) as caught:
                client.cancel(ID, KEY)
            self.assertEqual((caught.exception.code, caught.exception.attempts), ("response_unknown", 1))

    def test_correlated_context_status_proposal_cancel_schedule(self):
        vector = json.loads((Path(__file__).resolve().parents[3] / "protocol/v1/vectors/workflow-action-01.json").read_text())["action"]
        for name in ("account_id", "action_id", "line_id", "recipient_id", "purpose_id", "content_ref", "routine_id"):
            vector[name] = ID
        proposal_key = {**KEY, "binding_digest": action_digest(vector)}
        policy = {"timezone": "UTC", "first_local_date": "2027-01-01", "opens_minute": 100,
                  "closes_minute": 200, "repeat_every_days": None, "max_occurrences": 1, "pacing_seconds": 60}
        cases = [
            ("workflow.context.content", PARAMS, {"kind": "context_content", "result": {"context_id": OTHER, "revision": 1, "envelope_base64url": "YQ"}}),
            ("workflow.context.content", PARAMS, {"kind": "context_content", "result": {"context_id": ID, "revision": 1, "envelope_base64url": "YR"}}),
            ("workflow.action.status", {**PARAMS, "action_id": ID}, {"kind": "action", "result": {"key": {**KEY, "action_id": OTHER}, "record_version": 1, "phase": "approved", "delivery": {"availability": "unavailable"}}}),
            ("workflow.action.propose", {"request_id": ID, "descriptor": vector}, {"kind": "action", "result": {"key": {**proposal_key, "revision": 2}, "record_version": 1, "phase": "proposed"}}),
            ("workflow.action.cancel", {"request_id": ID, "key": KEY}, {"kind": "cancel", "result": {"key": {**KEY, "account_id": OTHER}, "message_id": ID, "state": "cancelled"}}),
            ("workflow.action.schedule", {"request_id": ID, "key": KEY, "policy": policy, "series_id": ID, "ordinal": 0}, {"kind": "occurrence", "result": {"occurrence_id": ID, "series_id": OTHER, "ordinal": 0, "phase": "owner_review", "opens_at_ms": None, "closes_at_ms": None, "expires_at_ms": 10}}),
        ]
        for method, params, value in cases:
            client = self.client()
            with patch.object(client, "_exchange", return_value=reply(value)) as exchange:
                with self.assertRaises(WorkflowError) as caught:
                    client.call(method, params, 3)
                self.assertEqual(caught.exception.state, "unknown")
                self.assertEqual(exchange.call_count, 1)

    def test_delayed_connection_cannot_submit_after_deadline(self):
        released, finished = threading.Event(), threading.Event()
        class DelayedConnection:
            sock = None
            requested = False
            def connect(self):
                released.wait(2)
            def request(self, *args, **kwargs):
                self.requested = True
            def close(self):
                finished.set()
        connection = DelayedConnection()
        client = WorkflowClient("https://gateway.example", CREDENTIAL, timeout_ms=20)
        try:
            with patch("workflow_client.http.client.HTTPSConnection", return_value=connection):
                started = time.monotonic()
                with self.assertRaises(WorkflowError) as caught:
                    client.call("workflow.contact.read", PARAMS)
                self.assertLess(time.monotonic() - started, 1)
                self.assertEqual(caught.exception.state, "unknown")
        finally:
            released.set()
        self.assertTrue(finished.wait(2))
        self.assertFalse(connection.requested)

    def test_truncated_content_length_and_chunked_entities_remain_unknown(self):
        body = json.dumps(CONTACT).encode()
        entities = [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body) + 100).encode() + b"\r\n\r\n" + body,
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + format(len(body), "x").encode() + b"\r\n" + body + b"\r\n"]
        for entity in entities:
            class SyntheticSocket:
                def makefile(self, *args, **kwargs):
                    return io.BytesIO(entity)
            response = http.client.HTTPResponse(SyntheticSocket())
            response.begin()
            class SyntheticConnection:
                def connect(self):
                    pass
                def request(self, *args, **kwargs):
                    pass
                def getresponse(self):
                    return response
                def close(self):
                    response.close()
            with patch("workflow_client.http.client.HTTPSConnection", return_value=SyntheticConnection()) as constructor:
                with self.assertRaises(WorkflowError) as caught:
                    self.client().call("workflow.contact.read", PARAMS, 3)
                self.assertEqual((caught.exception.code, caught.exception.attempts), ("response_unknown", 1))
                self.assertEqual(constructor.call_count, 1)

    def test_readiness_refuses_duplicate_method_and_wrong_hint(self):
        methods = [{"method": name, "operation": "send" if name.endswith("cancel") else name.removeprefix("workflow.").removeprefix("action.").replace(".", "_"),
                    "read_only_hint": tool["annotations"]["readOnlyHint"], "destructive_hint": tool["annotations"]["destructiveHint"],
                    "idempotent_hint": True, "implementation": "library_candidate", "transport_mounted": True,
                    "permission_granted": False} for name, tool in validation.TOOLS.items()]
        ready = {"available": True, "methods": methods, "scope": {"context_id": ID, "device_id": ID, "line_id": ID}, "send_semantics": "owner_bound_prepared_only"}
        validation.readiness(ready)
        ready["methods"][0]["read_only_hint"] = False
        with self.assertRaises(ValueError):
            validation.readiness(ready)
        ready["methods"][0] = copy.deepcopy(ready["methods"][1])
        with self.assertRaises(ValueError):
            validation.readiness(ready)

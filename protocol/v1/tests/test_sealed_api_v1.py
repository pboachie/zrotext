"""Contract checks for the proposed sealed API v1 OpenAPI document.

The sealed runtime is disabled and no server route exists; these checks pin
the proposal's shape so a later slice cannot silently widen it: binary-only
message-plane request bodies, no plaintext body property anywhere, the
required admission failures, alpha isolation, the read-only devices surface,
the owner-lifecycle webhook surface with ciphertext-only fanout, the usage
metering counters, and the stated disabled state.
Run: python -m unittest discover -s protocol/v1/tests -p 'test_sealed_api_v1.py'
"""

import json
import unittest
from pathlib import Path


DOCUMENT = json.loads(
    (Path(__file__).resolve().parents[1] / "openapi" / "sealed-v1.json").read_text()
)

SEALED_CONTENT_TYPE = "application/vnd.zrotext.sealed.v1"
HTTP_METHODS = ("get", "put", "post", "patch", "delete", "options", "head", "trace")

MESSAGE_ENDPOINTS = ("/v1/sealed/messages", "/v1/sealed/inbound-events")
DEVICE_PATHS = ("/v1/sealed/devices", "/v1/sealed/devices/{device_id}")
USAGE_PATHS = ("/v1/sealed/usage",)
WEBHOOK_PATHS = (
    "/v1/sealed/webhooks",
    "/v1/sealed/webhooks/{endpoint_id}/deliveries",
    "/v1/sealed/webhooks/{endpoint_id}/deliveries/{delivery_id}/replay",
    "/v1/sealed/webhooks/{endpoint_id}/enable",
    "/v1/sealed/webhooks/{endpoint_id}/disable",
    "/v1/sealed/webhooks/{endpoint_id}/rotate",
)
PATH_METHODS = {
    "/v1/sealed/messages": {"post"},
    "/v1/sealed/inbound-events": {"post"},
    "/v1/sealed/devices": {"get"},
    "/v1/sealed/devices/{device_id}": {"get"},
    "/v1/sealed/webhooks": {"get", "post"},
    "/v1/sealed/webhooks/{endpoint_id}/deliveries": {"get"},
    "/v1/sealed/webhooks/{endpoint_id}/deliveries/{delivery_id}/replay": {"post"},
    "/v1/sealed/webhooks/{endpoint_id}/enable": {"post"},
    "/v1/sealed/webhooks/{endpoint_id}/disable": {"post"},
    "/v1/sealed/webhooks/{endpoint_id}/rotate": {"post"},
    "/v1/sealed/usage": {"get"},
}

# Property names that would leak or accept unsealed message content.
FORBIDDEN_PROPERTY_NAMES = {
    "body",
    "text",
    "content",
    "plaintext",
    "to",
    "recipient",
    "sender",
    "from",
}
# Telephony identifiers must never appear as a device property name.
FORBIDDEN_DEVICE_PROPERTY_NAMES = {
    "phone_number",
    "msisdn",
    "iccid",
    "imsi",
    "sim_id",
    "subscription_id",
    "sim_slot",
}


def operations(document):
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


def responses(document, path, method):
    return document["paths"][path][method]["responses"].items()


def resolve_schema(document, schema):
    if isinstance(schema, dict) and "$ref" in schema:
        target = document
        for part in schema["$ref"].lstrip("#/").split("/"):
            target = target[part]
        return target
    return schema


def property_names(node):
    if isinstance(node, dict):
        if "properties" in node and isinstance(node["properties"], dict):
            yield from node["properties"].keys()
        for value in node.values():
            yield from property_names(value)
    elif isinstance(node, list):
        for value in node:
            yield from property_names(value)


def _dict_nodes(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _dict_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _dict_nodes(value)


def schema_properties(schema_name):
    schema = DOCUMENT["components"]["schemas"][schema_name]
    return schema["properties"]


class SealedApiContractTests(unittest.TestCase):
    def test_document_is_openapi_31_and_states_disabled_proposal(self):
        self.assertEqual(DOCUMENT["openapi"], "3.1.0")
        description = DOCUMENT["info"]["description"].lower()
        self.assertIn("proposal", description)
        self.assertIn("disabled", description)
        self.assertIn("no server route", description)
        self.assertIn("2026-09-26", DOCUMENT["info"]["description"])

    def test_documented_path_method_surface_is_exactly_the_sealed_v1_map(self):
        self.assertEqual(sorted(DOCUMENT["paths"]), sorted(PATH_METHODS))
        seen = {}
        for path, method, operation in operations(DOCUMENT):
            seen.setdefault(path, set()).add(method)
            self.assertTrue(operation.get("summary"), path)
            self.assertTrue(operation.get("description"), path)
            self.assertTrue(operation.get("operationId"), path)
            self.assertIn(
                {"bearerAuth": []},
                operation.get("security", []),
                f"{method} {path} must use the shared bearer scheme",
            )
            self.assertIn(
                operation["tags"],
                [[tag["name"]] for tag in DOCUMENT["tags"]],
                f"{method} {path} must use one declared tag",
            )
        self.assertEqual(seen, PATH_METHODS)

    def test_operation_ids_are_unique(self):
        ids = [operation["operationId"] for _, _, operation in operations(DOCUMENT)]
        self.assertEqual(len(ids), len(set(ids)), "operationIds must be unique")

    def test_every_local_ref_resolves(self):
        refs = []
        for node in _dict_nodes(DOCUMENT):
            ref = node.get("$ref")
            if isinstance(ref, str):
                refs.append(ref)
        self.assertTrue(refs, "the document is expected to use $ref")
        for ref in sorted(set(refs)):
            self.assertTrue(ref.startswith("#/"), f"external refs are not pinned: {ref}")
            target = DOCUMENT
            for part in ref.lstrip("#/").split("/"):
                self.assertIn(part, target, f"dangling ref {ref}")
                target = target[part]

    def test_message_plane_request_bodies_are_exactly_the_sealed_binary_type(self):
        for path in MESSAGE_ENDPOINTS:
            body = DOCUMENT["paths"][path]["post"]["requestBody"]
            self.assertTrue(body.get("required"), path)
            self.assertEqual(sorted(body["content"]), [SEALED_CONTENT_TYPE], path)
            schema = resolve_schema(
                DOCUMENT, body["content"][SEALED_CONTENT_TYPE]["schema"]
            )
            self.assertEqual(schema.get("type"), "string", path)
            self.assertEqual(schema.get("format"), "binary", path)

    def test_resource_request_bodies_are_json_metadata_only(self):
        resource_bodies = 0
        for path, method, operation in operations(DOCUMENT):
            if path in MESSAGE_ENDPOINTS:
                continue
            body = operation.get("requestBody")
            if body is None:
                continue
            resource_bodies += 1
            self.assertTrue(body.get("required"), f"{method} {path}")
            self.assertEqual(sorted(body["content"]), ["application/json"], path)
            schema = resolve_schema(
                DOCUMENT, body["content"]["application/json"]["schema"]
            )
            self.assertEqual(schema.get("type"), "object", path)
            self.assertFalse(schema.get("additionalProperties", True), path)
            self.assertTrue(schema.get("required"), path)
        self.assertEqual(
            resource_bodies, 1, "only webhook create carries a resource request body"
        )

    def test_every_response_is_no_store_json_metadata(self):
        for path, method, operation in operations(DOCUMENT):
            for status, response in responses(DOCUMENT, path, method):
                headers = response.get("headers", {})
                self.assertEqual(
                    headers.get("Cache-Control", {}).get("$ref"),
                    "#/components/headers/NoStore",
                    f"{method} {path} {status} must declare no-store",
                )
                content = response.get("content", {})
                self.assertEqual(
                    sorted(content), ["application/json"] if content else [],
                    f"{method} {path} {status} may only expose JSON metadata",
                )

    def test_error_responses_use_the_shared_error_schema(self):
        codes = DOCUMENT["components"]["schemas"]["Error"]["properties"]["code"]["enum"]
        for code in (
            "invalid_request",
            "invalid_webhook_endpoint",
            "not_found",
            "endpoint_limit",
            "replay_not_eligible",
            "replay_limit",
        ):
            self.assertIn(code, codes, f"error enum is missing {code}")
        for path, method, operation in operations(DOCUMENT):
            for status, response in responses(DOCUMENT, path, method):
                if not status.startswith(("4", "5")):
                    continue
                schema = response["content"]["application/json"]["schema"]
                self.assertEqual(
                    schema,
                    {"$ref": "#/components/schemas/Error"},
                    f"{method} {path} {status} must use the shared Error schema",
                )

    def test_no_plaintext_content_property_in_any_schema(self):
        offenders = sorted(
            name
            for name in property_names(DOCUMENT)
            if name in FORBIDDEN_PROPERTY_NAMES
            or "plaintext" in name
            or name.endswith("_text")
        )
        self.assertEqual(offenders, [], "a plaintext content property violates Q11")

    def test_no_endpoint_references_synthetic_alpha_paths(self):
        for path in DOCUMENT["paths"]:
            self.assertNotIn("alpha", path.lower())
        for path, method, operation in operations(DOCUMENT):
            self.assertNotIn("alpha", operation["operationId"].lower())
            self.assertNotIn("alpha", path.lower())

    def test_required_error_responses_exist_for_both_message_endpoints(self):
        for path in MESSAGE_ENDPOINTS:
            for status in ("400", "401", "403", "409", "415"):
                self.assertIn(status, DOCUMENT["paths"][path]["post"]["responses"], path)

    def test_resource_operations_declare_auth_and_missing_resource_failures(self):
        for path, method, operation in operations(DOCUMENT):
            if path in MESSAGE_ENDPOINTS:
                continue
            codes = set(operation["responses"])
            self.assertIn("401", codes, f"{method} {path}")
            self.assertIn("403", codes, f"{method} {path}")
            if "{device_id}" in path or "{endpoint_id}" in path:
                self.assertIn(
                    "404", codes, f"{method} {path} addresses an owned resource"
                )

    def test_devices_surface_is_read_only_without_telephony_identifiers(self):
        self.assertEqual(
            sorted(path for path in DOCUMENT["paths"] if "/devices" in path),
            sorted(DEVICE_PATHS),
        )
        for path in DEVICE_PATHS:
            self.assertEqual(PATH_METHODS[path], {"get"}, f"{path} must be read-only")
        device = schema_properties("SealedDevice")
        self.assertEqual(
            sorted(device),
            sorted(
                [
                    "device_id",
                    "display_name",
                    "revoked",
                    "active_socket_lease",
                    "lines",
                ]
            ),
        )
        self.assertEqual(
            sorted(schema_properties("SealedDeviceLine")),
            sorted(["line_id", "binding_generation", "state"]),
        )
        self.assertGreaterEqual(
            schema_properties("SealedDeviceLine")["binding_generation"]["minimum"], 1
        )
        for name in property_names(DOCUMENT["components"]["schemas"]["SealedDevice"]):
            self.assertNotIn(
                name, FORBIDDEN_DEVICE_PROPERTY_NAMES, "telephony identifier leaked"
            )
        page = schema_properties("SealedDevicePage")
        self.assertEqual(sorted(page), sorted(["devices", "next_cursor"]))
        list_operation = DOCUMENT["paths"]["/v1/sealed/devices"]["get"]
        query = [
            parameter
            for parameter in list_operation.get("parameters", [])
            if parameter["in"] == "query"
        ]
        self.assertEqual(
            [(parameter["name"], parameter["required"]) for parameter in query],
            [("before", False)],
            "the device list pages by one optional cursor",
        )

    def test_webhook_surface_mirrors_the_owner_lifecycle_contract(self):
        self.assertEqual(
            sorted(path for path in DOCUMENT["paths"] if "/webhooks" in path),
            sorted(WEBHOOK_PATHS),
        )
        webhook_operations = {
            DOCUMENT["paths"][path][method]["operationId"]: DOCUMENT["paths"][path][
                method
            ]
            for path, method, _ in operations(DOCUMENT)
            if path in WEBHOOK_PATHS
        }
        create = webhook_operations["createSealedWebhookEndpoint"]
        self.assertIn("201", create["responses"])
        self.assertEqual(
            create["responses"]["201"]["content"]["application/json"]["schema"],
            {"$ref": "#/components/schemas/SealedWebhookSecret"},
        )
        self.assertIn("409", create["responses"])
        for operation_id in ("enableSealedWebhookEndpoint", "disableSealedWebhookEndpoint"):
            operation = webhook_operations[operation_id]
            self.assertIn("204", operation["responses"], f"{operation_id} uses 204")
            self.assertEqual(
                operation["responses"]["204"].get("content", {}),
                {},
                f"{operation_id} acknowledges with an empty body",
            )
        replay = webhook_operations["replaySealedWebhookDelivery"]
        self.assertIn("202", replay["responses"])
        header_params = [
            parameter
            for parameter in replay["parameters"]
            if parameter["in"] == "header"
        ]
        self.assertEqual(
            [(parameter["name"], parameter["required"]) for parameter in header_params],
            [("Idempotency-Key", True)],
            "replay must require a caller-supplied idempotency key",
        )
        self.assertIn("pattern", header_params[0]["schema"])
        history = webhook_operations["listSealedWebhookDeliveries"]
        limit = [
            parameter
            for parameter in history["parameters"]
            if parameter["name"] == "limit"
        ][0]["schema"]
        self.assertEqual((limit["minimum"], limit["maximum"]), (1, 20))

    def test_webhook_secret_never_appears_outside_one_time_responses(self):
        secret_only = {"SealedWebhookSecret"}
        for name, schema in DOCUMENT["components"]["schemas"].items():
            has_secret = "signing_secret_b64url" in schema.get("properties", {})
            if has_secret:
                self.assertIn(name, secret_only)
        self.assertEqual(
            secret_only, {"SealedWebhookSecret"}, "the secret needs a one-time surface"
        )

    def test_webhook_event_fanout_is_ciphertext_only(self):
        event = DOCUMENT["components"]["schemas"]["SealedWebhookEventBody"]
        self.assertEqual(event["type"], "object")
        self.assertFalse(event.get("additionalProperties", True))
        self.assertEqual(
            sorted(event["properties"]), sorted(event["required"]),
            "every event field is required",
        )
        for field in ("envelope_b64", "unsigned_digest_b64", "event_id"):
            self.assertIn(field, event["properties"])
        for name in event["properties"]:
            self.assertNotIn(name, FORBIDDEN_PROPERTY_NAMES)
        self.assertIn("never decrypts", event["description"])
        self.assertIn("five-minute", event["description"])

    def test_usage_surface_reports_bounded_metering_counters(self):
        self.assertEqual(
            sorted(path for path in DOCUMENT["paths"] if "/usage" in path),
            sorted(USAGE_PATHS),
        )
        usage = DOCUMENT["components"]["schemas"]["SealedUsage"]
        self.assertEqual(
            usage["properties"]["metric"].get("const"), "outbound_message"
        )
        for field in ("limit_units", "reserved_units", "refunded_units", "used_units"):
            counter = usage["properties"][field]
            self.assertEqual(counter["type"], "integer", field)
            self.assertGreaterEqual(counter["minimum"], 0, field)
        for field in ("period_start", "period_end"):
            self.assertEqual(usage["properties"][field]["format"], "date", field)
        self.assertEqual(
            sorted(usage["required"]),
            sorted(usage["properties"]),
            "every usage field is required",
        )


if __name__ == "__main__":
    unittest.main()

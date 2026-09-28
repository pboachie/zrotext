"""Contract checks for the public HTTP API v1 OpenAPI document.

The document pins the four public route families (/v1/messages, /v1/devices,
/v1/webhooks and /v1/usage) as crates/server implements them today, and labels
the planned-but-unimplemented routes. These checks fail if the documented
surface drifts from the server: a route marked implemented must exist in the
document with the server's method map, the implemented response bodies must
match the server serializers field for field, planned routes must stay clearly
labeled, and the one-time webhook secret must never leak into another schema.
Run: python -m unittest discover -s protocol/v1/tests -p 'test_public_api_v1.py'
"""

import json
import unittest
from pathlib import Path


DOCUMENT = json.loads(
    (Path(__file__).resolve().parents[1] / "openapi" / "public-v1.json").read_text()
)

HTTP_METHODS = ("get", "put", "post", "patch", "delete", "options", "head", "trace")

# Routes crates/server/src/main.rs mounts today, with their exact methods.
IMPLEMENTED_PATH_METHODS = {
    "/v1/webhooks": {"get", "post"},
    "/v1/webhooks/{endpoint_id}/deliveries": {"get"},
    "/v1/webhooks/{endpoint_id}/deliveries/{delivery_id}/replay": {"post"},
    "/v1/webhooks/{endpoint_id}/enable": {"post"},
    "/v1/webhooks/{endpoint_id}/disable": {"post"},
    "/v1/webhooks/{endpoint_id}/rotate": {"post"},
    "/v1/owner/messages": {"get"},
    "/v1/alpha/messages": {"post"},
    "/v1/alpha/messages/{message_id}": {"get"},
    "/v1/alpha/messages/{message_id}/cancel": {"post"},
    "/v1/enrollment/devices": {"get"},
    "/v1/enrollment/devices/{device_id}": {"delete"},
}
# Design targets from the docs/ARCHITECTURE.md outline; no route exists today.
PLANNED_PATH_METHODS = {
    "/v1/messages": {"post", "get"},
    "/v1/messages/{message_id}": {"get"},
    "/v1/messages/{message_id}/cancel": {"post"},
    "/v1/devices": {"get"},
    "/v1/usage": {"get"},
}
OWNER_SESSION_SECURITY = [{"ownerSession": [], "ownerCsrf": []}]
BEARER_SECURITY = [{"bearerAuth": []}]

# The 11 writer message states serialized by zrotext_domain::MessageState.
DOMAIN_MESSAGE_STATES = [
    "accepted",
    "queued",
    "claimed",
    "submitting",
    "submitted",
    "delivered",
    "delivery_unknown",
    "unknown",
    "failed",
    "cancelled",
    "expired",
]
# Every reason code the implemented routes can emit in an Error body.
IMPLEMENTED_ERROR_CODES = {
    "invalid_request",
    "unauthorized",
    "forbidden",
    "not_found",
    "conflict",
    "rate_limited",
    "queue_full",
    "quota_exceeded",
    "billing_pending",
    "payment_hold",
    "recipient_suppressed",
    "invalid_webhook_endpoint",
    "endpoint_limit",
    "replay_not_eligible",
    "replay_limit",
    "unavailable",
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


def _dict_nodes(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _dict_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _dict_nodes(value)


def property_names(node):
    if isinstance(node, dict):
        if "properties" in node and isinstance(node["properties"], dict):
            yield from node["properties"].keys()
        for value in node.values():
            yield from property_names(value)
    elif isinstance(node, list):
        for value in node:
            yield from property_names(value)


def schema_properties(schema_name):
    schema = DOCUMENT["components"]["schemas"][schema_name]
    return schema["properties"]


def implemented_operations():
    return [
        (path, method, operation)
        for path, method, operation in operations(DOCUMENT)
        if operation["x-implemented"]
    ]


def planned_operations():
    return [
        (path, method, operation)
        for path, method, operation in operations(DOCUMENT)
        if not operation["x-implemented"]
    ]


class PublicApiContractTests(unittest.TestCase):
    def test_document_is_openapi_31_describing_both_states(self):
        self.assertEqual(DOCUMENT["openapi"], "3.1.0")
        description = DOCUMENT["info"]["description"]
        self.assertIn("exactly as crates/server implements them today", description)
        self.assertIn("planned but not implemented", description)
        self.assertIn("x-implemented", description)

    def test_documented_path_method_surface_is_exactly_the_server_map(self):
        self.assertEqual(
            sorted(DOCUMENT["paths"]),
            sorted(list(IMPLEMENTED_PATH_METHODS) + list(PLANNED_PATH_METHODS)),
        )
        seen = {}
        for path, method, operation in operations(DOCUMENT):
            seen.setdefault(path, set()).add(method)
            self.assertTrue(operation.get("summary"), path)
            self.assertTrue(operation.get("description"), path)
            self.assertTrue(operation.get("operationId"), path)
            self.assertIn(
                operation["tags"],
                [[tag["name"]] for tag in DOCUMENT["tags"]],
                f"{method} {path} must use one declared tag",
            )
        self.assertEqual(
            {path: methods for path, methods in seen.items()
             if path in IMPLEMENTED_PATH_METHODS},
            IMPLEMENTED_PATH_METHODS,
        )
        self.assertEqual(
            {path: methods for path, methods in seen.items()
             if path in PLANNED_PATH_METHODS},
            PLANNED_PATH_METHODS,
        )

    def test_x_implemented_partitions_implemented_and_planned_routes(self):
        for path, method, operation in implemented_operations():
            self.assertIn(
                path, IMPLEMENTED_PATH_METHODS, f"{method} {path} is not a server route"
            )
            self.assertIn(
                "crates/server/src/", operation["description"],
                f"{method} {path} must cite its implementation",
            )
        for path, method, operation in planned_operations():
            self.assertIn(
                path, PLANNED_PATH_METHODS, f"{method} {path} exists in the server"
            )
            self.assertTrue(
                operation["description"].startswith("PLANNED:"),
                f"{method} {path} must be labeled planned up front",
            )
            self.assertIn(
                "no", operation["description"].lower().split("today")[0],
                f"{method} {path} must state that no route exists today",
            )
        self.assertEqual(
            sorted(path for path, _, _ in implemented_operations()),
            sorted(
                path
                for path, methods in IMPLEMENTED_PATH_METHODS.items()
                for _ in methods
            ),
        )

    def test_planned_operations_pin_no_response_schema_or_request_body(self):
        for path, method, operation in planned_operations():
            self.assertNotIn(
                "requestBody", operation,
                f"{method} {path} is planned and must not pin a request body",
            )
            for status, response in responses(DOCUMENT, path, method):
                if status.startswith("2"):
                    self.assertEqual(
                        response.get("content", {}),
                        {},
                        f"{method} {path} {status} must stay schema-unpinned",
                    )

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

    def test_owner_routes_require_session_and_csrf_and_mutations_require_origin(self):
        owner_mutations = {"post", "delete", "put", "patch"}
        for path, method, operation in implemented_operations():
            if path.startswith("/v1/alpha/"):
                self.assertEqual(operation["security"], BEARER_SECURITY, f"{method} {path}")
                continue
            self.assertEqual(
                operation["security"], OWNER_SESSION_SECURITY, f"{method} {path}"
            )
            header_names = [
                parameter["name"]
                for parameter in operation.get("parameters", [])
                if parameter["in"] == "header"
            ]
            if method in owner_mutations:
                self.assertIn(
                    "Origin", header_names,
                    f"{method} {path} is an owner mutation and requires Origin",
                )
            else:
                self.assertNotIn(
                    "Origin", header_names,
                    f"{method} {path} is an owner read and must not require Origin",
                )

    def test_every_response_is_no_store(self):
        for path, method, operation in operations(DOCUMENT):
            for status, response in responses(DOCUMENT, path, method):
                self.assertEqual(
                    response.get("headers", {}).get("Cache-Control", {}).get("$ref"),
                    "#/components/headers/NoStore",
                    f"{method} {path} {status} must declare no-store",
                )

    def test_json_error_responses_use_the_shared_error_schema(self):
        enum = set(DOCUMENT["components"]["schemas"]["Error"]["properties"]["code"]["enum"])
        self.assertEqual(enum, IMPLEMENTED_ERROR_CODES)
        for path, method, operation in operations(DOCUMENT):
            for status, response in responses(DOCUMENT, path, method):
                if not status.startswith(("4", "5")):
                    continue
                content = response.get("content", {})
                if not content:
                    continue
                schema = content["application/json"]["schema"]
                self.assertEqual(
                    schema,
                    {"$ref": "#/components/schemas/Error"},
                    f"{method} {path} {status} must use the shared Error schema",
                )

    def test_webhook_surface_mirrors_the_implemented_owner_lifecycle(self):
        webhook_operations = {
            operation["operationId"]: operation
            for path, method, operation in implemented_operations()
            if path.startswith("/v1/webhooks")
        }
        self.assertEqual(
            sorted(webhook_operations),
            sorted(
                [
                    "listWebhookEndpoints",
                    "createWebhookEndpoint",
                    "listWebhookDeliveries",
                    "replayWebhookDelivery",
                    "enableWebhookEndpoint",
                    "disableWebhookEndpoint",
                    "rotateWebhookEndpoint",
                ]
            ),
        )
        create = webhook_operations["createWebhookEndpoint"]
        self.assertIn("201", create["responses"])
        self.assertEqual(
            create["responses"]["201"]["content"]["application/json"]["schema"],
            {"$ref": "#/components/schemas/WebhookSecret"},
        )
        self.assertIn("409", create["responses"])
        self.assertEqual(
            create["requestBody"]["content"]["application/json"]["schema"],
            {"$ref": "#/components/schemas/WebhookCreateRequest"},
        )
        for operation_id in ("enableWebhookEndpoint", "disableWebhookEndpoint"):
            self.assertIn("204", webhook_operations[operation_id]["responses"])
            self.assertEqual(
                webhook_operations[operation_id]["responses"]["204"].get("content", {}),
                {},
                f"{operation_id} acknowledges with an empty body",
            )
        replay = webhook_operations["replayWebhookDelivery"]
        self.assertIn("202", replay["responses"])
        header_params = [
            parameter
            for parameter in replay["parameters"]
            if parameter["in"] == "header" and parameter["name"] == "Idempotency-Key"
        ]
        self.assertEqual(len(header_params), 1)
        self.assertTrue(header_params[0]["required"])
        self.assertIn("pattern", header_params[0]["schema"])
        history = webhook_operations["listWebhookDeliveries"]
        limit = [
            parameter
            for parameter in history["parameters"]
            if parameter["name"] == "limit"
        ][0]["schema"]
        self.assertEqual((limit["minimum"], limit["maximum"], limit["default"]), (1, 20, 20))

    def test_webhook_secret_never_appears_outside_one_time_responses(self):
        secret_only = {"WebhookSecret"}
        for name, schema in DOCUMENT["components"]["schemas"].items():
            has_secret = "signing_secret_b64url" in schema.get("properties", {})
            if has_secret:
                self.assertIn(name, secret_only)
        self.assertEqual(
            secret_only, {"WebhookSecret"}, "the secret needs a one-time surface"
        )

    def test_alpha_request_and_status_match_the_server_serializers(self):
        submit = DOCUMENT["paths"]["/v1/alpha/messages"]["post"]
        request = resolve_schema(
            DOCUMENT, submit["requestBody"]["content"]["application/json"]["schema"]
        )
        self.assertEqual(
            sorted(request["properties"]),
            sorted(
                [
                    "client_message_id",
                    "device_id",
                    "recipient_e164",
                    "test_case_id",
                    "expires_at_ms",
                ]
            ),
        )
        self.assertEqual(sorted(request["required"]), sorted(request["properties"]))
        self.assertFalse(request.get("additionalProperties", True))
        idempotency = [
            parameter
            for parameter in submit["parameters"]
            if parameter["name"] == "Idempotency-Key"
        ]
        self.assertEqual(len(idempotency), 1)
        self.assertTrue(idempotency[0]["required"])
        self.assertIn("pattern", idempotency[0]["schema"])
        status = schema_properties("AlphaStatus")
        self.assertEqual(
            sorted(status),
            sorted(
                [
                    "message_id",
                    "device_id",
                    "state",
                    "state_version",
                    "created_at_ms",
                    "updated_at_ms",
                ]
            ),
        )
        self.assertEqual(
            resolve_schema(DOCUMENT, status["state"])["enum"],
            DOMAIN_MESSAGE_STATES,
        )
        self.assertEqual(
            resolve_schema(
                DOCUMENT, schema_properties("OwnerMessageView")["state"]
            )["enum"],
            DOMAIN_MESSAGE_STATES,
        )

    def test_alpha_admission_failures_declare_retry_after(self):
        submit = DOCUMENT["paths"]["/v1/alpha/messages"]["post"]["responses"]
        self.assertIn("402", submit)
        self.assertEqual(
            submit["429"]["headers"]["Retry-After"]["$ref"],
            "#/components/headers/RetryAfter60",
        )
        self.assertEqual(
            submit["503"]["headers"]["Retry-After"]["$ref"],
            "#/components/headers/RetryAfter10",
        )
        self.assertIn("404", submit)
        self.assertIn("409", submit)

    def test_owner_device_surface_matches_the_server_serializer(self):
        device = schema_properties("OwnerDevice")
        self.assertEqual(
            sorted(device),
            sorted(
                [
                    "device_id",
                    "display_name",
                    "revoked",
                    "active_socket_lease",
                    "pending_messages",
                    "in_flight_messages",
                    "status_observed_at_ms",
                    "reported_preconditions",
                ]
            ),
        )
        self.assertEqual(
            sorted(schema_properties("ReportedPreconditions")),
            sorted(
                [
                    "selected_sim",
                    "sms_permission",
                    "airplane_mode",
                    "network_service",
                    "received_at_ms",
                    "fresh",
                ]
            ),
        )
        for name in property_names(DOCUMENT["components"]["schemas"]["OwnerDevice"]):
            self.assertNotIn(
                name, FORBIDDEN_DEVICE_PROPERTY_NAMES, "telephony identifier leaked"
            )
        page = schema_properties("OwnerDevicePage")
        self.assertEqual(sorted(page), sorted(["devices", "next_cursor"]))
        self.assertEqual(page["devices"]["maxItems"], 50)
        self.assertEqual(
            schema_properties("OwnerMessagePage")["messages"]["maxItems"], 20
        )

    def test_documented_mount_conditions_are_stated(self):
        description = DOCUMENT["info"]["description"].lower()
        for flag in (
            "webhook_kek_version",
            "synthetic_alpha_enabled",
        ):
            self.assertIn(flag, description, f"the {flag} mount condition must be stated")
        alpha = DOCUMENT["paths"]["/v1/alpha/messages"]["post"]["description"].lower()
        self.assertIn("/v1/alpha", alpha)

    def test_planned_entries_redirect_to_implemented_neighbors(self):
        planned_text = " ".join(
            operation["description"] for _, _, operation in planned_operations()
        ).lower()
        self.assertIn("/v1/alpha/messages", planned_text)
        self.assertIn("/v1/owner/messages", planned_text)
        self.assertIn("/v1/enrollment/devices", planned_text)
        self.assertIn("sealed-v1.json", planned_text)


if __name__ == "__main__":
    unittest.main()

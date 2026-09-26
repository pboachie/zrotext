"""Contract checks for the proposed sealed API v1 OpenAPI document.

The sealed runtime is disabled and no server route exists; these checks pin
the proposal's shape so a later slice cannot silently widen it: binary-only
request bodies, no plaintext body property anywhere, the required admission
failures, alpha isolation and the stated disabled state.
Run: python -m unittest discover -s protocol/v1/tests -p 'test_sealed_api_v1.py'
"""

import json
import unittest
from pathlib import Path


DOCUMENT = json.loads(
    (Path(__file__).resolve().parents[1] / "openapi" / "sealed-v1.json").read_text()
)

SEALED_CONTENT_TYPE = "application/vnd.zrotext.sealed.v1"
ENDPOINTS = ("/v1/sealed/messages", "/v1/sealed/inbound-events")
HTTP_METHODS = ("get", "put", "post", "patch", "delete", "options", "head", "trace")


def operations(document):
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


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


class SealedApiContractTests(unittest.TestCase):
    def test_document_is_openapi_31_and_states_disabled_proposal(self):
        self.assertEqual(DOCUMENT["openapi"], "3.1.0")
        description = DOCUMENT["info"]["description"].lower()
        self.assertIn("proposal", description)
        self.assertIn("disabled", description)
        self.assertIn("no server route", description)
        self.assertIn("2026-09-26", DOCUMENT["info"]["description"])

    def test_exactly_two_documented_post_endpoints(self):
        self.assertEqual(sorted(DOCUMENT["paths"]), sorted(ENDPOINTS))
        seen = {(path, method) for path, method, _ in operations(DOCUMENT)}
        self.assertEqual(seen, {(path, "post") for path in ENDPOINTS})
        for path, method, operation in operations(DOCUMENT):
            self.assertTrue(operation.get("summary"), path)
            self.assertTrue(operation.get("description"), path)
            self.assertTrue(operation.get("operationId"), path)
            self.assertIn(
                {"bearerAuth": []},
                operation.get("security", []),
                f"{method} {path} must use the shared bearer scheme",
            )

    def test_every_request_body_is_exactly_the_sealed_binary_content_type(self):
        requests = 0
        for path, method, operation in operations(DOCUMENT):
            body = operation.get("requestBody")
            self.assertIsNotNone(body, f"{method} {path} has no request body")
            self.assertTrue(body.get("required"), f"{method} {path} body must be required")
            content = body["content"]
            self.assertEqual(
                sorted(content),
                [SEALED_CONTENT_TYPE],
                f"{method} {path} must accept only {SEALED_CONTENT_TYPE}",
            )
            schema = resolve_schema(DOCUMENT, content[SEALED_CONTENT_TYPE]["schema"])
            self.assertEqual(schema.get("type"), "string", f"{method} {path}")
            self.assertEqual(schema.get("format"), "binary", f"{method} {path}")
            requests += 1
        self.assertEqual(requests, len(ENDPOINTS))

    def test_no_plaintext_body_property_in_any_schema(self):
        offenders = sorted(
            name
            for name in property_names(DOCUMENT.get("components", {}))
            if name == "body"
        )
        self.assertEqual(offenders, [], "a plaintext body property violates Q11")

    def test_required_error_responses_exist_for_both_endpoints(self):
        for path in ENDPOINTS:
            responses = DOCUMENT["paths"][path]["post"]["responses"]
            for status in ("400", "401", "403", "409", "415"):
                self.assertIn(status, responses, f"{path} is missing {status}")
                self.assertIn("application/json", responses[status]["content"])

    def test_no_endpoint_references_synthetic_alpha_paths(self):
        for path in DOCUMENT["paths"]:
            self.assertNotIn("alpha", path.lower())
        for path, method, operation in operations(DOCUMENT):
            self.assertNotIn("alpha", operation["operationId"].lower())
            self.assertNotIn("alpha", path.lower())


if __name__ == "__main__":
    unittest.main()

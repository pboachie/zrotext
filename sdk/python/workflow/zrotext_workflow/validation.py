"""Native validators for the exact shared workflow contract; no authority creation."""

import base64
import copy
import hashlib
import json
import math
from importlib.resources import files
import re

CONTRACT = json.loads(files(__package__).joinpath("workflow_contract.json").read_text(encoding="utf-8"))
TOOLS = {tool["name"]: tool for tool in CONTRACT["tools"]}
MAX_SAFE = 2**53 - 1
INTEGER_FIELDS = {"authority_generation", "content_version", "expires_at", "not_before", "revision"}
ACTION_FIELDS = tuple(sorted(("account_id", "action_id", "revision", "line_id", "recipient_id",
                             "purpose_id", "content_ref", "content_digest", "content_version", "not_before",
                             "expires_at", "timezone", "window_id", "routine_id", "authority_generation", "commitment")))


def _same(a, b):
    return (type(a) is type(b) or type(a) in (int, float) and type(b) in (int, float)) and a == b


def safe_integer(value):
    return type(value) in (int, float) and abs(value) <= MAX_SAFE and math.isfinite(value) and int(value) == value


def wire_numbers(value):
    """Match JSON.stringify's integer tokens after closed-schema validation."""
    if type(value) is float and safe_integer(value):
        return int(value)
    if type(value) is dict:
        return {name: wire_numbers(item) for name, item in value.items()}
    if type(value) is list:
        return [wire_numbers(item) for item in value]
    return value


def matches(schema, value):
    if "anyOf" in schema:
        return any(matches(item, value) for item in schema["anyOf"])
    if "enum" in schema:
        return any(_same(item, value) for item in schema["enum"])
    if "const" in schema:
        return _same(schema["const"], value)
    kind = schema.get("type")
    if kind == "null":
        return value is None
    if kind == "boolean":
        return type(value) is bool
    if kind == "integer":
        return safe_integer(value) and schema.get("minimum", -MAX_SAFE) <= value <= schema.get("maximum", MAX_SAFE)
    if kind == "string":
        if type(value) is not str:
            return False
        # JavaScript schema lengths are UTF-16 code units, not Unicode scalar count.
        length = len(value.encode("utf-16-le", errors="surrogatepass")) // 2
        return (schema.get("minLength", 0) <= length <= schema.get("maxLength", MAX_SAFE)
                and ("pattern" not in schema or re.search(schema["pattern"], value) is not None))
    if kind == "array":
        return (type(value) is list and schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", MAX_SAFE)
                and all(matches(schema["items"], item) for item in value))
    if kind == "object":
        fields = schema.get("properties", {})
        return (type(value) is dict and all(name in value for name in schema.get("required", []))
                and all(name in fields and matches(fields[name], item) for name, item in value.items()))
    return False


def canonical_action(value):
    if type(value) is not dict or sorted(value) != list(ACTION_FIELDS):
        raise ValueError("invalid fields")
    for name, item in value.items():
        if name in INTEGER_FIELDS:
            if not safe_integer(item) or not (0 if name == "not_before" else 1) <= item:
                raise ValueError("invalid integer")
        elif type(item) is not str or not 1 <= len(item) <= 128 or not item.isascii():
            raise ValueError("invalid identifier")
    if (re.fullmatch("[0-9a-f]{64}", value["content_digest"]) is None
            or value["commitment"] not in ("informational", "sensitive")
            or value["not_before"] >= value["expires_at"]):
        raise ValueError("invalid binding")
    canonical = {name: int(item) if name in INTEGER_FIELDS else item for name, item in value.items()}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def action_digest(value):
    return hashlib.sha256(canonical_action(value)).hexdigest()


def functions():
    return copy.deepcopy([{"name": tool["name"], "description": tool["description"], "parameters": tool["inputSchema"]}
                          for tool in TOOLS.values()])


def request(method, params):
    if method not in TOOLS or not matches(TOOLS[method]["inputSchema"], params):
        raise ValueError("invalid_request")
    if method == "workflow.action.propose":
        canonical_action(params["descriptor"])
    if method == "workflow.action.schedule":
        policy = params["policy"]
        if (params["ordinal"] >= policy["max_occurrences"] or policy["opens_minute"] == policy["closes_minute"]
                or policy["repeat_every_days"] is None and policy["max_occurrences"] != 1):
            raise ValueError("invalid_request")


def canonical_base64url(value):
    try:
        return base64.urlsafe_b64encode(base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)).rstrip(b"=").decode() == value
    except (ValueError, UnicodeError):
        return False


def response(method, value, params):
    if not matches(TOOLS[method]["outputSchema"], value):
        raise ValueError("unexpected_response")
    result = value["result"]
    if method == "workflow.context.content" and not canonical_base64url(result["envelope_base64url"]):
        raise ValueError("unexpected_response")
    if method in ("workflow.context.metadata", "workflow.context.content") and result["context_id"] != params["context_id"]:
        raise ValueError("unexpected_response")
    if method == "workflow.action.status" and result["key"]["action_id"] != params["action_id"]:
        raise ValueError("unexpected_response")
    if method == "workflow.action.propose":
        descriptor = params["descriptor"]
        if (any(result["key"][name] != descriptor[name] for name in ("account_id", "action_id", "revision"))
                or result["key"]["binding_digest"] != action_digest(descriptor)):
            raise ValueError("unexpected_response")
    if method == "workflow.action.cancel" and result["key"] != params["key"]:
        raise ValueError("unexpected_response")
    if method == "workflow.action.schedule" and any(result[name] != params[name] for name in ("series_id", "ordinal")):
        raise ValueError("unexpected_response")


def readiness(value):
    if not matches(CONTRACT["readiness"], value):
        raise ValueError("unexpected_response")
    seen = set()
    for item in value["methods"]:
        method = item["method"]
        if method in seen:
            raise ValueError("unexpected_response")
        seen.add(method)
        expected_operation = "send" if method == "workflow.action.cancel" else method.removeprefix("workflow.").removeprefix("action.").replace(".", "_")
        annotations = TOOLS[method]["annotations"]
        if (item["operation"] != expected_operation or item["read_only_hint"] is not annotations["readOnlyHint"]
                or item["destructive_hint"] is not annotations["destructiveHint"]):
            raise ValueError("unexpected_response")

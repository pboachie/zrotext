"""Check the maintained setup design contract, not runtime acceptance.

Browser, Android and server behavior must also satisfy the named requirements.
This guard catches accidental deletion of those requirements and unsafe changes
to recovery examples; it does not claim that a UI or provider has been tested.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "protocol/v1/setup-journey-contract.json"
REQUIREMENTS = frozenset((
    "UX-NAV-01", "UX-OVERVIEW-01", "UX-NAV-02", "UX-LAYOUT-01", "UX-A11Y-01",
    "UX-STYLE-01", "SETUP-TRUST-01", "SETUP-PAIR-01", "SETUP-BIND-01",
    "SETUP-ACCESS-01", "SETUP-CONNECT-01", "SETUP-LINE-01", "SETUP-LINE-02",
    "SETUP-RESUME-01", "SETUP-UNKNOWN-01", "SETUP-FRESH-01", "HOSTED-ACCOUNT-01",
    "HOSTED-TERMS-01", "HOSTED-CHECKOUT-01", "HOSTED-MODE-01", "HOSTED-SELF-01",
    "HOSTED-APP-01", "HONEST-STATUS-01",
))
RECOVERY_GUARDS = {
    "REC-RETURN": {"new_checkout", "new_pairing", "automatic_start"},
    "REC-VERIFY": {"assume_verified", "persist_password"},
    "REC-QR": {"blind_replace_ticket", "repeat_approval"},
    "REC-APPROVAL": {"assume_failed", "repeat_approval", "new_pairing"},
    "REC-CAMERA": {"restart_account", "trust_scanned_origin"},
    "REC-PERMISSION": {"request_unrelated_permission", "claim_sms_ready"},
    "REC-OFFLINE": {"repeat_enrollment", "send_test_sms", "automatic_start"},
    "REC-SIM": {"reuse_old_line_approval", "select_peer_automatically"},
    "REC-SESSION": {"rebind_old_consent", "restart_account", "new_checkout"},
    "REC-PAY-PENDING": {"grant_paid_entitlement", "new_checkout", "request_payment_again"},
    "REC-PAY-FAILED": {"assume_no_charge_without_evidence", "duplicate_subscription"},
    "REC-KEYS": {"silently_recreate_key", "restore_permission_or_consent", "recover_key_from_billing"},
    "REC-REVOKED": {"revive_device_from_checkpoint", "start_with_cached_binding"},
    "REC-ACCOUNT": {"restore_previous_account_controls", "transfer_checkout_authority"},
}
PALETTE = {
    "background": "#0b0f0c", "surface": "#111712", "raised": "#161e17",
    "text": "#f0f3e9", "secondary": "#99a696", "accent": "#b6f36a",
    "caution": "#edbe70", "border": "#29332a",
}


def unique_text(values: object, name: str) -> list[str]:
    if not isinstance(values, list) or not values or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise ValueError(f"{name} must be a nonempty list of text")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} contains duplicate values")
    return values


def indexed(values: object, name: str) -> dict[str, dict]:
    if not isinstance(values, list) or not values:
        raise ValueError(f"{name} must be a nonempty list")
    result = {}
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError(f"{name} contains an item without an id")
        if item["id"] in result:
            raise ValueError(f"{name} contains a duplicate id")
        result[item["id"]] = item
    return result


def validate(contract: object) -> None:
    if not isinstance(contract, dict) or contract.get("schema_version") != 1:
        raise ValueError("unsupported setup design contract version")
    if contract.get("status") != "approved_design_implementation_acceptance_separate":
        raise ValueError("design approval must remain separate from implementation acceptance")
    if contract.get("palette") != PALETTE:
        raise ValueError("canonical dark-green palette changed without a contract revision")
    navigation = contract.get("navigation", {})
    for field, expected in (
        ("web", ["overview", "phones_lines", "activity", "integrations", "team", "settings"]),
        ("android_primary", ["home", "activity", "setup"]),
        ("android_advanced", ["connection", "tools"]),
        ("hosted_steps", ["account", "plan", "phone", "finish"]),
        ("phone_steps", ["scan", "compare", "connect", "approve_line"]),
    ):
        if navigation.get(field) != expected:
            raise ValueError(f"{field} navigation changed without updating the product contract")
    requirements = indexed(contract.get("requirements"), "requirements")
    if not REQUIREMENTS.issubset(requirements):
        raise ValueError("an approved requirement was removed")
    for item in requirements.values():
        surfaces = unique_text(item.get("surfaces"), "requirement surfaces")
        if not set(surfaces).issubset({"web", "android", "server"}):
            raise ValueError("unknown requirement surface")
        if not isinstance(item.get("must"), str) or not item["must"].strip():
            raise ValueError("requirement has no behavioral criterion")
    scenarios = indexed(contract.get("recovery_scenarios"), "recovery scenarios")
    if not RECOVERY_GUARDS.keys() <= scenarios.keys():
        raise ValueError("an approved recovery scenario was removed")
    for scenario_id, item in scenarios.items():
        for field in ("given", "next"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"{scenario_id} lacks {field}")
        unique_text(item.get("preserve"), f"{scenario_id} preserve")
        forbidden = set(unique_text(item.get("must_not"), f"{scenario_id} forbidden actions"))
        if not RECOVERY_GUARDS.get(scenario_id, set()) <= forbidden:
            raise ValueError(f"{scenario_id} lost an uncertainty or authority guard")
    binding = contract.get("binding", {})
    if binding.get("signature_domain") != "ZROTEXT-PAIRING-BINDING-V1" or binding.get("domain_zero_terminated") is not True:
        raise ValueError("binding proof must retain its distinct zero-terminated domain")
    if binding.get("transcript_fields") != [
        "account_id_uuid_bytes", "pairing_id_uuid_bytes", "challenge_id_uuid_bytes",
        "key_fingerprint_32_bytes", "challenge_nonce_32_bytes",
    ]:
        raise ValueError("binding proof transcript changed")
    if binding.get("recovery_key_policy") != "existing_key_only":
        raise ValueError("recovery cannot create a device key")
    terminal = binding.get("preclaim_terminal_observation", {})
    if terminal != {
        "http_status": 409,
        "codes": ["pairing_cancelled", "pairing_expired"],
        "required_facts": ["active_account", "unclaimed", "unapproved", "cancelled_or_expired"],
        "grants_binding": False,
        "missing_row": "unknown",
    }:
        raise ValueError("pre-claim terminal observations cannot infer missing state or grant binding")
    if binding.get("origin_authority") != "independently_selected_canonical_https_origin":
        raise ValueError("scanned or returned addresses cannot establish trust")
    if binding.get("stream_path") != "/v1/device-stream":
        raise ValueError("binding must use the canonical device stream path")
    if set(unique_text(binding.get("persistent_progress"), "persistent progress")) != {"canonical_origin", "pairing_id", "key_fingerprint"}:
        raise ValueError("only public locators may be persisted as pairing progress")
    if not {"pairing_token", "comparison_code", "private_key", "permission_consent", "line_approval", "active_binding_authority"} <= set(unique_text(binding.get("never_persist"), "forbidden persistence")):
        raise ValueError("pairing progress must not restore secrets or authority")
    layers = set(unique_text(contract.get("acceptance_layers"), "acceptance layers"))
    if not {"served_authenticated_browser_interactions", "android_emulator_accessibility_and_layout", "cross_platform_binding_and_recovery", "live_implementation_isolation_and_acceptance"} <= layers:
        raise ValueError("source-only evidence cannot replace runtime acceptance")
    forbidden = set(unique_text(contract.get("non_authorizations"), "non-authorizations"))
    if not {"merge", "deploy", "publish_release", "live_payment_call", "activate_prices", "send_real_sms", "weaken_privacy_or_consent_gate"} <= forbidden:
        raise ValueError("implementation approval cannot silently authorize external activation")


def validate_sources(root: Path, contract: dict) -> None:
    """Check shared visual tokens and durable references, not geometry or behavior."""
    for field in ("specification", "adr"):
        target = root / contract[field]
        if not target.is_file() or root.resolve() not in target.resolve().parents:
            raise ValueError(f"missing repository-local {field}")
    css = (root / "web/owner/devices.css").read_text(encoding="utf-8")
    for name, color in contract["palette"].items():
        if color.lower() not in css.lower():
            raise ValueError(f"web palette is missing {name}")
    appearance = (root / "android/app/src/main/java/org/zrotext/gateway/GatewayAppearance.kt").read_text(encoding="utf-8")
    for name in ("background", "surface", "raised", "text", "secondary", "accent"):
        color = contract["palette"][name][1:]
        if re.search(r"0xFF" + re.escape(color), appearance, re.IGNORECASE) is None:
            raise ValueError(f"Android palette is missing {name}")


def main() -> int:
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        validate(contract)
        validate_sources(ROOT, contract)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"setup design contract: {error}", file=sys.stderr)
        return 1
    print("setup design contract and palette: valid; runtime acceptance remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

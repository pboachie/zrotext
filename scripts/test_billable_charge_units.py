"""Executable model and vectors for the billable charge-unit contract (#673).

This is a pure design model, not a billing adapter. It makes the prose in
protocol/v1/billable-usage-candidate.md checkable: which events mint a unit,
which never do, and how the usage identifier is derived. It performs no
network, database or provider call.
"""

import hashlib
import json
from pathlib import Path
import re
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "protocol" / "v1" / "billable-charge-unit-vectors.json"
MIGRATION = ROOT / "deploy" / "compose" / "migrations" / "078_test_billable_usage.sql"
CONTRACT_DOC = ROOT / "protocol" / "v1" / "billable-usage-candidate.md"

# category -> (event that can mint a unit, field naming the action identity)
CHARGE_EVENT = {
    "android_execution": "sent_callback_ok",
    "provider_transport": "provider_acceptance_verified",
    "ai_generated_reply": "generation_completed_verified",
}
IDENTITY_FIELD = {
    "android_execution": None,  # the logical message is the identity
    "provider_transport": "action_id",
    "ai_generated_reply": "generation_id",
}


def usage_identifier(account_id, message_id, category="android_execution", unit=1):
    """Return the stable meter identifier and idempotency key."""
    text = "{}:{}:{}:{}".format(uuid.UUID(account_id), uuid.UUID(message_id), category, unit)
    return "zt-usage-v1-" + hashlib.sha256(text.encode("ascii")).hexdigest()


def replay(category, events):
    """Apply ordered events to one logical action stream; return its outcome."""
    charged = set()
    refunded = False
    review = False
    uncertain = False
    credit_requested = False
    for event in events:
        kind = event["type"]
        key = event.get(IDENTITY_FIELD[category]) if IDENTITY_FIELD[category] else "message"
        if kind == CHARGE_EVENT[category]:
            if category == "android_execution":
                # Every segment of the current attempt must report success.
                if event["segments_ok"] != event["segments_total"]:
                    continue
                if refunded:
                    continue
            charged.add(key)
        elif kind == "outcome_unknown":
            uncertain = True
        elif kind == "refund_before_finalize":
            if not charged:
                refunded = True
        elif kind == "callback_conflict":
            if charged:
                review = True
        elif kind == "request_credit":
            if charged:
                credit_requested = True
        # Every other event (rejection, failure, cancellation, approval,
        # edit, retry, delivery receipt, duplicate) is deliberately inert.
    return {
        "units": len(charged),
        "review": review,
        "uncertain": uncertain and not charged,
        "credit_requested": credit_requested,
    }


class BillableChargeUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_contract_is_versioned_and_covers_every_category(self):
        self.assertEqual(self.vectors["contract_version"], "billable-charge-unit-v1")
        self.assertEqual(set(self.vectors["categories"]), set(CHARGE_EVENT))
        seen = {s["category"] for s in self.vectors["scenarios"]}
        self.assertEqual(seen, set(CHARGE_EVENT))
        for name, meta in self.vectors["categories"].items():
            self.assertEqual(meta["charge_event"], CHARGE_EVENT[name])
            self.assertIn(meta["runtime"], ("candidate_test_only", "unavailable"))

    def test_scenarios_mint_expected_units(self):
        names = set()
        for scenario in self.vectors["scenarios"]:
            self.assertNotIn(scenario["name"], names)
            names.add(scenario["name"])
            with self.subTest(scenario["name"]):
                outcome = replay(scenario["category"], scenario["events"])
                self.assertEqual(outcome, scenario["expected"])

    def test_never_charge_events_never_mint_a_unit(self):
        for category, charge in CHARGE_EVENT.items():
            for kind in self.vectors["never_charge_event_types"]:
                with self.subTest(category=category, event=kind):
                    self.assertNotEqual(kind, charge)
                    outcome = replay(category, [{"type": kind}])
                    self.assertEqual(outcome["units"], 0)

    def test_retry_and_duplicate_events_do_not_add_units(self):
        for category in CHARGE_EVENT:
            event = {"type": CHARGE_EVENT[category], "segments_ok": 1, "segments_total": 1,
                     "action_id": "a1", "generation_id": "g1"}
            self.assertEqual(replay(category, [event] * 5)["units"], 1)

    def test_identifier_vectors_match_reference_derivation(self):
        for vector in self.vectors["identifier_vectors"]:
            with self.subTest(vector["name"]):
                derived = usage_identifier(vector["account_id"], vector["message_id"])
                self.assertEqual(derived, vector["identifier"])
                self.assertRegex(derived, r"^zt-usage-v1-[0-9a-f]{64}$")
        identifiers = [v["identifier"] for v in self.vectors["identifier_vectors"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_identifier_is_tenant_and_message_bound(self):
        a, b, m1, m2 = (str(uuid.UUID(int=i)) for i in (1, 2, 3, 4))
        self.assertNotEqual(usage_identifier(a, m1), usage_identifier(b, m1))
        self.assertNotEqual(usage_identifier(a, m1), usage_identifier(a, m2))
        self.assertNotEqual(usage_identifier(a, m1), usage_identifier(a, m1, "ai_generated_reply"))

    def test_candidate_migration_still_derives_the_same_identifier(self):
        sql = " ".join(MIGRATION.read_text(encoding="utf-8").split())
        self.assertIn(
            "'zt-usage-v1-' || encode(sha256(convert_to( NEW.account_id::text || ':' "
            "|| NEW.message_id::text || ':android_execution:1','UTF8')),'hex')",
            sql,
        )

    def test_contract_document_points_at_the_vectors(self):
        text = CONTRACT_DOC.read_text(encoding="utf-8")
        self.assertIn("billable-charge-unit-vectors.json", text)
        self.assertIn("billable-charge-unit-v1", text)

    def test_vectors_are_synthetic(self):
        raw = VECTORS.read_text(encoding="utf-8")
        raw = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "", raw)
        raw = re.sub(r"zt-usage-v1-[0-9a-f]{64}", "", raw)
        self.assertIsNone(re.search(r"\+?\d{10,}", raw))
        self.assertNotIn("sk_", raw)


if __name__ == "__main__":
    unittest.main()

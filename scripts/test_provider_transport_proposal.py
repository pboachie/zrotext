"""Test-only provider transport design oracle; no I/O, crypto or runtime sender."""

import copy
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TransportModel:
    def __init__(self, binding):
        self.binding = copy.deepcopy(binding)
        self.state = "queued"
        self.sends = 0
        self.message = None
        self.events = {}
        self.held = False
        self.operator_hold = False
        self.sequence = 0
        self.approved = True
        self.delivery_failed = False
        self.admissions = {}

    def admit(self, account, identity, binding):
        if account != self.binding["account"] or binding["account"] != account:
            return "refused"
        previous = self.admissions.get(identity)
        if previous is not None:
            return "replay" if previous == binding else "conflict"
        if binding != self.binding:
            return "conflict"
        self.admissions[identity] = copy.deepcopy(binding)
        return "accepted"

    def apply(self, operation, data):
        if operation == "intent":
            if (self.state != "queued" or self.held or self.operator_hold
                    or not self.approved or data.get("now", 1) >= self.binding["expiry"]
                    or not data.get("eligible", True) or not data.get("writer", True)
                    or not data.get("budget", True) or not data.get("reader", True)):
                return "refused"
            if any(data.get(k, v) != v for k, v in self.binding.items()):
                return "conflict"
            self.state = "submitting"
            self.sends += 1  # One committed network entitlement, not actual traffic.
            return "intent"
        if operation == "restart":
            if self.state == "submitting":
                self.state = "unknown"
            return self.state
        if operation == "response":
            if self.state not in ("submitting", "unknown") or not data.get("message"):
                return "refused"
            if self.message is not None and self.message != data["message"]:
                return "conflict"
            self.message = data["message"]
            return "accepted"
        if operation == "receipt":
            # These are trusted verifier outputs in the model, never HTTP fields.
            if not data.get("verified", True) or not data.get("fresh", True):
                return "refused"
            for key in ("account", "route", "revision", "sender", "recipient", "content"):
                if data.get(key, self.binding[key]) != self.binding[key]:
                    return "conflict"
            if self.message is None:
                return "awaiting_correlation"
            if data["message"] != self.message:
                return "conflict"
            if data["event"] in self.events:
                return "duplicate" if self.events[data["event"]] == data["digest"] else "conflict"
            if len(self.events) >= 64:
                return "capacity"
            fact = data["fact"]
            if ((self.state == "delivered" and fact in ("failed", "delivery_failed"))
                    or (self.state == "failed" and fact in ("submitted", "delivered", "delivery_unknown"))
                    or (self.delivery_failed and fact == "delivered")
                    or (self.state in ("submitted", "delivery_unknown") and fact == "failed")):
                return "conflict"
            if fact == "delivered":
                self.state = "delivered"
            elif fact == "failed":
                self.state = "failed"
            elif fact in ("submitted", "delivery_unknown", "delivery_failed"):
                if self.state in ("submitting", "unknown"):
                    self.state = "submitted"
                if fact == "delivery_unknown" and self.state == "submitted" and not self.delivery_failed:
                    self.state = "delivery_unknown"
                if fact == "delivery_failed":
                    self.delivery_failed = True
            self.events[data["event"]] = data["digest"]
            return "applied"
        if operation == "stop":
            if data["sequence"] <= self.sequence:
                return "stale"
            self.sequence = data["sequence"]
            self.held = True
            if self.state == "queued":
                self.state = "cancelled"
            return "held"
        if operation == "start":
            if data["sequence"] <= self.sequence:
                return "stale"
            self.sequence = data["sequence"]
            self.held = False
            return "released"
        raise ValueError("unknown model operation")


class ProviderTransportProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((ROOT / "protocol/v1/vectors/provider-transport-proposal.json").read_text(encoding="utf-8"))

    def model(self):
        return TransportModel(self.vectors["binding"])

    def test_published_transcripts(self):
        for case in self.vectors["cases"]:
            with self.subTest(case=case["name"]):
                model = self.model()
                for operation, data, expected in case["steps"]:
                    self.assertEqual(model.apply(operation, data), expected)
                self.assertEqual(model.state, case["state"])
                self.assertEqual(model.sends, case["sends"])

    def test_each_bound_field_refuses_changed_intent_without_mutation(self):
        for field in self.vectors["binding"]:
            with self.subTest(field=field):
                model = self.model()
                before = copy.deepcopy(model.__dict__)
                changed = 2 if field in ("revision", "expiry") else "changed_commitment"
                self.assertEqual(model.apply("intent", {field: changed}), "conflict")
                self.assertEqual(model.__dict__, before)

    def test_revocation_budget_reader_eligibility_and_fence_stop_submission(self):
        for field in ("writer", "budget", "reader", "eligible"):
            with self.subTest(field=field):
                model = self.model()
                self.assertEqual(model.apply("intent", {field: False}), "refused")
                self.assertEqual(model.sends, 0)
        model = self.model()
        model.approved = False
        self.assertEqual(model.apply("intent", {}), "refused")

    def test_foreign_unverified_stale_or_mismatched_receipt_never_mutates(self):
        base = {"event": "event_sample", "digest": "fact_delivered", "message": "message_sample", "fact": "delivered"}
        changes = [{key: "foreign"} for key in ("account", "route", "revision", "sender", "recipient", "content", "message")]
        changes += [{"verified": False}, {"fresh": False}]
        for changed in changes:
            with self.subTest(changed=changed):
                model = self.model()
                model.apply("intent", {})
                model.apply("response", {"message": "message_sample"})
                before = copy.deepcopy(model.__dict__)
                self.assertIn(model.apply("receipt", dict(base, **changed)), ("conflict", "refused"))
                self.assertEqual(model.__dict__, before)

    def test_event_capacity_preserves_duplicate_tombstones(self):
        model = self.model()
        model.apply("intent", {})
        model.apply("response", {"message": "message_sample"})
        for index in range(64):
            event = {"event": f"event_{index}", "digest": "fact_sample", "message": "message_sample", "fact": "unrecognized"}
            self.assertEqual(model.apply("receipt", event), "applied")
        before = copy.deepcopy(model.__dict__)
        event["event"] = "event_overflow"
        self.assertEqual(model.apply("receipt", event), "capacity")
        self.assertEqual(model.__dict__, before)
        event["event"] = "event_0"
        self.assertEqual(model.apply("receipt", event), "duplicate")

    def test_start_does_not_release_operator_hold(self):
        model = self.model()
        model.operator_hold = True
        model.apply("start", {"sequence": 1})
        self.assertEqual(model.apply("intent", {}), "refused")

    def test_admission_replay_cannot_change_route_content_or_charge_twice(self):
        model = self.model()
        binding = copy.deepcopy(model.binding)
        self.assertEqual(model.admit(binding["account"], "action_sample", binding), "accepted")
        self.assertEqual(model.admit(binding["account"], "action_sample", binding), "replay")
        for field in binding:
            with self.subTest(field=field):
                changed = dict(binding, **{field: "different_commitment"})
                self.assertIn(model.admit(binding["account"], "action_sample", changed), ("conflict", "refused"))
        self.assertEqual(len(model.admissions), 1)
        binding["content"] = "caller_mutation"
        self.assertEqual(model.admissions["action_sample"], model.binding)

    def test_unknown_phone_action_cannot_select_provider_midflight(self):
        model = self.model()
        model.state = "unknown"
        self.assertEqual(model.apply("intent", {}), "refused")
        self.assertEqual(model.sends, 0)

    def test_provider_acceptance_and_negative_delivery_are_separate_facts(self):
        model = self.model()
        model.apply("intent", {})
        self.assertEqual(model.apply("response", {"message": "message_sample"}), "accepted")
        self.assertEqual(model.state, "submitting")
        event = {"event": "event_sample", "digest": "failed_delivery", "message": "message_sample", "fact": "delivery_failed"}
        self.assertEqual(model.apply("receipt", event), "applied")
        self.assertEqual(model.state, "submitted")
        self.assertTrue(model.delivery_failed)
        event.update(event="other_event", digest="delivered_fact", fact="delivered")
        self.assertEqual(model.apply("receipt", event), "conflict")
        self.assertTrue(model.delivery_failed)


if __name__ == "__main__":
    unittest.main()

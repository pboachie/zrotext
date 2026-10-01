"""Executable design model, not a live billing adapter (#645)."""

import copy
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def startup(config):
    """Validate symbolic credential provenance, not credential strings."""
    mode = config["mode"]
    if mode not in ("disabled", "test", "live") or config["both_enabled"]:
        return "configuration_refused"
    if mode == "disabled":
        return "disabled"
    if not config["schema_ready"] or config["database_mode"] != mode:
        return "configuration_refused"
    if config["caps_enabled"] and not config["caps_configured"]:
        return "configuration_refused"
    if not config["provider_available"]:
        return "unready"
    for role in ("session", "reconcile", "webhook"):
        credential = config[role]
        if not credential or credential != [mode, config["provider_account"]]:
            return "configuration_refused"
    return "ready"


def receive(state, event):
    if not event["signature_valid"] or not event["fresh"]:
        return "verification_refused"
    if any(event[field] != state["namespace"][index]
           for field, index in (("mode", 0), ("object_mode", 0), ("provider_account", 1))):
        return "namespace_refused"
    if event["owner"] != state["owner"] or event["customer"] != state["customer"]:
        return "binding_refused"
    previous = state["inbox"].get(event["id"])
    if previous is not None:
        return "duplicate" if previous == event["digest"] else "conflict"
    state["inbox"][event["id"]] = event["digest"]
    state["pending"] = True
    if event["risk"]:
        state["risk"] = True
    return "queued"


def admission(state, request):
    # Replay is an existing commitment, not a new paid admission.
    previous = state["reservations"].get(request["id"])
    if previous is not None:
        return "replay" if previous == request["digest"] else "conflict"
    if request["required_mode"] != state["namespace"][0]:
        return "namespace_refused"
    if state["risk"]:
        return "payment_hold"
    if state["pending"]:
        return "billing_pending"
    if state["nonterminal_subscriptions"] != 1 or not state["recognized_price"]:
        return "quota_exceeded"
    if state["status"] == "past_due":
        deadline = state["grace_deadline"]
        if deadline is None or request["now"] >= deadline:
            return "quota_exceeded"
    elif state["status"] != "active":
        return "quota_exceeded"
    if len(state["reservations"]) >= state["quota"]:
        return "quota_exceeded"
    state["reservations"][request["id"]] = request["digest"]
    return "accepted"


class BillingModeProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((ROOT / "protocol/v1/billing-mode-proposal-vectors.json").read_text())

    def test_configuration_vectors(self):
        for case in self.vectors["configuration"]:
            with self.subTest(case=case["name"]):
                config = copy.deepcopy(self.vectors["base_configuration"])
                config.update(case["changes"])
                self.assertEqual(startup(config), case["expected"])

    def test_event_vectors_refuse_without_mutation(self):
        for case in self.vectors["events"]:
            with self.subTest(case=case["name"]):
                state = copy.deepcopy(self.vectors["base_state"])
                state.update(case.get("state_changes", {}))
                before = copy.deepcopy(state)
                event = dict(self.vectors["base_event"], **case["changes"])
                self.assertEqual(receive(state, event), case["expected"])
                if case["expected"] != "queued":
                    self.assertEqual(state, before)
                else:
                    self.assertTrue(state["pending"])
                    if event["risk"]:
                        self.assertEqual(admission(state, self.vectors["base_request"]), "payment_hold")

    def test_admission_vectors_and_reservation_atomicity(self):
        for case in self.vectors["admission"]:
            with self.subTest(case=case["name"]):
                state = copy.deepcopy(self.vectors["base_state"])
                state.update(case["state_changes"])
                before = copy.deepcopy(state)
                request = dict(self.vectors["base_request"], **case.get("changes", {}))
                result = admission(state, request)
                self.assertEqual(result, case["expected"])
                if result == "accepted":
                    self.assertEqual(len(state["reservations"]), len(before["reservations"]) + 1)
                    self.assertEqual(admission(state, request), "replay")
                else:
                    self.assertEqual(state, before)

    def test_interrupted_reconciliation_and_restart(self):
        state = copy.deepcopy(self.vectors["base_state"])
        self.assertEqual(receive(state, self.vectors["base_event"]), "queued")
        durable = copy.deepcopy(state)
        transaction = copy.deepcopy(durable)
        transaction["quota"] = 2
        transaction["pending"] = False
        # Kill before commit: the durable pending fence still refuses admission.
        self.assertEqual(admission(durable, self.vectors["base_request"]), "billing_pending")
        # Commit all projection/queue changes together and restart from storage.
        durable = copy.deepcopy(transaction)
        self.assertEqual(receive(durable, self.vectors["base_event"]), "duplicate")
        self.assertEqual(admission(durable, self.vectors["base_request"]), "accepted")
        restarted = copy.deepcopy(durable)
        self.assertEqual(admission(restarted, self.vectors["base_request"]), "replay")
        self.assertEqual(len(restarted["reservations"]), 1)

    def test_rollback_keeps_live_state_and_refuses_test_binary(self):
        state = copy.deepcopy(self.vectors["base_state"])
        state["risk"] = True
        state["reservations"] = {"action_previous": "content_previous"}
        config = copy.deepcopy(self.vectors["base_configuration"])
        config["mode"] = "test"
        before = copy.deepcopy(state)
        self.assertEqual(startup(config), "configuration_refused")
        self.assertEqual(state, before)
        self.assertEqual(admission(state, self.vectors["base_request"]), "payment_hold")

    def test_colliding_ids_remain_independent_in_isolated_namespaces(self):
        live = copy.deepcopy(self.vectors["base_state"])
        test = copy.deepcopy(live)
        test["namespace"][0] = "test"
        event = copy.deepcopy(self.vectors["base_event"])
        self.assertEqual(receive(live, event), "queued")
        event.update(mode="test", object_mode="test")
        self.assertEqual(receive(test, event), "queued")
        self.assertEqual(receive(live, event), "namespace_refused")
        self.assertEqual(len(live["inbox"]), 1)
        self.assertEqual(len(test["inbox"]), 1)

    def test_outage_does_not_renew_grace_or_clear_hold(self):
        state = copy.deepcopy(self.vectors["base_state"])
        state.update(status="past_due", grace_deadline=11)
        event = dict(self.vectors["base_event"], fresh=False)
        before = copy.deepcopy(state)
        self.assertEqual(receive(state, event), "verification_refused")
        self.assertEqual(state, before)
        self.assertEqual(admission(state, dict(self.vectors["base_request"], now=11)), "quota_exceeded")
        state["risk"] = True
        state["pending"] = True
        self.assertEqual(admission(state, self.vectors["base_request"]), "payment_hold")


if __name__ == "__main__":
    unittest.main()

"""Closed server observations never convert a redirect into payment authority."""
import copy
import json
from pathlib import Path
import unittest
import jsonschema


class HostedBillingRuntime(unittest.TestCase):
    def setUp(self):
        schema = json.loads((Path(__file__).parents[1] / "hosted-billing-runtime.schema.json").read_text())
        self.validator = jsonschema.Draft202012Validator(schema)
        self.status = {
            "schema_version": 1, "mode": "live",
            "account_id": "02020202-0202-0202-0202-020202020202",
            "session_id": "03030303-0303-0303-0303-030303030303",
            "observed_at_ms": 1000000, "customer_bound": False,
            "checkout": {"state": "pending", "url": None, "expires_at_ms": None},
            "entitlement": {"phase": "pending", "valid_until_ms": 1000000,
                            "first_failure_at_ms": None, "outbound_limit": 0,
                            "device_cap": 0, "payment_hold": False, "review_required": False},
            "reconciliation_pending": True,
        }

    def test_checkout_resume_needs_a_confirmed_same_session_url(self):
        self.validator.validate(self.status)
        for state in ("none", "pending", "reconciliation_required", "replaceable"):
            value = copy.deepcopy(self.status)
            value["checkout"]["state"] = state
            self.validator.validate(value)
            value["checkout"]["url"] = "https://checkout.stripe.com/c/pay/cs_fixture"
            self.assertFalse(self.validator.is_valid(value))
        self.status["checkout"] = {"state": "resumable", "url": None, "expires_at_ms": 2000000}
        self.assertFalse(self.validator.is_valid(self.status))
        self.status["checkout"]["url"] = "https://checkout.stripe.com/c/pay/cs_fixture"
        self.validator.validate(self.status)
        self.status["checkout"]["state"] = "success"
        self.assertFalse(self.validator.is_valid(self.status))

    def test_mode_account_session_and_closed_entitlement_are_required(self):
        for field in ("account_id", "session_id", "mode", "customer_bound"):
            value = copy.deepcopy(self.status)
            del value[field]
            self.assertFalse(self.validator.is_valid(value))
        self.status["entitlement"]["checkout_return"] = True
        self.assertFalse(self.validator.is_valid(self.status))

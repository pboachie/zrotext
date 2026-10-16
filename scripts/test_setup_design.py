"""Regression guards for the cross-platform product contract, not UI acceptance."""

import copy
import json
import unittest

from check_setup_design import CONTRACT, ROOT, validate, validate_sources


class SetupDesignContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_approved_requirements_and_current_palette_are_maintained(self):
        validate(self.contract)
        validate_sources(ROOT, self.contract)

    def test_losing_any_approved_requirement_fails_the_maintenance_gate(self):
        for index in range(len(self.contract["requirements"])):
            candidate = copy.deepcopy(self.contract)
            del candidate["requirements"][index]
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "requirement was removed"):
                validate(candidate)

    def test_uncertain_results_cannot_lose_duplicate_operation_guards(self):
        for scenario in self.contract["recovery_scenarios"]:
            for forbidden in scenario["must_not"]:
                candidate = copy.deepcopy(self.contract)
                case = next(item for item in candidate["recovery_scenarios"] if item["id"] == scenario["id"])
                case["must_not"].remove(forbidden)
                with self.subTest(case=scenario["id"], action=forbidden), self.assertRaises(ValueError):
                    validate(candidate)

    def test_duplicate_scenario_ids_cannot_shadow_recovery_behavior(self):
        candidate = copy.deepcopy(self.contract)
        candidate["recovery_scenarios"].append(candidate["recovery_scenarios"][0])
        with self.assertRaisesRegex(ValueError, "duplicate id"):
            validate(candidate)

    def test_progress_cannot_be_changed_to_persist_tokens_or_approval(self):
        for value in ("pairing_token", "private_key", "line_approval", "active_binding_authority"):
            candidate = copy.deepcopy(self.contract)
            candidate["binding"]["persistent_progress"].append(value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "public locators"):
                validate(candidate)

    def test_recovery_cannot_create_keys_or_take_trust_from_qr(self):
        for field, value in (("recovery_key_policy", "create_if_missing"), ("origin_authority", "scanned_origin")):
            candidate = copy.deepcopy(self.contract)
            candidate["binding"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(candidate)

    def test_binding_domain_and_transcript_cannot_reuse_enrollment_proof(self):
        for field, value in (("signature_domain", "zrotext-enrollment-v1"), ("domain_zero_terminated", False), ("transcript_fields", ["pairing_id_uuid_bytes"])):
            candidate = copy.deepcopy(self.contract)
            candidate["binding"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(candidate)

    def test_source_checks_cannot_replace_runtime_acceptance_layers(self):
        candidate = copy.deepcopy(self.contract)
        candidate["acceptance_layers"] = ["contract_and_source_checks"]
        with self.assertRaisesRegex(ValueError, "runtime acceptance"):
            validate(candidate)


if __name__ == "__main__":
    unittest.main()

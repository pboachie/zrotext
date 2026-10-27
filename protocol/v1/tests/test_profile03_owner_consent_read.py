# SPDX-License-Identifier: AGPL-3.0-only
"""Read grammar controls, not authentication or accepted current permission."""
import copy
import json
from pathlib import Path
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "profile03-owner-consent-read.schema.json").read_text())
VECTOR = json.loads((ROOT / "vectors/profile03-owner-consent-read-01.json").read_text())


class OwnerConsentReadTests(unittest.TestCase):
    def test_reads_have_distinct_closed_scopes(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        for kind in ["context_request", "opening_status_request"]:
            check = jsonschema.Draft202012Validator(
                {"$ref": "#/$defs/" + kind, "$defs": SCHEMA["$defs"]}
            )
            check.validate(VECTOR[kind])
            other = "opening_status_request" if kind == "context_request" else "context_request"
            self.assertFalse(check.is_valid(VECTOR[other]))
            for field in ["account_id", "owner_session_id", "fresh_mfa", "permission"]:
                changed = copy.deepcopy(VECTOR[kind])
                changed[field] = True
                self.assertFalse(check.is_valid(changed))

    def test_nonces_and_original_ids_must_be_canonical_nonzero_uuids(self):
        check = jsonschema.Draft202012Validator(SCHEMA)
        for name in ["request_id", "opening_id", "interval_id"]:
            for invalid in ["00000000-0000-0000-0000-000000000000", "01", 1, None]:
                changed = copy.deepcopy(VECTOR["context_request"])
                changed[name] = invalid
                self.assertFalse(check.is_valid(changed))

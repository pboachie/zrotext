# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import struct
import unittest
import uuid
import jsonschema

ROOT = Path(__file__).resolve().parents[1] / "vectors"


def aad(scope):
    return (b"ZTWC\x01" + bytes([scope["kind"]])
            + b"".join(uuid.UUID(scope[k]).bytes for k in
                       ("account_id", "device_id", "line_id", "interval_id", "context_id"))
            + b"".join(struct.pack(">q", scope[k]) for k in
                       ("binding_generation", "revision", "expires_ms", "trust_generation", "manifest_version"))
            + b"".join(bytes.fromhex(scope[k]) for k in
                       ("peer_digest", "reader_id", "manifest_digest")))


class WorkflowContextContractTest(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((ROOT / "workflow-context-01.json").read_text(encoding="utf-8"))
        self.schema = json.loads((ROOT / "workflow-context.schema.json").read_text(encoding="utf-8"))

    def test_vector_has_exact_nonempty_info_and_canonical_aad(self):
        jsonschema.validate(self.vector, self.schema, format_checker=jsonschema.FormatChecker())
        header = aad(self.vector["scope"])
        self.assertEqual(len(header), 222)
        self.assertEqual(header.hex(), self.vector["aad_hex"])
        self.assertEqual((b"ZT/workflow-context/hpke/v1\0" + header).hex(), self.vector["hpke_info_hex"])

    def test_every_scope_identity_changes_authenticated_bytes(self):
        for key in self.vector["scope"]:
            scope = copy.deepcopy(self.vector["scope"])
            if key.endswith("_id") and key != "reader_id":
                scope[key] = str(uuid.UUID(int=99))
            elif isinstance(scope[key], int):
                scope[key] += 1
            else:
                scope[key] = "09" * 32
            self.assertNotEqual(aad(scope), aad(self.vector["scope"]), key)

    def test_integration_representation_changes_only_the_selected_reader_aad(self):
        vector = json.loads((ROOT / "workflow-context-integration-01.json").read_text(encoding="utf-8"))
        jsonschema.validate(vector, self.schema, format_checker=jsonschema.FormatChecker())
        header = aad(vector["scope"])
        self.assertEqual(header.hex(), vector["aad_hex"])
        self.assertEqual((b"ZT/workflow-context/hpke/v1\0" + header).hex(), vector["hpke_info_hex"])
        archive = aad(self.vector["scope"])
        self.assertEqual(header[:158], archive[:158])
        self.assertNotEqual(header[158:190], archive[158:190])
        self.assertEqual(header[190:], archive[190:])

    def test_schema_refuses_plaintext_fields_nil_ids_and_unbounded_revisions(self):
        for change in ({"plaintext": "synthetic"}, {"revision": 0}, {"revision": 129},
                       {"context_id": str(uuid.UUID(int=0))}, {"kind": 4}):
            vector = copy.deepcopy(self.vector)
            vector["scope"].update(change)
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(vector, self.schema)
